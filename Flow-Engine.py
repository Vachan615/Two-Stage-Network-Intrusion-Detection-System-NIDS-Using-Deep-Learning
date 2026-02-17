from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from tensorflow.keras.models import load_model
import joblib
import numpy as np
import time
import threading



binary_model = load_model("models/binary_model.h5")
scaler_binary = joblib.load("models/binary_scaler.pkl")
binary_features = joblib.load("models/binary_features.pkl")

multiclass_model = load_model("models/multiclass_model.h5")
scaler_multi = joblib.load("models/multiclass_scaler.pkl")
multiclass_features = joblib.load("models/multiclass_features.pkl")
label_encoder = joblib.load("models/multiclass_label_encoder.pkl")



# -------------------------
# Flow Storage
# -------------------------

flows = {}
FLOW_WINDOW = 15  # seconds
flow_lock = threading.Lock()


# -------------------------
# Flow Key (5-tuple)
# -------------------------

def get_flow_key(packet):
    if IP in packet:

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            return None

        src = packet[IP].src
        dst = packet[IP].dst

        # Normalize direction (sort endpoints)
        if (src, sport) < (dst, dport):
            return (src, sport, dst, dport, proto)
        else:
            return (dst, dport, src, sport, proto)

    return None



# -------------------------
# Update Flow Stats
# -------------------------
def update_flow(packet):
    key = get_flow_key(packet)
    if key is None:
        return

    current_time = time.time()

    with flow_lock:   # ✅ MUST be inside function

        if key not in flows:
            flows[key] = {
                "start_time": current_time,
                "end_time": current_time,

                "total_packets": 0,
                "total_bytes": 0,

                "fwd_packets": 0,
                "bwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,

                "packet_lengths": [],
                "packet_timestamps": [],

                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0
            }

        flow = flows[key]

        flow["end_time"] = current_time
        flow["total_packets"] += 1
        flow["total_bytes"] += len(packet)
        flow["packet_lengths"].append(len(packet))
        flow["packet_timestamps"].append(current_time)

        # Direction handling
        if packet[IP].src == key[0]:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += len(packet)
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += len(packet)

        # TCP Flags
        if TCP in packet:
            flags = packet[TCP].flags

            if flags & 0x02:  # SYN
                flow["syn_count"] += 1
            if flags & 0x10:  # ACK
                flow["ack_count"] += 1
            if flags & 0x01:  # FIN
                flow["fin_count"] += 1
            if flags & 0x04:  # RST
                flow["rst_count"] += 1


# -------------------------
# Feature Computation
# -------------------------

def compute_flow_features(key, flow):

    duration = flow["end_time"] - flow["start_time"]
    duration = max(duration, 0.01)


    packets_per_sec = flow["total_packets"] / duration
    bytes_per_sec = flow["total_bytes"] / duration

    lengths = flow["packet_lengths"]

    mean_len = np.mean(lengths)
    std_len = np.std(lengths)
    max_len = np.max(lengths)
    min_len = np.min(lengths)

    timestamps = flow["packet_timestamps"]

    if len(timestamps) > 1:
       iats = np.diff(timestamps)
       mean_iat = np.mean(iats)
       std_iat = np.std(iats)
       max_iat = np.max(iats)
       min_iat = np.min(iats)
    else:
       mean_iat = 0
       std_iat = 0
       max_iat = 0
       min_iat = 0

    features = {
        "Flow Duration": duration,
        "Total Packets": flow["total_packets"],
        "Total Bytes": flow["total_bytes"],
        "Packets/s": packets_per_sec,
        "Bytes/s": bytes_per_sec,

        "Fwd Packets": flow["fwd_packets"],
        "Bwd Packets": flow["bwd_packets"],
        "Fwd Bytes": flow["fwd_bytes"],
        "Bwd Bytes": flow["bwd_bytes"],

        "Mean Packet Length": mean_len,
        "Std Packet Length": std_len,
        "Max Packet Length": max_len,
        "Min Packet Length": min_len,

        "SYN Count": flow["syn_count"],
        "ACK Count": flow["ack_count"],
        "FIN Count": flow["fin_count"],
        "RST Count": flow["rst_count"],
        "IAT Mean": mean_iat,
        "IAT Std": std_iat,
        "IAT Max": max_iat,
        "IAT Min": min_iat,



        "Destination Port": key[3]
    }

    return features


# -------------------------
# Flow Window Processor
# -------------------------

def flow_cleanup():
    while True:
        time.sleep(FLOW_WINDOW)

        print("\n---- Flow Window End ----")

        with flow_lock:

            for key in list(flows.keys()):
                flow = flows[key]
                features = compute_flow_features(key, flow)

                # -------- Stage 1: Binary Classification --------
                feature_vector = [
                    features.get(f, 0) for f in binary_features
                ]

                X_live = np.array(feature_vector).reshape(1, -1)

                try:
                    X_live_scaled = scaler_binary.transform(X_live)
                    prob = binary_model.predict(
                        X_live_scaled, verbose=0
                    )[0][0]
                    print(f"[DEBUG] Binary Probability: {prob:.4f}")

                except Exception as e:
                    print("[ERROR] Binary prediction failed:", e)
                    continue

                if prob > 0.10:

                    # -------- Stage 2: Multiclass Classification --------
                    feature_vector_multi = [
                        features.get(f, 0) for f in multiclass_features
                    ]

                    X_multi = np.array(feature_vector_multi).reshape(1, -1)

                    try:
                        X_multi_scaled = scaler_multi.transform(X_multi)

                        multi_probs = multiclass_model.predict(
                            X_multi_scaled, verbose=0
                        )[0]

                        pred = np.argmax(multi_probs)
                        attack_type = label_encoder.inverse_transform([pred])[0]
                        attack_conf = multi_probs[pred]

                        print(f"[ALERT] {attack_type} | "
                              f"BinaryProb: {prob:.2f} | "
                              f"MultiProb: {attack_conf:.2f}")

                    except Exception as e:
                        print("[ERROR] Multiclass prediction failed:", e)
                        continue

                else:
                    print("[INFO] Benign flow")

            flows.clear()


# -------------------------
# Start Engine
# -------------------------

def start_engine():
    cleanup_thread = threading.Thread(target=flow_cleanup)
    cleanup_thread.daemon = True
    cleanup_thread.start()

    print("Starting packet capture...")
    sniff(prn=update_flow, store=False)


if __name__ == "__main__":
    start_engine()    
