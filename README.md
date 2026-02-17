# 🚀 Two-Stage Network Intrusion Detection System (NIDS) Using Deep Learning

A Deep Learning based real-time Network Intrusion Detection System built using a two-stage architecture:

1️⃣ Binary Classification (Benign vs Attack)  
2️⃣ Multiclass Classification (Attack Type Detection)

This project captures live packets using Scapy, performs real-time flow-based feature extraction, and detects network attacks using trained deep learning models.

---

## 📌 Project Overview

Traditional IDS systems often suffer from high false positives or poor scalability.  
This project solves that by using a **two-stage detection pipeline**:

Stage 1:
- Detect whether traffic is malicious or benign.

Stage 2:
- If malicious, classify into specific attack types:
  - DoS
  - PortScan
  - FTP-Patator
  - SSH-Patator

---

## 🧠 Models Used

### 🔹 Binary Model
- Input: 22 engineered flow-based features
- Output: Attack Probability
- Threshold-based detection

### 🔹 Multiclass Model
- Input: Same engineered feature set
- Output: Specific attack category using Softmax

Both models trained using:
- Stratified K-Fold Cross Validation
- Class Weighting
- Early Stopping
- StandardScaler

---

## 📊 Features Engineered (22 Features)

- Flow Duration
- Total Packets
- Total Bytes
- Packets/s
- Bytes/s
- Fwd Packets
- Bwd Packets
- Fwd Bytes
- Bwd Bytes
- Mean Packet Length
- Std Packet Length
- Max Packet Length
- Min Packet Length
- SYN Count
- ACK Count
- FIN Count
- RST Count
- IAT Mean
- IAT Std
- IAT Max
- IAT Min
- Destination Port

---

## 🛠️ Tech Stack

- Python
- TensorFlow / Keras
- Scikit-Learn
- Scapy
- NumPy
- Pandas
- Joblib

---



