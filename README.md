# PRODIGY_CS_05
# 📡 Interactive Network Packet Analyzer

A Python-based interactive network packet analyzer using Tkinter for the GUI and Scapy for packet sniffing. The tool allows users to monitor network traffic in real-time, filter by protocol, and display packets with color-coded details.

---

## 🚀 Features
- **Real-Time Packet Capture**: Capture packets live from the network.
- **Protocol Filtering**: Filter traffic by TCP, UDP, ICMP, or view all traffic.
- **Color-Coded Display**: Each protocol is displayed with a unique color.
- **User-Friendly Interface**: Simple, intuitive design with start/stop controls.
- **Threaded Sniffing**: Uses threading for non-blocking packet capture.

---

## 🛠️ Prerequisites
**Ensure you have the following installed:**
- **Python 3.x**
- **`tkinter`** (comes with Python)
- **`scapy`**

**Install required libraries with:**
```bash
pip install scapy
```

**⚠️ Important:** Ensure **WinPcap** or **Npcap** is installed for packet sniffing on Windows.

---

## 💻 Installation & Usage

### 📥 Clone the repository:
git clone
```bash
cd network-packet-analyzer
```

### ▶️ Run the application:
```bash
python analyzer.py
```

### 🛠️ Usage Steps:
- **Select** a protocol filter (**All**, **TCP**, **UDP**, **ICMP**).
- **Click** **Start Sniffing** to begin capturing packets.
- **Click** **Stop Sniffing** to halt packet capture.

---

## 🔍 How It Works
- **Packet Capture**: Uses Scapy's `sniff()` function to capture packets.
- **Protocol Detection**: Identifies protocol type based on IP headers.
- **Color-Coded Display**: **TCP** *(blue)*, **UDP** *(green)*, **ICMP** *(orange)*, **Other** *(gray)*.

---

## 🖥️ Sample Output
```plaintext
Source: 192.168.1.10 -> Destination: 192.168.1.20 | Protocol: TCP
Source: 192.168.1.15 -> Destination: 8.8.8.8 | Protocol: ICMP
```

---

## 🛠️ Troubleshooting
- **Error:** `No libpcap provider available`
  - Install **Npcap** from [npcap.com](https://npcap.com/) and ensure it's in **WinPcap API-compatible mode**.

- **Packets not captured:**
  - Run the script as an **administrator**.

---

## 🤝 Contributions
**Feel free to fork the repo, create issues, and submit PRs.**

---

## ⚖️ License
**This project is licensed under the MIT License.**

---

**Happy sniffing! 🕵️‍♂️📡**

