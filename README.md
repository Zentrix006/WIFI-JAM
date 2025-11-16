# 🛡️ WIFI-JAM – Red Team Intelligence Platform

A Python + PyQt5–based WiFi Network Reconnaissance & Red Team Intelligence Platform designed for ethical hacking labs.
WIFI-JAM performs ARP scanning, Nmap vulnerability analysis, live packet capture, MITM readiness checks, and provides real-time visualization — all inside a modern GUI.

## 🔍 Features

  - ✅ Modular Red Team intelligence engine
  - 🌐 Network discovery (ARP, vendor lookup, subnet validation)
  - 🧩 Vulnerability scanning using Nmap + NSE scripts
  - 📊 Real-time traffic monitoring with Matplotlib
  - 🔥 Dynamic risk scoring (CRITICAL, HIGH, MEDIUM, LOW)
  - ⚙️ Active testing tools:
     - ARP Spoof injection simulator
     - Wireshark launcher
     - Bettercap HTTP/HTTPS Proxy launcher
  - 🧵 Non-blocking, multi-threaded engine using QThread + ThreadPool
  - 📦 Highly decoupled daemon architecture for stability & maintainability

## 📸 Screenshots

### 🔧 Scanning + Result Output

![Scanner Main Interface]!<img width="1913" height="981" alt="image" src="https://github.com/user-attachments/assets/889e897a-a340-4b3f-b7d3-434164984ba1" />


![Scanner with scan of lo]!<img width="1600" height="728" alt="image" src="https://github.com/user-attachments/assets/4b561a49-2474-4800-87cd-62f156a17b68" />


!<img width="639" height="582" alt="image" src="https://github.com/user-attachments/assets/4e8cf6cc-f503-4ae3-b317-c554cf5f0fe6" />


![Viewing the traffic in graph representation]!<img width="639" height="585" alt="image" src="https://github.com/user-attachments/assets/a1c0587f-1e59-49c8-8ff1-ebb73f369e9f" />


<img width="437" height="196" alt="image (1)" src="https://github.com/user-attachments/assets/216cd576-9ef6-408b-9ccf-6ca37f518b96" />


---

## 🚀 How to Run

```bash
git clone https://github.com/Zentrix006/WIFI-JAM.git
cd WIFI-JAM
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 main.py

```

---

## 🧩 Architecture Overview

### Daemon Modules

| Module     | Purpose                                      |
|------------|----------------------------------------------|
| `discovery` | ARP scan, vendor lookup, subnet validation   |
| `scanner`   | Nmap scanning + NSE vulnerability detection  |
| `capture`   | Live Scapy sniffing (DNS, protocol stats)    |
| `exploit`   | ARP spoof injection simulator                |
| `external`  | Wireshark & Bettercap process manager        |

---

Performance

   -  Heavy tasks run in QThreads
    
   -  Matplotlib graphs updated safely
    
   -  Non-blocking UI at all times


---

⚙️ Technical Highlights

   - Fixed real-time graph crash (x and y must have same first dimension)
    
   - Prevented ARP scans on loopback subnet (127.0.0.0/8)
    
   - Removed mac-vendor-lookup startup freeze
    
   - Stabilized Wireshark & Bettercap launching
    
   - Improved thread-safe UI updates

---
## 📘 About This Project

WIFI-JAM was built as a part of my cybersecurity learning and red-team practice.

It simulates a **real-world reconnaisance workflow**, focusing on:

- Host discovery
- Port/service Enumeration
- Vulnerability identification
- Passive packet capture
- MITM readiness tests
- Real-time visual analytics
  
> ⚠️ This tool is strictly for educational use and authorized lab environments.
> Unauthorized network scanning is illegal.  
> ❌ This tool is for **educational and ethical testing** only.

---

## 🙋‍♂️ Developed By

**Arnoldo Felix R**  
Aspiring Cybersecurity Student | CTF Player | Python & Linux Enthusiast  
📍 Based in India 🇮🇳  
🧠 Computer Science Student (GITAM University)

---

## 📬 Contact Me

- 📧 Email: [arnoldofelix146@gmail.com](mailto:arnoldofelix146@gmail.com)
- 💼 LinkedIn: [Arnoldo Felix R](https://www.linkedin.com/in/arnoldo-felix-r-30123b313)  

