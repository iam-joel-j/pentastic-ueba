# 🔐 Pentastic — Insider Threat Detection using UEBA & Deception

---

## 📖 Definition
Pentastic is a cybersecurity system designed to detect and prevent insider threats using User and Entity Behavior Analytics (UEBA) combined with Deception Technology.  
It identifies abnormal user behavior, evaluates risk, and confirms malicious intent through controlled deception.

---

## 📌 Overview
Traditional security systems focus on external threats, but insider attacks are harder to detect.  
Pentastic monitors user activities in real-time, assigns risk scores, and triggers a deception environment when suspicious behavior is detected.

---

## 🚀 Key Features
- 🔍 Real-time user activity monitoring  
- 🧠 Risk-based anomaly detection  
- 📊 Interactive dashboard visualization  
- 🕵️ Honey Desktop (deception environment)  
- 🔐 Secure log transmission (SHA256)  
- 🔗 Tamper-proof logging (hash chaining)  
- 🚨 Insider attack detection and blocking  

---

## 🛠️ Tech Stack
Backend:  
- Python (Flask)  
- SQLite  

Frontend:  
- React.js  
- Tailwind CSS  
- Recharts  

Security:  
- SHA256 hashing  
- Secure API validation  
- Tamper-proof log storage  

---

## 🔄 System Workflow
1. User performs actions (login, file access, etc.)  
2. Log agent collects activity data  
3. Logs are securely sent to backend  
4. Risk engine evaluates behavior  
5. Dashboard displays user risk status  
6. If high risk → user redirected to Honey Desktop  
7. Interaction with decoy files → user blocked and alert generated  

---

## 🎯 Use Cases
- Enterprise insider threat detection  
- Employee activity monitoring  
- Prevention of data leakage  
- Cybersecurity training and simulations  
- Government and defense systems  

---

## 🔮 Future Enhancements
- 🤖 Machine learning-based anomaly detection  
- 📊 Behavioral baseline modeling per user  
- 🔗 Integration with SIEM tools  
- 📡 Real-time OS-level monitoring agent  
- 🌐 Cloud-based deployment  

---

## 📌 Conclusion
Pentastic provides an effective solution for detecting insider threats by combining behavior analysis, secure logging, and deception techniques.  
It not only identifies suspicious activity but also confirms malicious intent, ensuring stronger and smarter internal security.
