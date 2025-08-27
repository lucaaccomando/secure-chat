# 🔐 Secure Chat

![Python](https://img.shields.io/badge/Python-3.11%20%7C%202.7-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Security](https://img.shields.io/badge/End--to--End-Encryption-orange)

> A lightweight, end-to-end encrypted messaging system built with Python.  
> Secure-Chat provides private client-server communication using **RSA** and **AES** encryption, with a **Prompt Toolkit** interface for a smooth terminal experience.

---

## ✨ Features

- 🔑 **Hybrid Encryption**: RSA for key exchange, AES for message payloads.  
- 💬 **Interactive TUI**: Built with [Prompt Toolkit](https://python-prompt-toolkit.readthedocs.io/).  
- 👥 **Multi-user Support**: Server can handle multiple clients simultaneously.  
- 📡 **Threaded I/O**: Non-blocking communication using Python sockets.  
- 🛡️ **Security-focused**: Keys never leave the local machine.  
- 📂 **Modular Codebase**: Easily extensible for new features (file transfer, group chats, etc.).  

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/your-username/secure-chat.git
cd secure-chat
```

Install dependencies (create a venv recommended):

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### 1. Start the Server
```bash
python server.py
```

### 2. Start a Client
```bash
python client.py
```

You’ll be prompted to:
- Enter your username  
- Generate / load RSA keys  
- Connect securely to the server  

---

## ⚙️ Configuration

- Default port: `5000` (changeable in `server.py`)  
- RSA key size: `2048 bits`  
- AES mode: `CBC with PKCS7 padding`  

---

## 🧪 Example Session

```text
[Client A] > Hello, world!  
[Client B] < Encrypted message received... decrypted -> "Hello, world!"
```

---

## 📂 Project Structure

```
secure-chat/
├── client.py          # Secure chat client
├── server.py          # Secure chat server
├── crypto_utils.py    # RSA/AES encryption helpers
├── requirements.txt   # Python dependencies
└── README.txt         # Project documentation
```

---

## 🛠️ Tech Stack

- **Language:** Python (3.11+, legacy 2.7 support)  
- **Libraries:** `cryptography`, `prompt_toolkit`, `socket`, `threading`  
- **Protocols:** RSA + AES hybrid encryption  

---

## 📈 Roadmap

- [ ] 🔔 Add notification system  
- [ ] 📂 Secure file transfers  
- [ ] 📱 WebSocket client (browser-based)  
- [ ] 👥 Group chats with shared symmetric keys  

---

## 🤝 Contributing

Pull requests are welcome!  
If you’d like to contribute:
1. Fork the repo  
2. Create a feature branch  
3. Submit a PR with detailed notes  

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.  

---

> ⚠️ **Disclaimer:** This project is for **educational purposes** only. Do not use in production without a professional security audit.
