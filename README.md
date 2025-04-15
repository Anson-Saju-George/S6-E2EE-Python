
---

```markdown
# 🔐 E2EE Chat App – Cryptography Project (CNS)

A console-based End-to-End Encrypted (E2EE) chat application built using Python and Flask. This project explores multiple encryption schemes and progressively implements them across three versions of the app.

---

## 📁 Project Versions

### ✅ **Version 1**
- Basic E2EE Chat
- Uses **RSA for key exchange** and **AES-GCM** for encryption
- Functional, stable, and working flawlessly

### 🔍 **Version 2** (⚡ Recommended for Demonstration)
- Displays **plaintext and encrypted messages in the terminal**
- Best suited for understanding how encryption works in real-time
- Easy to follow and test

### 🚧 **Version 3** (Under Development)
- Implements multiple encryption schemes:
  - 🔐 RSA + AES-GCM  
  - 🔐 X25519 + ChaCha20-Poly1305  
  - 🔁 Diffie-Hellman + AES-GCM
- Includes a Flask-based web UI
- Currently **unstable** but actively being developed

---

## 🛠️ Tech Stack

- Python
- Flask (for V3)
- cryptography & PyNaCl libraries

---

## 📦 Install Requirements

```bash
pip install flask cryptography pynacl
```

---

## ▶️ How to Run

Navigate to the version folder:

```bash
cd Ver
```

### Run Version 1

```bash
python Ver1.py
```

### Run Version 2 (Recommended)

```bash
python Ver2.py
```

### Run Version 3 (Experimental Web Version)

```bash
python Ver3.py
```

Then open your browser and go to:  
`http://127.0.0.1:5000/`

---

## 📚 License

License © 2025 Anson Saju George  
Developed as part of the **Cryptography & Network Security (CNS)** course.

---

```
