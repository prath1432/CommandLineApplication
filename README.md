# Command-Line Cybersecurity Toolkit

This repository contains a set of command-line cybersecurity tools developed as part of a college project.  
It includes three independent tools:

| Tool               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| **CryptoFile**     | Encrypts and decrypts files using symmetric cryptography                    |
| **SecureWipe**     | Securely deletes files by overwriting their contents                        |
| **IDS Tool**       | Performs basic real-time packet inspection and detects suspicious traffic   |

---

### 🔧 Installation

Just clone this repository:

git clone https://github.com/prath1432/CommandLineApplication.git

cd CommandLineApplication

pip install -r requirements.txt

## 🚀 Usage

You can run each tool separately, or use the cli.py launcher to access all of them from one menu:

🔐 CryptoFile

python3 crypto.py --encrypt <file>


python3 crypto.py --decrypt <file>

🧹 SecureWipe

python3 Securewipe.py <file>

🚨 IDS Tool (Linux only)

sudo python3 ids1.py


⚠️ The IDS script requires root privileges to capture network traffic.


🧭 Unified CLI Menu (Recommended)

python3 cli.py


This will display a menu where you can choose between CryptoFile, SecureWipe, and the IDS Tool.

## 📂 Project Structure
cli.py                                                         # Main CLI launcher  
crypto.py                                                      # CryptoFile implementation  
Securewipe.py                                                  # Secure deletion tool  
ids1.py                                                        # Simple Intrusion Detection System  
sample1.yaml                                                   # Example config / rule file  
requirements.txt                                               # Python dependencies  
README.md                                                      # Documentation  
 

## ✅ Compatibility
Tool	              Windows	Linux
CryptoFile	           ✅	   ✅
SecureWipe	           ✅	   ✅
IDS Tool	             ❌   ✅

⚠️ The IDS Tool requires raw packet capturing, which is currently supported only on Linux systems.

## 🙏 Contributing

Feel free to fork the project, add new detection rules, or improve the tools — contributions are welcome!
