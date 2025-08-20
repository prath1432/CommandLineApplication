# CommandLineApplication
Command-Line Cybersecurity Toolkit – A Python-based project that includes three defensive tools: CryptoFile (file encryption/decryption), SecureWipe (secure file deletion), and a lightweight IDS for live network traffic monitoring and alerting on suspicious activity.

# Command-Line Cybersecurity Toolkit

This repository contains a set of command-line cybersecurity tools developed as part of a college project.  
It includes three independent tools:

| Tool               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| CryptoFile     | Encrypts and decrypts files using symmetric cryptography                    |
| SecureWipe     | Securely deletes files by overwriting their contents                        |
| IDS Tool       | Performs basic real-time packet inspection and detects suspicious traffic   |

## 🛠 Requirements

pip install -r requirements.txt

## Usage

You can run each tool separately or use the main CLI launcher (cli.py) to access all of them from a single menu.

🔐 CryptoFile
python3 crypto.py --encrypt <file>
python3 crypto.py --decrypt <file>

🧹 SecureWipe
python3 Securewipe.py <file>

🚨 IDS Tool
sudo python3 ids1.py

⚠️ The IDS script requires root privileges to capture network traffic.

🧭 Run All Tools from a Unified Menu
python3 cli.py

This will open a command-line menu where you can choose between CryptoFile, SecureWipe, and the IDS tool.

## Project Structure
cli.py            # Optional main CLI wrapper  
crypto.py         # CryptoFile implementation  
Securewipe.py     # Secure deletion tool  
ids1.py           # Intrusion Detection System  
sample1.yaml      # Example configuration file for IDS (rules/settings)
requirements.txt  # Python dependencies  
README.md         # Project documentation
