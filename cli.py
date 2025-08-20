import subprocess
import sys
import os
import platform
import time

def clear_terminal():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def print_welcome():
    print("""
============================================
        🔐 CYBERSECURITY CLI APP 🔐
============================================
Choose an option to proceed:

1. CryptoFile - File encryption and digital signing
2. IDS Tool   - Intrusion Detection System
3. SecureWipe - Secure file/directory deletion
4. Exit
""")

def main():
    while True:
        print_welcome()
        choice = input("Enter your choice (1/2/3/4): ").strip()

        if choice == '1':
            print("\n🔒 Launching CryptoFile...\n")
            subprocess.run([sys.executable, "crypto.py"])
            input("\nPress Enter to return to main menu...")
        elif choice == '2':
            print("\n🛡️  Launching IDS Tool...\n")
            rules_file = input("Enter path to IDS rules file (YAML) [default: C:/Users/prath/Desktop/College Project/All apps/sample1.yaml]: ").strip()
            if not rules_file:
                rules_file = "C:/Users/prath/Desktop/College Project/All apps/sample1.yaml"
            interface = input("Enter network interface to monitor (leave blank for default): ").strip()
            args = ["ids1.py", "-r", rules_file]
            if interface:
                args += ["-i", interface]

            try:
                subprocess.run([sys.executable] + args)
            except KeyboardInterrupt:
                print("\n🛑 IDS Tool interrupted. Returning to main menu...")
                time.sleep(1)  

            input("\nPress Enter to return to main menu...")
        elif choice == '3':
            print("\n🧹 Launching SecureWipe...\n")
            subprocess.run([sys.executable, "Securewipe.py"])
            input("\nPress Enter to return to main menu...")
        elif choice == '4':
            print("Goodbye! 👋")
            break
        else:
            print("Invalid choice. Please try again.\n")
            continue

        clear_terminal()  

if __name__ == "__main__":
    clear_terminal()  
    main()