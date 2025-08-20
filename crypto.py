import os
import stat
import hashlib
import logging
import json
import tkinter as tk
from tkinter import filedialog
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, dsa, utils
from cryptography.hazmat.backends import default_backend


logging.basicConfig(
    filename='cryptofile.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def derive_key(password: str, salt: bytes, algorithm: str):
    logging.info(f"Deriving key using algorithm: {algorithm}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32 if algorithm == 'AES' else 24,  
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    h.verify(expected_hmac)

# New functions for asymmetric encryption

def generate_rsa_key_pair(key_size=2048):
    """Generate an RSA key pair and return both public and private keys."""
    logging.info(f"Generating RSA key pair with size: {key_size}")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key
def validate_rsa_public_key(public_key):
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Error: The provided key is not an RSA public key.")

def validate_rsa_private_key(private_key):
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Error: The provided key is not an RSA private key.")
    


def generate_dsa_key_pair(key_size=2048):
    """Generate a DSA key pair for digital signatures."""
    logging.info(f"Generating DSA key pair with size: {key_size}")
    private_key = dsa.generate_private_key(
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def validate_dsa_private_key(private_key):
    if not isinstance(private_key, dsa.DSAPrivateKey):
        raise ValueError("Error: The provided key is not a DSA private key.")

def validate_dsa_public_key(public_key):
    if not isinstance(public_key, dsa.DSAPublicKey):
        raise ValueError("Error: The provided key is not a DSA public key.")
    


def save_private_key(private_key, file_path, password=None):
    """Save a private key to a file, optionally encrypted with a password."""
    encryption_algorithm = None
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm or serialization.NoEncryption()
    )
    
    with open(file_path, 'wb') as f:
        f.write(pem)
    os.chmod(file_path, stat.S_IREAD)
    logging.info(f"Private key saved to: {file_path}")

def save_public_key(public_key, file_path):
    """Save a public key to a file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(file_path, 'wb') as f:
        f.write(pem)
    logging.info(f"Public key saved to: {file_path}")

def load_private_key(file_path, password=None):
    """Load a private key from a file, optionally decrypting with a password."""
    with open(file_path, 'rb') as f:
        private_key_data = f.read()
    
    try:
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=password.encode() if password else None,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        logging.error(f"Error loading private key: {e}")
        raise

def load_public_key(file_path):
    """Load a public key from a file."""
    with open(file_path, 'rb') as f:
        public_key_data = f.read()
    
    try:
        public_key = serialization.load_pem_public_key(
            public_key_data,
            backend=default_backend()
        )
        return public_key
    except Exception as e:
        logging.error(f"Error loading public key: {e}")
        raise

def rsa_encrypt_file(file_path: str, public_key_path: str):
    """Encrypt a file using RSA public key for the symmetric key and AES for the file content."""
    logging.info(f"Started RSA encryption for file: {file_path}")

    if file_path.endswith('.enc'):
        logging.error(f"Error: The file '{file_path}' is already encrypted.")
        print(f"Error: The file '{file_path}' is already encrypted.")
        return

    folder_name = os.path.splitext(file_path)[0]
    encrypted_file_path = os.path.join(folder_name, f"{os.path.basename(file_path)}.rsa.enc")

    try:
        # Load the public key
        public_key = load_public_key(public_key_path)
        
        # Verify it's an RSA public key
        validate_rsa_public_key(public_key)
        
        # Read the file
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Generate a random symmetric key for AES encryption
        symmetric_key = os.urandom(32)  # 256-bit key for AES
        
        # Encrypt the file with AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt the symmetric key with RSA
        encrypted_key = public_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Calculate HMAC for integrity
        hmac_value = generate_hmac(symmetric_key, encrypted_data)
        
        # Store the original file extension
        original_extension = os.path.splitext(file_path)[1].encode('utf-8')
        
        # Prepare metadata
        metadata = {
            'algorithm': 'RSA-AES',
            'key_length': len(encrypted_key),
            'iv': urlsafe_b64encode(iv).decode('utf-8'),
            'ext_length': len(original_extension),
            'ext': original_extension.decode('utf-8')
        }
        
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_length = len(metadata_json).to_bytes(2, 'big')
        
        # Combine all components
        final_data = (
            metadata_length +
            metadata_json +
            encrypted_key +
            encrypted_data +
            hmac_value
        )
        
        # Create output directory
        os.makedirs(folder_name, exist_ok=True)
        
        # Write the encrypted file
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(final_data)
        
        os.chmod(encrypted_file_path, stat.S_IREAD)
        print(f"\nFile successfully encrypted with RSA and saved as: {encrypted_file_path} 😊")
        print("The file has been set to read-only mode.\n")
        
        logging.info(f"File successfully encrypted with RSA: {encrypted_file_path}")
        
    except ValueError as ve:
        logging.error(f"Validation error during RSA encryption: {ve}")
        print(f"Error: {ve}")
    except Exception as e:
        logging.error(f"Error during RSA encryption: {e}")
        print(f"Error during RSA encryption: {e}")

def rsa_decrypt_file(encrypted_file_path: str, private_key_path: str, private_key_password: str = None):
    """Decrypt a file that was encrypted using RSA and AES."""
    logging.info(f"Started RSA decryption for file: {encrypted_file_path}")
    
    if not encrypted_file_path.endswith('.rsa.enc'):
        print(f"Error: The file '{encrypted_file_path}' is not RSA encrypted.")
        return
    
    try:
        # Load the private key
        private_key = load_private_key(private_key_path, private_key_password)
        
        # Verify it's an RSA private key
        validate_rsa_private_key(private_key)
        
        # Read the encrypted file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        # Extract metadata length
        metadata_length = int.from_bytes(encrypted_data[:2], 'big')
        
        # Extract and parse metadata
        metadata_json = encrypted_data[2:2+metadata_length]
        metadata = json.loads(metadata_json)
        
        # Verify it's an RSA encrypted file
        if metadata.get('algorithm') != 'RSA-AES':
            print(f"Error: The file was not encrypted with RSA-AES. Found: {metadata.get('algorithm', 'unknown')}")
            return
        
        # Extract components based on metadata
        key_length = metadata['key_length']
        iv = urlsafe_b64decode(metadata['iv'])
        ext_length = metadata['ext_length']
        original_extension = metadata['ext']
        
        # Extract encrypted key, encrypted data, and HMAC
        current_pos = 2 + metadata_length
        encrypted_key = encrypted_data[current_pos:current_pos+key_length]
        current_pos += key_length
        
        hmac_value = encrypted_data[-32:]  # Last 32 bytes are HMAC
        actual_encrypted_data = encrypted_data[current_pos:-32]
        
        # Decrypt the symmetric key with RSA
        symmetric_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Verify HMAC
        try:
            verify_hmac(symmetric_key, actual_encrypted_data, hmac_value)
        except Exception:
            print("Decryption failed: The file has been tampered with or the key is incorrect.")
            return
        
        # Decrypt the file data with AES
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        try:
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        except ValueError:
            print("Decryption failed: Invalid padding. The key may be incorrect.")
            return
        
        # Write decrypted data to a new file
        decrypted_file_path = os.path.join(
            os.path.dirname(encrypted_file_path),
            f"{os.path.splitext(os.path.splitext(os.path.basename(encrypted_file_path))[0])[0]}{original_extension}"
        )
        
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        print(f"\nFile successfully decrypted and saved as: {decrypted_file_path} 😊")
        print("Enjoy your decrypted file! 👋\n")
        
        logging.info(f"File successfully decrypted with RSA: {decrypted_file_path}")
        
    except ValueError as ve:
        logging.error(f"Validation error during RSA decryption: {ve}")
        print(f"Error: {ve}")
    except Exception as e:
        logging.error(f"Error during RSA decryption: {e}")
        print(f"Error during RSA decryption: {e}")

def dsa_sign_file(file_path: str, private_key_path: str, private_key_password: str = None):
    """Sign a file using DSA for authentication."""
    logging.info(f"Signing file with DSA: {file_path}")
    
    try:
        # Load the private key
        private_key = load_private_key(private_key_path, private_key_password)
        
        # Check if it's a DSA key
        validate_dsa_private_key(private_key)
        
        # Read the file
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Calculate file hash
        file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        file_hash.update(file_data)
        digest = file_hash.finalize()
        
        # Sign the hash
        signature = private_key.sign(
            digest,
            utils.Prehashed(hashes.SHA256())
        )
        
        # Save the signature
        signature_path = f"{file_path}.sig"
        with open(signature_path, 'wb') as sig_file:
            sig_file.write(signature)
        
        print(f"\nFile successfully signed. Signature saved as: {signature_path} 😊\n")
        logging.info(f"File signed with DSA: {signature_path}")
        
    except ValueError as ve:
        logging.error(f"Validation error during DSA signing: {ve}")
        print(f"Error: {ve}")
    except Exception as e:
        logging.error(f"Error during DSA signing: {e}")
        print(f"Error during DSA signing: {e}")

def dsa_verify_file(file_path: str, signature_path: str, public_key_path: str):
    """Verify a file's DSA signature."""
    logging.info(f"Verifying DSA signature for file: {file_path}")
    
    try:
        # Load the public key
        public_key = load_public_key(public_key_path)
        
        # Check if it's a DSA key
        validate_dsa_public_key(public_key)
        
        # Read the file
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Read the signature
        with open(signature_path, 'rb') as sig_file:
            signature = sig_file.read()
        
        # Calculate file hash
        file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        file_hash.update(file_data)
        digest = file_hash.finalize()
        
        # Verify the signature
        try:
            public_key.verify(
                signature,
                digest,
                utils.Prehashed(hashes.SHA256())
            )
            print(f"\nSignature verification successful! The file is authentic. ✅\n")
            logging.info(f"DSA signature verification successful for: {file_path}")
            return True
        except Exception:
            print(f"\nSignature verification failed! The file may have been tampered with. ❌\n")
            logging.warning(f"DSA signature verification failed for: {file_path}")
            return False
        
    except ValueError as ve:
        logging.error(f"Validation error during DSA verification: {ve}")
        print(f"Error: {ve}")
        return False
    except Exception as e:
        logging.error(f"Error during DSA verification: {e}")
        print(f"Error during DSA verification: {e}")
        return False

#Encrypt file function (original symmetric encryption)
def encrypt_file(file_path: str, password: str, algorithm: str = 'AES'):
    logging.info(f"Started encryption for file: {file_path}")

    if file_path.endswith('.enc'):
        logging.error(f"Error: The file '{file_path}' is already encrypted.")
        print(f"Error: The file '{file_path}' is already encrypted.")
        return

    folder_name = os.path.splitext(file_path)[0]
    encrypted_file_path = os.path.join(folder_name, f"{os.path.basename(file_path)}.enc")

    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        print(f"Error reading file: {e}")
        return

    # Encryption process...
    try:
        salt = os.urandom(16)
        key = derive_key(password, salt, algorithm)

        if algorithm == 'AES':
            iv = os.urandom(16)  
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        elif algorithm == 'DES':
            iv = os.urandom(8)  
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        else:
            raise ValueError("Unsupported algorithm. Choose 'AES' or 'DES'.")

        padder = padding.PKCS7(cipher.algorithm.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        hmac_value = generate_hmac(key, encrypted_data)

        original_extension = os.path.splitext(file_path)[1].encode('utf-8')

        encrypted_data = (
            algorithm.encode('utf-8') + b'|' +
            salt + iv +
            len(original_extension).to_bytes(1, 'big') +
            original_extension +
            encrypted_data +
            hmac_value
        )

        os.makedirs(folder_name, exist_ok=True)

        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        secret_key = urlsafe_b64encode(key).decode('utf-8')
        secret_key_path = os.path.join(folder_name, "secret.key")

        with open(secret_key_path, 'w') as secret_file:
            secret_file.write(secret_key)

        os.chmod(encrypted_file_path, stat.S_IREAD)
        os.chmod(secret_key_path, stat.S_IREAD)
        print(f"\nFile successfully encrypted and saved as: {encrypted_file_path} 😊")
        print(f"Secret key saved as: {secret_key_path}")
        print("Both files have been set to read-only mode.\n")
        
        logging.info(f"File successfully encrypted: {encrypted_file_path}")

    except PermissionError:
        logging.error(f"Permission error: Unable to write to file '{encrypted_file_path}'. Check file permissions.")
        print(f"Permission error: Unable to write to file '{encrypted_file_path}'. Check file permissions.")
    except Exception as e:
        logging.error(f"Error during encryption: {e}")
        print(f"Error during encryption: {e}")

#decrypt file function (original symmetric decryption)
def decrypt_file(encrypted_file_path: str, password: str = None, secret_key: str = None, algorithm: str = 'AES'):
    """Decrypt an encrypted file using either a password or a secret key."""
    if not encrypted_file_path.endswith('.enc'):
        print(f"Error: The file '{encrypted_file_path}' is not encrypted.")
        return

    # Read the encrypted file content
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Extract metadata
    file_algorithm, encrypted_data = encrypted_data.split(b'|', 1)
    file_algorithm = file_algorithm.decode('utf-8')

    if file_algorithm != algorithm:
        print(f"Decryption failed: Encryption algorithm ({file_algorithm}) does not match the chosen decryption algorithm ({algorithm}).")
        return

    # Extract components from encrypted data
    salt = encrypted_data[:16]
    iv_length = 16 if algorithm == 'AES' else 8
    iv = encrypted_data[16:16 + iv_length]
    ext_length = encrypted_data[16 + iv_length]
    original_extension = encrypted_data[17 + iv_length:17 + iv_length + ext_length].decode('utf-8')
    hmac_value = encrypted_data[-32:]
    actual_encrypted_data = encrypted_data[17 + iv_length + ext_length:-32]

    # Derive or decode the key
    if password:
        key = derive_key(password, salt, algorithm)
    elif secret_key:
        try:
            key = urlsafe_b64decode(secret_key)
        except Exception as e:
            print(f"Error decoding secret key: {e}")
            return
    else:
        print("Decryption failed: No password or secret key provided.")
        return

    # Verify the HMAC
    try:
        verify_hmac(key, actual_encrypted_data, hmac_value)
    except Exception:
        print("Decryption failed: The file has been tampered with or the key is incorrect.")
        return

    # Initialize cipher and decrypt data
    if algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif algorithm == 'DES':
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    else:
        raise ValueError("Unsupported algorithm. Choose 'AES' or 'DES'.")

    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(cipher.algorithm.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError:
        print("Decryption failed: Invalid padding. The key or password may be incorrect.")
        return

    # Write decrypted data to a new file
    decrypted_file_path = os.path.join(
        os.path.dirname(encrypted_file_path),
        f"{os.path.splitext(os.path.basename(encrypted_file_path))[0]}{original_extension}"
    )
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"\nFile successfully decrypted and saved as: {decrypted_file_path} 😊")
    print("Enjoy your decrypted file! 👋\n")

    logging.info(f"Started decryption for file: {encrypted_file_path}")
    logging.info(f"File successfully decrypted: {decrypted_file_path}")

# Function to detect key type
def detect_key_type(key_path, password=None):
    """Detect if a key is RSA or DSA, and if it's private or public."""
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        # Try to load as public key first
        try:
            key = serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
            # Determine if it's RSA or DSA
            if isinstance(key, rsa.RSAPublicKey):
                return "RSA public key"
            elif isinstance(key, dsa.DSAPublicKey):
                return "DSA public key"
            else:
                return "Unknown public key type"
        except Exception:
            # If not a public key, try as private key
            try:
                key = serialization.load_pem_private_key(
                    key_data,
                    password=password.encode() if password else None,
                    backend=default_backend()
                )
                # Determine if it's RSA or DSA
                if isinstance(key, rsa.RSAPrivateKey):
                    return "RSA private key"
                elif isinstance(key, dsa.DSAPrivateKey):
                    return "DSA private key"
                else:
                    return "Unknown private key type"
            except Exception:
                return "Not a valid key file or incorrect password"
    except Exception as e:
        return f"Error reading key file: {e}"

# New function for file selection
def select_file(title="Select a file"):
    """Open a file dialog to select a file."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    file_path = filedialog.askopenfilename(title=title)
    root.destroy()
    return file_path if file_path else None

# New function for directory selection
def select_directory(title="Select a directory"):
    """Open a dialog to select a directory."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    dir_path = filedialog.askdirectory(title=title)
    root.destroy()
    return dir_path if dir_path else None

# Welcome message function
def print_welcome_message():
    """Print the welcome message for the CryptoFile utility."""
    welcome_message = """
    ==========================================
               Welcome to CryptoFile
    ==========================================
    A command-line tool for encrypting and decrypting files
    using symmetric (AES/DES) and asymmetric (RSA/DSA) algorithms.
    """
    print(welcome_message)

def get_non_empty_input(prompt: str) -> str:
    """Prompt the user for input and ensure it is not empty."""
    while True:
        user_input = input(prompt).strip()
        if user_input:
            return user_input
        else:
            print("Error: This field cannot be empty. Please enter the required data.")

def get_file_path(prompt: str, allow_browse: bool = True) -> str:
    """Get file path either by input or file selection."""
    if allow_browse:
        choice = input(f"{prompt} (Enter 1 to type path, 2 to browse): ").strip()
        if choice == '2':
            file_path = select_file("Select File")
            if file_path:
                print(f"Selected: {file_path}")
                return file_path
            else:
                print("No file selected. Please enter the path manually.")
    
    return get_non_empty_input("Enter the file path: ").strip().strip('"')

def get_directory_path(prompt: str, allow_browse: bool = True) -> str:
    """Get directory path either by input or directory selection."""
    if allow_browse:
        choice = input(f"{prompt} (Enter 1 to type path, 2 to browse): ").strip()
        if choice == '2':
            dir_path = select_directory("Select Directory")
            if dir_path:
                print(f"Selected: {dir_path}")
                return dir_path
            else:
                print("No directory selected. Please enter the path manually.")
    
    return get_non_empty_input("Enter the directory path: ").strip().strip('"')

def main():
    print_welcome_message()

    while True:
        print("1. Encrypt a file (Symmetric: AES/DES)")
        print("2. Decrypt a file (Symmetric: AES/DES)")
        print("3. Generate RSA key pair")
        print("4. Generate DSA key pair")
        print("5. Encrypt a file with RSA")
        print("6. Decrypt a file with RSA")
        print("7. Sign a file with DSA")
        print("8. Verify a file signature")
        print("9. Check key type")
        print("10. Exit")
        choice = get_non_empty_input("Enter your choice (1-10): ").strip()
        print()  

        if choice == '1':
            file_path = get_file_path("Select the file to encrypt")
            password = get_non_empty_input("Enter the encryption password: ")
            algorithm = get_non_empty_input("Choose the encryption algorithm (AES/DES): ").upper()
            if algorithm in ['AES', 'DES']:
                encrypt_file(file_path, password, algorithm)
            else:
                print("Invalid algorithm choice. Please choose AES or DES.")
        
        elif choice == '2':
            file_path = get_file_path("Select the file to decrypt")
            method = get_non_empty_input("Do you want to decrypt using password or secret key? (Enter 'password' or 'secret'): ").strip().lower()
            algorithm = get_non_empty_input("Choose the decryption algorithm (AES/DES): ").upper()
            if method == 'password':
                password = get_non_empty_input("Enter the decryption password: ")
                decrypt_file(file_path, password=password, algorithm=algorithm)
            elif method == 'secret':
                secret_path = get_file_path("Select the secret key file")
                with open(secret_path, 'r') as secret_file:
                    secret_key = secret_file.read().strip()
                decrypt_file(file_path, secret_key=secret_key, algorithm=algorithm)
            else:
                print("Invalid method. Please choose 'password' or 'secret'.")
        
        elif choice == '3':
            key_size = int(get_non_empty_input("Enter key size (2048, 3072, 4096): ").strip())
            key_password = input("Enter a password to protect the private key (leave empty for no password): ").strip()
            key_password = key_password if key_password else None
            
            # Generate the keys
            private_key, public_key = generate_rsa_key_pair(key_size)
            
            # Save the keys
            output_dir = get_directory_path("Select directory to save keys")
            private_key_path = os.path.join(output_dir, "private_rsa_key.pem")
            public_key_path = os.path.join(output_dir, "public_rsa_key.pem")
            
            save_private_key(private_key, private_key_path, key_password)
            save_public_key(public_key, public_key_path)
            
            print(f"\nRSA key pair generated successfully! 🔑")
            print(f"Private key saved to: {private_key_path}")
            print(f"Public key saved to: {public_key_path}")
            if key_password:
                print("Private key is password-protected. Keep your password safe!\n")
            else:
                print("Private key is NOT password-protected. Keep it safe!\n")
        
        elif choice == '4':
            key_size = int(get_non_empty_input("Enter key size (2048, 3072): ").strip())
            key_password = input("Enter a password to protect the private key (leave empty for no password): ").strip()
            key_password = key_password if key_password else None
            
            # Generate the keys
            private_key, public_key = generate_dsa_key_pair(key_size)
            
            # Save the keys
            output_dir = get_directory_path("Select directory to save keys")
            private_key_path = os.path.join(output_dir, "private_dsa_key.pem")
            public_key_path = os.path.join(output_dir, "public_dsa_key.pem")
            
            save_private_key(private_key, private_key_path, key_password)
            save_public_key(public_key, public_key_path)
            
            print(f"\nDSA key pair generated successfully! 🔑")
            print(f"Private key saved to: {private_key_path}")
            print(f"Public key saved to: {public_key_path}")
            if key_password:
                print("Private key is password-protected. Keep your password safe!\n")
            else:
                print("Private key is NOT password-protected. Keep it safe!\n")
        
        elif choice == '5':
            file_path = get_file_path("Select the file to encrypt with RSA")
            public_key_path = get_file_path("Select the RSA public key file")
            
            # Check if the key is actually an RSA public key
            key_type = detect_key_type(public_key_path)
            if key_type != "RSA public key":
                print(f"Error: The selected key is not an RSA public key. Detected: {key_type}")
                continue
                
            rsa_encrypt_file(file_path, public_key_path)
        
        elif choice == '6':
            file_path = get_file_path("Select the RSA encrypted file")
            private_key_path = get_file_path("Select the RSA private key file")
            
            # Check if the key is actually an RSA private key
            key_type = detect_key_type(private_key_path)
            if key_type != "RSA private key":
                print(f"Error: The selected key is not an RSA private key. Detected: {key_type}")
                continue
                
            key_password = input("Enter the private key password (leave empty if not password-protected): ").strip()
            key_password = key_password if key_password else None
            
            rsa_decrypt_file(file_path, private_key_path, key_password)
        
        elif choice == '7':
            file_path = get_file_path("Select the file to sign")
            private_key_path = get_file_path("Select the DSA private key file")
            
            # Check if the key is actually a DSA private key
            key_type = detect_key_type(private_key_path)
            if key_type != "DSA private key":
                print(f"Error: The selected key is not a DSA private key. Detected: {key_type}")
                continue
                
            key_password = input("Enter the private key password (leave empty if not password-protected): ").strip()
            key_password = key_password if key_password else None
            
            dsa_sign_file(file_path, private_key_path, key_password)
        
        elif choice == '8':
            file_path = get_file_path("Select the file to verify")
            signature_path = get_file_path("Select the signature file")
            public_key_path = get_file_path("Select the DSA public key file")
            
            # Check if the key is actually a DSA public key
            key_type = detect_key_type(public_key_path)
            if key_type != "DSA public key":
                print(f"Error: The selected key is not a DSA public key. Detected: {key_type}")
                continue
                
            dsa_verify_file(file_path, signature_path, public_key_path)
        
        elif choice == '9':
            key_path = get_file_path("Select the key file to check")
            key_password = input("Enter the key password (leave empty if not password-protected): ").strip()
            key_password = key_password if key_password else None
            
            key_type = detect_key_type(key_path, key_password)
            print(f"\nKey type: {key_type}\n")
        
        elif choice == '10':
            print("\nThank you for using CryptoFile! Goodbye! 👋\n")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 10.")
        
        print()  # Add an empty line for better readability

if __name__ == "__main__":
    main()