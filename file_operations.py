import os
import shutil
import time
import json
import datetime
from cryptography.fernet import Fernet

SHARE_LOG = "shared_logs.json"

# Define secure directory
SECURE_DIR = "secure_storage"

# Create secure directory if not exists
if not os.path.exists(SECURE_DIR):
    os.makedirs(SECURE_DIR)

# Encryption key management
KEY_FILE = "encryption_key.key"

def generate_key():
    """Generate a key and save it in a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    """Load the encryption key from a file."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

# Load encryption key
encryption_key = load_key()
cipher = Fernet(encryption_key)

def encrypt_file(source_path):
    """Encrypt and save file in secure storage."""
    try:
        if not os.path.exists(source_path):
            print("Source file does not exist.")
            return False

        file_name = os.path.basename(source_path) + ".enc"
        destination = os.path.join(SECURE_DIR, file_name)

        with open(source_path, "rb") as file:
            encrypted_data = cipher.encrypt(file.read())

        with open(destination, "wb") as enc_file:
            enc_file.write(encrypted_data)

        print(f"File '{file_name}' encrypted and stored securely.")

    except Exception as e:
        print("Error encrypting file:", e)

def decrypt_file(file_name):
    """Decrypt file and return content."""
    try:
        file_path = os.path.join(SECURE_DIR, file_name)

        if not os.path.exists(file_path):
            print("File not found.")
            return

        with open(file_path, "rb") as enc_file:
            decrypted_data = cipher.decrypt(enc_file.read())

        return decrypted_data.decode()

    except Exception as e:
        print("Error decrypting file:", e)
        return None

def sync_encrypted_version(file_name):
    """Encrypt the updated original file and overwrite its .enc version."""
    try:
        source_path = os.path.join(SECURE_DIR, file_name)
        if not os.path.exists(source_path):
            print(f"Original file '{file_name}' not found in secure storage.")
            return

        with open(source_path, "rb") as file:
            encrypted_data = cipher.encrypt(file.read())

        enc_file_name = file_name + ".enc"
        enc_file_path = os.path.join(SECURE_DIR, enc_file_name)

        with open(enc_file_path, "wb") as enc_file:
            enc_file.write(encrypted_data)

        print(f"Encrypted version '{enc_file_name}' updated successfully.")

    except Exception as e:
        print("Error syncing encrypted version:", e)

def upload_file(source_path):
    """Copy original file and create its encrypted version."""
    try:
        if not os.path.exists(source_path):
            print("Source file does not exist.")
            return

        file_name = os.path.basename(source_path)
        destination = os.path.join(SECURE_DIR, file_name)

        # Copy original
        shutil.copy2(source_path, destination)
        print(f"Original file '{file_name}' copied to secure storage.")

        # Create encrypted version
        sync_encrypted_version(file_name)

    except Exception as e:
        print("Error during upload:", e)

def read_file(file_name):
    """Decrypt and display file content."""
    content = decrypt_file(file_name)
    if content:
        print(f"Contents of '{file_name}':\n{content}")

def write_to_file(file_name, content, mode="w"):
    """Write or append content to the original file and re-sync encrypted version."""
    try:
        file_path = os.path.join(SECURE_DIR, file_name)
        with open(file_path, mode) as f:
            f.write(content)
        
        print(f"Original file '{file_name}' updated.")
        sync_encrypted_version(file_name)

    except Exception as e:
        print("Error writing to file:", e)

def view_metadata(file_name):
    """View metadata of stored file."""
    try:
        file_path = os.path.join(SECURE_DIR, file_name)
        if not os.path.exists(file_path):
            print("File not found.")
            return

        stats = os.stat(file_path)
        print(f"Metadata for '{file_name}':")
        print(f"  Size: {stats.st_size} bytes")
        print(f"  Created on: {time.ctime(stats.st_ctime)}")
        print(f"  Last modified: {time.ctime(stats.st_mtime)}")

    except Exception as e:
        print("Error fetching metadata:", e)

SHARE_LOG = "shared_logs.json"

def log_file_share(file_name, shared_to):
    """Log the sharing activity."""
    log_entry = {
        "file_name": file_name,
        "shared_to": shared_to,
        "timestamp": datetime.datetime.now().isoformat()
    }

    if not os.path.exists(SHARE_LOG):
        with open(SHARE_LOG, "w") as log_file:
            json.dump([log_entry], log_file, indent=4)
    else:
        with open(SHARE_LOG, "r") as log_file:
            logs = json.load(log_file)
        logs.append(log_entry)
        with open(SHARE_LOG, "w") as log_file:
            json.dump(logs, log_file, indent=4)

def share_file(file_name, destination_folder, shared_to="Unknown"):
    """Copy encrypted file to destination and log sharing."""
    try:
        source_path = os.path.join(SECURE_DIR, file_name)
        if not os.path.exists(source_path):
            print("File not found in secure storage.")
            return

        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)

        destination_path = os.path.join(destination_folder, file_name)
        shutil.copy2(source_path, destination_path)
        print(f"File '{file_name}' shared to '{destination_folder}'.")

        log_file_share(file_name, shared_to)

    except Exception as e:
        print("Error sharing file:", e)

# For testing purpose
if __name__ == "__main__":
    while True:
        print("\nChoose operation:")
        print("1. Upload File (Encrypt & Store)")
        print("2. Read File (Decrypt & View)")
        print("3. Write to File")
        print("4. Append to File")
        print("5. View Metadata")
        print("6. Share File")
        print("7. Exit")


        choice = input("Enter choice: ")

        if choice == '1':
            src = input("Enter source file path: ")
            upload_file(src)

        elif choice == '2':
            fname = input("Enter encrypted file name: ")
            read_file(fname)

        elif choice == '3':
            fname = input("Enter file name to write: ")
            data = input("Enter content: ")
            write_to_file(fname, data, mode="w")

        elif choice == '4':
            fname = input("Enter file name to append: ")
            data = input("Enter content to append: ")
            write_to_file(fname, data, mode="a")

        elif choice == '5':
            fname = input("Enter file name for metadata: ")
            view_metadata(fname)

        elif choice == '6':
            fname = input("Enter encrypted file name to share: ")
            dest = input("Enter destination folder path: ")
            recipient = input("Enter recipient or purpose (optional): ")
            share_file(fname, dest, recipient)
        
        elif choice == '7':
            break
