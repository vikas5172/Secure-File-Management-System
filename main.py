import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
import random
import json
import hashlib
import os
import shutil
import time
from file_operations import upload_file
from file_operations import share_file
from file_operations import decrypt_file
from file_operations import write_to_file

SECURE_DIR = "secure_storage"
if not os.path.exists(SECURE_DIR):
    os.makedirs(SECURE_DIR)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def save_default_credentials():
    if not os.path.exists("credentials.json"):
        credentials = {
            "username": "admin",
            "password": hash_password("admin123")
        }
        with open("credentials.json", "w") as f:
            json.dump(credentials, f)


def upload_file_gui():
    source_path = filedialog.askopenfilename(title="Select file to upload")
    if source_path:
        try:
            upload_file(source_path)  # ✅ Call the encrypted upload function
            file_name = os.path.basename(source_path)
            messagebox.showinfo("Success", f"File '{file_name}' uploaded and encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error uploading file: {e}")


def read_file_gui():
    file_name = simpledialog.askstring("Read File", "Enter encrypted file name (with .enc):")
    if file_name:
        content = decrypt_file(file_name)
        if content:
            content_window = tk.Toplevel()
            content_window.title(f"Contents of {file_name}")
            text_area = scrolledtext.ScrolledText(content_window, wrap=tk.WORD, width=60, height=20)
            text_area.pack()
            text_area.insert(tk.END, content)
            text_area.configure(state="disabled")
        else:
            messagebox.showerror("Error", "Could not decrypt or find the file.")

def write_or_append_file_gui():
    file_name = simpledialog.askstring("Write/Append to File", "Enter file name:")
    if file_name:
        action = messagebox.askquestion("Action", "Do you want to append to the file?\nClick 'Yes' for Append and 'No' for Overwrite.")
        content = simpledialog.askstring("Content", "Enter content:")
        if content:
            mode = 'a' if action == 'yes' else 'w'
            try:
                # ✅ Use the file_operations.py function:
                write_to_file(file_name, content + "\n", mode)
                messagebox.showinfo("Success", f"File '{file_name}' updated and encrypted file re-synced!")
            except Exception as e:
                messagebox.showerror("Error", f"Error writing to file: {e}")

def view_metadata_gui():
    file_name = simpledialog.askstring("View Metadata", "Enter file name:")
    if file_name:
        file_path = os.path.join(SECURE_DIR, file_name)
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        try:
            stats = os.stat(file_path)
            metadata = f"Metadata for '{file_name}':\n\n" \
                       f"Size: {stats.st_size} bytes\n" \
                       f"Created on: {time.ctime(stats.st_ctime)}\n" \
                       f"Last modified: {time.ctime(stats.st_mtime)}"
            messagebox.showinfo("Metadata", metadata)
        except Exception as e:
            messagebox.showerror("Error", f"Error fetching metadata: {e}")

def share_file_gui():
    files = os.listdir(SECURE_DIR)
    if not files:
        messagebox.showinfo("Info", "No files available to share.")
        return

    share_window = tk.Toplevel()
    share_window.title("Share File")

    tk.Label(share_window, text="Select file to share:").pack(pady=5)
    selected_file = tk.StringVar(share_window)
    selected_file.set(files[0])

    dropdown = tk.OptionMenu(share_window, selected_file, *files)
    dropdown.pack(pady=5)

    def proceed_sharing():
        file_name = selected_file.get()
        destination_folder = filedialog.askdirectory(title="Select destination folder to share the file")
        if destination_folder:
            recipient = simpledialog.askstring("Recipient", "Enter recipient name (optional):")
            try:
                share_file(file_name, destination_folder, recipient or "Unknown")
                messagebox.showinfo("Success", f"File '{file_name}' shared successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Error sharing file: {e}")

    tk.Button(share_window, text="Share", command=proceed_sharing).pack(pady=10)

def launch_file_manager_gui():
    fm = tk.Tk()
    fm.title("Secure File Manager")

    tk.Label(fm, text="Choose Operation", font=("Arial", 14)).pack(pady=10)
    tk.Button(fm, text="Upload File", width=25, command=upload_file_gui).pack(pady=5)
    tk.Button(fm, text="Read File", width=25, command=read_file_gui).pack(pady=5)
    tk.Button(fm, text="Write / Append to File", width=25, command=write_or_append_file_gui).pack(pady=5)
    tk.Button(fm, text="View Metadata", width=25, command=view_metadata_gui).pack(pady=5)
    tk.Button(fm, text="Share File", width=25, command=share_file_gui).pack(pady=5)
    tk.Button(fm, text="Exit", width=25, command=fm.destroy).pack(pady=10)
    fm.mainloop()


def verify_otp_window(root):
    otp = str(random.randint(1000, 9999))
    messagebox.showinfo("OTP", f"Your OTP is: {otp}")

    otp_window = tk.Toplevel(root)
    otp_window.title("OTP Verification")

    tk.Label(otp_window, text="Enter OTP:").pack()
    otp_entry = tk.Entry(otp_window)
    otp_entry.pack()

    def check_otp():
        if otp_entry.get() == otp:
            messagebox.showinfo("Success", "Authentication Successful!")
            otp_window.destroy()
            root.destroy()
            launch_file_manager_gui()
        else:
            messagebox.showerror("Error", "Incorrect OTP!")

    tk.Button(otp_window, text="Verify", command=check_otp).pack()


def auth_window():
    save_default_credentials()
    root = tk.Tk()
    root.title("Secure File Manager - Login")

    tk.Label(root, text="Username").pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    tk.Label(root, text="Password").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    def login():
        with open("credentials.json", "r") as f:
            data = json.load(f)
        username = username_entry.get()
        password = password_entry.get()

        if username == data["username"] and hash_password(password) == data["password"]:
            verify_otp_window(root)
        else:
            messagebox.showerror("Error", "Invalid Credentials")

    tk.Button(root, text="Login", command=login).pack()
    root.mainloop()


if __name__ == "__main__":
    auth_window()
