import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
import random
import json
import hashlib
import os
import time
from file_operations import upload_file, share_file, decrypt_file, write_to_file

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
            success = upload_file(source_path)
            file_name = os.path.basename(source_path)

            if success:
                messagebox.showinfo("Success", f"File '{file_name}' uploaded and encrypted successfully!")
            else:
                messagebox.showerror("Upload Failed", f"File '{file_name}' was not uploaded due to a detected threat.")

        except Exception as e:
            messagebox.showerror("Error", f"Error uploading file: {e}")


def read_file_gui():
    file_name = simpledialog.askstring("Read File", "Enter encrypted file name (with .enc):")
    if file_name:
        content = decrypt_file(file_name)
        if content:
            content_window = tk.Toplevel()
            content_window.title(f"Contents of {file_name}")
            text_area = scrolledtext.ScrolledText(content_window, wrap=tk.WORD, width=80, height=25)
            text_area.pack(padx=10, pady=10)
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

def view_threat_log_gui():
    try:
        with open("threat_log.txt", "r") as f:
            content = f.read()
        log_window = tk.Toplevel()
        log_window.title("Threat Log Viewer")
        text_area = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, width=80, height=25)
        text_area.pack(padx=10, pady=10)
        text_area.insert(tk.END, content)
        text_area.config(state='disabled')
    except FileNotFoundError:
        messagebox.showerror("Error", "threat_log.txt not found!")

def launch_file_manager_gui():
    fm = tk.Tk()
    fm.title("Secure File Manager")
    fm.geometry("500x500")  # Enlarged window

    tk.Label(fm, text="Choose Operation", font=("Arial", 14)).pack(pady=10)
    tk.Button(fm, text="Upload File", width=30, command=upload_file_gui).pack(pady=5)
    tk.Button(fm, text="Read File", width=30, command=read_file_gui).pack(pady=5)
    tk.Button(fm, text="Write / Append to File", width=30, command=write_or_append_file_gui).pack(pady=5)
    tk.Button(fm, text="View Metadata", width=30, command=view_metadata_gui).pack(pady=5)
    tk.Button(fm, text="Share File", width=30, command=share_file_gui).pack(pady=5)
    tk.Button(fm, text="View Threat Log", width=30, command=view_threat_log_gui).pack(pady=5)
    tk.Button(fm, text="Exit", width=30, command=fm.destroy).pack(pady=10)
    fm.mainloop()

def auth_window():
    save_default_credentials()
    root = tk.Tk()
    root.title("Secure File Manager - Login")
    root.geometry("400x300")

    tk.Label(root, text="Username").pack(pady=5)
    username_entry = tk.Entry(root)
    username_entry.pack(pady=5)

    tk.Label(root, text="Password").pack(pady=5)
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(pady=5)

    otp_entry = None
    generated_otp = None  

    def verify_otp_window():
        nonlocal otp_entry, generated_otp
        generated_otp = str(random.randint(1000, 9999))
        messagebox.showinfo("OTP", f"Your OTP is: {generated_otp}")

        if otp_entry:
            otp_entry.delete(0, tk.END)
        else:
            tk.Label(root, text="Enter OTP:").pack(pady=5)
            otp_entry = tk.Entry(root)
            otp_entry.pack(pady=5)
            tk.Button(root, text="Verify OTP", command=check_otp).pack(pady=10)

    def check_otp():
        if otp_entry.get() == generated_otp:
            messagebox.showinfo("Success", "Authentication Successful!")
            root.destroy()
            launch_file_manager_gui()
        else:
            messagebox.showerror("Error", "Incorrect OTP!")
            otp_entry.delete(0, tk.END)

    def login():
        with open("credentials.json", "r") as f:
            data = json.load(f)
        if username_entry.get() == data["username"] and hash_password(password_entry.get()) == data["password"]:
            verify_otp_window()
        else:
            messagebox.showerror("Error", "Invalid Credentials")

    tk.Button(root, text="Login", command=login).pack(pady=10)
    root.mainloop()
if __name__ == "__main__":
    auth_window()
