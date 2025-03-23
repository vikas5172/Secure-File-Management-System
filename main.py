import tkinter as tk
from tkinter import messagebox
import random
import json
import hashlib
import os

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Save default credentials (you can change username & password if you like)
def save_default_credentials():
    if not os.path.exists("credentials.json"):
        credentials = {
            "username": "admin",
            "password": hash_password("admin123")
        }
        with open("credentials.json", "w") as f:
            json.dump(credentials, f)

# OTP Verification
def verify_otp_window(root):
    otp = str(random.randint(1000, 9999))
    messagebox.showinfo("OTP", f"Your OTP is {otp}")

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
            start_file_manager()
        else:
            messagebox.showerror("Error", "Incorrect OTP!")

    tk.Button(otp_window, text="Verify", command=check_otp).pack()

# Authentication window
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
        print(f"Entered username: {username}")
        print(f"Hashed entered password: {hash_password(password)}")
        print(f"Stored username: {data['username']}")
        print(f"Stored password: {data['password']}")

        if username == data["username"] and hash_password(password) == data["password"]:
            verify_otp_window(root)
        else:
            messagebox.showerror("Error", "Invalid Credentials")

    tk.Button(root, text="Login", command=login).pack()
    root.mainloop()

# Placeholder for next steps
def start_file_manager():
    pass

# Start authentication
if __name__ == "__main__":
    auth_window()
