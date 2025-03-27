import os
import datetime
from tkinter import messagebox

BUFFER_OVERFLOW_THRESHOLD = 50 * 1024 * 1024  
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.scr']

def check_buffer_overflow(file_path):
    try:
        size = os.path.getsize(file_path)
        if size > BUFFER_OVERFLOW_THRESHOLD:
            log_threat("Buffer Overflow Risk", file_path)
            messagebox.showwarning("Threat Alert ⚠️", f"Buffer overflow risk detected! File too large: {round(size/(1024*1024), 2)} MB")
            return True
    except Exception as e:
        print(f"Error checking buffer overflow: {e}")
    return False


def check_malware(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        log_threat("Suspicious File (Malware risk)", file_path)
        messagebox.showwarning("Threat Alert ⚠️", f"Suspicious file type detected: {ext}")
        return True
    return False


def log_threat(threat_type, file_path):
    with open("threat_log.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} - {threat_type} - {file_path}\n")
