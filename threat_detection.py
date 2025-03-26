import os
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ThreatDetection:
    def __init__(self):
        self.suspicious_patterns = [
            '.exe', '.bat', '.sh',  # Executable files
            '../', '..\\'          # Directory traversal attempts
        ]
        self.access_log = {}
        self.max_attempts = 10
        self.log_file = "access_history.json"
        self._load_access_history()

    def _load_access_history(self):
        """Load previous access history if exists"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    self.access_log = json.load(f)
        except Exception as e:
            logging.error(f"Error loading access history: {e}")
            self.access_log = {}

    def _save_access_history(self):
        """Save current access history"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.access_log, f)
        except Exception as e:
            logging.error(f"Error saving access history: {e}")

    def check_file_operation(self, username, operation, filename):
        """
        Check if the file operation is suspicious
        Returns: (bool, str) - (is_suspicious, message)
        """
        try:
            # Log the attempt
            current_time = datetime.now().isoformat()
            if username not in self.access_log:
                self.access_log[username] = []
            
            self.access_log[username].append({
                'time': current_time,
                'operation': operation,
                'filename': filename
            })

            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if pattern in filename:
                    msg = f"Suspicious pattern detected: {pattern} in {filename}"
                    logging.warning(msg)
                    return True, msg

            # Check for rapid repeated operations - FIXED to allow more operations
            # Increased time window from 60 seconds to 300 seconds (5 minutes)
            # Increased max_attempts from 3 to 10
            self.max_attempts = 10  # Increased from 3
            recent_operations = [
                log for log in self.access_log[username][-self.max_attempts:]
                if (datetime.now() - datetime.fromisoformat(log['time'])).seconds < 300  # Increased from 60
            ]
            
            # Only trigger if there are really too many operations
            if len(recent_operations) >= self.max_attempts:
                msg = f"Too many operations attempted by {username}"
                logging.warning(msg)
                return True, msg

            self._save_access_history()
            return False, "Operation allowed"
        except Exception as e:
            logging.error(f"Error in threat detection: {e}")
            return True, f"Security error: {str(e)}"

    def log_operation(self, username, operation, filename, status):
        """Log file operations"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'operation': operation,
            'filename': filename,
            'status': status
        }
        logging.info(f"File operation: {json.dumps(log_entry)}")
