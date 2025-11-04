import os
import logging
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import queue
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Set up advanced logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("file_encryption.log"),
                              logging.StreamHandler()])

logger = logging.getLogger(__name__)

class FileEncryptor:
    def __init__(self, password: str):
        """
        Initialize the FileEncryptor with a password.
        """
        self.password = password
        logger.info("FileEncryptor initialized.")

    def encrypt_file(self, file_path: str, callback=None) -> bool:
        """Encrypt a single file using AES-128 CBC with PBKDF2 key derivation."""
        try:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=16,
                salt=salt,
                iterations=480000,
                backend=default_backend()
            )
            key = kdf.derive(self.password.encode())
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            temp_path = file_path + '.enc'
            with open(file_path, 'rb') as fin, open(temp_path, 'wb') as fout:
                fout.write(salt)
                fout.write(iv)
                while True:
                    chunk = fin.read(4096)
                    if callback:
                        callback(len(chunk))
                    if not chunk:
                        break
                    padded = padder.update(chunk)
                    encrypted = encryptor.update(padded)
                    fout.write(encrypted)
                final_padded = padder.finalize()
                final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
                fout.write(final_encrypted)
            os.remove(file_path)
            os.rename(temp_path, file_path)
            logger.info(f"Encrypted file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error encrypting file {file_path}: {str(e)}")
            return False

    def decrypt_file(self, file_path: str, callback=None) -> bool:
        """Decrypt a single file using AES-128 CBC with PBKDF2 key derivation."""
        try:
            temp_path = file_path + '.dec'
            with open(file_path, 'rb') as fin:
                salt = fin.read(16)
                if len(salt) != 16:
                    raise ValueError("Invalid salt length.")
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=16,
                    salt=salt,
                    iterations=480000,
                    backend=default_backend()
                )
                key = kdf.derive(self.password.encode())
                iv = fin.read(16)
                if len(iv) != 16:
                    raise ValueError("Invalid IV length.")
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                with open(temp_path, 'wb') as fout:
                    while True:
                        chunk = fin.read(4096)
                        if callback:
                            callback(len(chunk))
                        if not chunk:
                            break
                        decrypted = decryptor.update(chunk)
                        unpadded = unpadder.update(decrypted)
                        fout.write(unpadded)
                    final_dec = decryptor.finalize()
                    final_unpad = unpadder.update(final_dec) + unpadder.finalize()
                    fout.write(final_unpad)
            os.remove(file_path)
            os.rename(temp_path, file_path)
            logger.info(f"Decrypted file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error decrypting file {file_path}: {str(e)}")
            return False

    def hide_file(self, file_path: str) -> bool:
        """Hide a file or directory by setting hidden attribute (Windows) or prefixing with dot (Unix)."""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                if attrs == -1:
                    raise OSError("File not found.")
                ctypes.windll.kernel32.SetFileAttributesW(file_path, attrs | 2)  # FILE_ATTRIBUTE_HIDDEN = 2
            else:  # Unix-like
                dir_name, base_name = os.path.split(file_path)
                if not base_name.startswith('.'):
                    new_path = os.path.join(dir_name, '.' + base_name)
                    os.rename(file_path, new_path)
            logger.info(f"Hid: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error hiding {file_path}: {str(e)}")
            return False

    def unhide_file(self, file_path: str) -> bool:
        """Unhide a file or directory."""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                if attrs == -1:
                    raise OSError("File not found.")
                ctypes.windll.kernel32.SetFileAttributesW(file_path, attrs & ~2)
            else:  # Unix-like
                dir_name, base_name = os.path.split(file_path)
                if base_name.startswith('.'):
                    new_path = os.path.join(dir_name, base_name[1:])
                    os.rename(file_path, new_path)
            logger.info(f"Unhid: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error unhiding {file_path}: {str(e)}")
            return False

class EncryptionApp:
    def __init__(self):
        """Initialize the enhanced GUI application."""
        self.root = tk.Tk()
        self.root.title("File Encryption Tool")
        self.root.geometry("500x400")

        self.password_label = tk.Label(self.root, text="Password:")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)

        self.path_label = tk.Label(self.root, text="Select Folder/File:")
        self.path_label.pack(pady=5)
        self.path_entry = tk.Entry(self.root, width=50)
        self.path_entry.pack(pady=5)

        self.browse_button = tk.Button(self.root, text="Browse", command=self.browse_path)
        self.browse_button.pack(pady=5)

        self.encrypt_button = tk.Button(self.root, text="Encrypt & Hide", command=self.start_encrypt)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(self.root, text="Decrypt & Unhide", command=self.start_decrypt)
        self.decrypt_button.pack(pady=10)

        self.progress = ttk.Progressbar(self.root, orient='horizontal', length=400, mode='determinate')
        self.progress.pack(pady=10)

        self.percent_label = tk.Label(self.root, text="0%")
        self.percent_label.pack(pady=5)

        self.elapsed_label = tk.Label(self.root, text="Elapsed: 0s")
        self.elapsed_label.pack(pady=5)

        self.remaining_label = tk.Label(self.root, text="Remaining: 0s")
        self.remaining_label.pack(pady=5)

        self.queue = queue.Queue()
        self.root.after(100, self.monitor_queue)

        logger.info("EncryptionApp GUI initialized.")

    def browse_path(self):
        """Browse for a file or directory."""
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def get_encryptor(self) -> FileEncryptor:
        """Get FileEncryptor instance from password."""
        password = self.password_entry.get()
        if not password:
            raise ValueError("Password is required.")
        return FileEncryptor(password)

    def start_encrypt(self):
        """Start encryption in a thread."""
        self.encrypt_button.config(state='disabled')
        self.decrypt_button.config(state='disabled')
        self.progress['value'] = 0
        self.percent_label.config(text="0%")
        self.elapsed_label.config(text="Elapsed: 0s")
        self.remaining_label.config(text="Remaining: 0s")
        threading.Thread(target=self.do_process, args=(True,), daemon=True).start()

    def start_decrypt(self):
        """Start decryption in a thread."""
        self.decrypt_button.config(state='disabled')
        self.encrypt_button.config(state='disabled')
        self.progress['value'] = 0
        self.percent_label.config(text="0%")
        self.elapsed_label.config(text="Elapsed: 0s")
        self.remaining_label.config(text="Remaining: 0s")
        threading.Thread(target=self.do_process, args=(False,), daemon=True).start()

    def do_process(self, is_encrypt: bool):
        """Perform encryption or decryption in a background thread."""
        try:
            path = self.path_entry.get()
            if not path:
                raise ValueError("Path is required.")
            encryptor = self.get_encryptor()

            # Get all files and total size
            if os.path.isfile(path):
                all_files = [path]
                total_bytes = os.path.getsize(path)
            elif os.path.isdir(path):
                all_files = []
                total_bytes = 0
                for root, _, files in os.walk(path):
                    for f in files:
                        file_p = os.path.join(root, f)
                        all_files.append(file_p)
                        total_bytes += os.path.getsize(file_p)
            else:
                raise ValueError("Invalid path.")

            if total_bytes == 0:
                self.queue.put(('done', "No files to process."))
                return

            start_time = time.time()
            processed_bytes = 0
            success_count = 0

            def byte_callback(chunk_size):
                nonlocal processed_bytes
                processed_bytes += chunk_size
                elapsed = time.time() - start_time
                rem = (elapsed / processed_bytes * (total_bytes - processed_bytes)) if processed_bytes > 0 else 0
                self.queue.put(('progress', (processed_bytes / total_bytes) * 100, elapsed, rem))

            for file_path in all_files:
                if is_encrypt:
                    if encryptor.encrypt_file(file_path, callback=byte_callback):
                        success_count += 1
                else:
                    if encryptor.decrypt_file(file_path, callback=byte_callback):
                        success_count += 1

            # Now hide or unhide files
            for file_path in all_files:
                if is_encrypt:
                    encryptor.hide_file(file_path)
                else:
                    encryptor.unhide_file(file_path)

            # Hide or unhide subdirs (excluding root)
            subdirs = []
            for root, dirs, _ in os.walk(path):
                for d in dirs:
                    subdir_p = os.path.join(root, d)
                    subdirs.append(subdir_p)
            for sd in subdirs:
                if is_encrypt:
                    encryptor.hide_file(sd)
                else:
                    encryptor.unhide_file(sd)

            action = "Encrypted" if is_encrypt else "Decrypted"
            self.queue.put(('progress', 100, time.time() - start_time, 0))
            self.queue.put(('done', f"{action} and processed {success_count} files."))
        except Exception as e:
            self.queue.put(('error', str(e)))

    def monitor_queue(self):
        """Monitor the queue for updates from the thread."""
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg[0] == 'progress':
                    self.progress['value'] = msg[1]
                    self.percent_label.config(text=f"{msg[1]:.2f}%")
                    self.elapsed_label.config(text=f"Elapsed: {msg[2]:.2f}s")
                    self.remaining_label.config(text=f"Remaining: {msg[3]:.2f}s")
                elif msg[0] == 'done':
                    self.encrypt_button.config(state='normal')
                    self.decrypt_button.config(state='normal')
                    messagebox.showinfo("Success", msg[1])
                elif msg[0] == 'error':
                    self.encrypt_button.config(state='normal')
                    self.decrypt_button.config(state='normal')
                    messagebox.showerror("Error", msg[1])
        except queue.Empty:
            pass
        self.root.after(100, self.monitor_queue)

    def run(self):
        """Run the GUI main loop."""
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = EncryptionApp()
        app.run()
    except Exception as e:
        logger.critical(f"Application startup error: {str(e)}")
        raise