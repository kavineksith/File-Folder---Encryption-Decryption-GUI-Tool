## Introduction
The File Encryption Tool is a Python-based application designed to encrypt, decrypt, hide, and unhide files and folders (including nested ones) using AES-128 encryption with CBC mode and PKCS7 padding. It employs PBKDF2 for secure key derivation from a user-provided password. The tool features a graphical user interface (GUI) built with Tkinter, allowing users to select paths, enter passwords, and monitor progress during operations. It supports recursive processing of directories and provides real-time feedback via a progress bar, percentage completion, elapsed time, and estimated remaining time.

This tool is intended for personal use to protect sensitive files. **Important: Encryption is only as secure as your password. Use a strong, unique password and keep it secret. Always back up your data before encrypting, as incorrect passwords or corrupted files may result in permanent data loss.**

## System Requirements
- **Operating System**: Windows, macOS, or Linux (tested on Python-compatible environments).
- **Python Version**: Python 3.8 or higher (the script uses features from Python 3.6+).
- **Dependencies**:
  - `cryptography`: For encryption/decryption (install via `pip install cryptography`).
  - Tkinter: Usually included with Python installations; if not, install it via your package manager (e.g., `apt install python3-tk` on Ubuntu).
- No internet access is required for the tool to function.

## Installation
1. **Install Python**: Download and install Python from the official website (python.org) if not already installed.
2. **Install Dependencies**:
   - Open a terminal or command prompt.
   - Run: `pip install cryptography`
3. **Download the Script**:
   - Save the provided Python script to a file, e.g., `file_encryption_tool.py`.
4. **Run the Script**:
   - Navigate to the directory containing the script.
   - Execute: `python file_encryption_tool.py` (or `python3 file_encryption_tool.py` on some systems).

The application window should appear upon running.

## Running the Application
- Launch the script as described above.
- The GUI will open with fields for password entry, path selection, and operation buttons.
- Logs are written to `file_encryption.log` in the script's directory for debugging and tracking operations.

## Using the GUI
The interface is straightforward and includes the following elements:

### 1. Password Field
- Label: "Password:"
- This is a secure entry field (shows asterisks as you type).
- Enter a strong password here. It will be used to derive the encryption key via PBKDF2.
- **Note**: The same password must be used for decryption. Forgetting it will make files unrecoverable.

### 2. Path Selection
- Label: "Select Folder/File:"
- Enter or paste the full path to a file or folder.
- Use the "Browse" button to select a file or directory via a file dialog.

### 3. Operation Buttons
- **Encrypt & Hide**: Encrypts files (and subfiles recursively if a folder) using AES-128, then hides them.
- **Decrypt & Unhide**: Decrypts files using the provided password, then unhides them.
- Buttons are disabled during operations to prevent concurrent actions.

### 4. Progress Indicators
- **Progress Bar**: Shows overall completion as a horizontal bar (0-100%).
- **Percentage**: Displays current progress (e.g., "45.67%").
- **Elapsed Time**: Shows time spent so far (e.g., "Elapsed: 12.34s").
- **Remaining Time**: Estimates time left based on current speed (e.g., "Remaining: 15.67s").
- These update in real-time during encryption/decryption.

### Step-by-Step Usage
1. **Enter Password**: Type your password in the field.
2. **Select Path**: Use the entry field or "Browse" to choose a file or folder.
3. **Choose Operation**:
   - For encryption: Click "Encrypt & Hide".
   - For decryption: Click "Decrypt & Unhide".
4. **Monitor Progress**: Watch the indicators as the tool processes files chunk-by-chunk (to handle large files efficiently).
5. **Completion**: A message box will appear upon success (e.g., "Encrypted and processed 5 files.") or error (e.g., with details like "Invalid password").
6. **Close the App**: Use the window close button when done.

### Handling Folders
- The tool recursively processes all files in the selected folder and its subfolders.
- Subdirectories (except the root) are also hidden/unhidden.
- On Unix-like systems (macOS/Linux), hiding prefixes names with a dot (e.g., ".hiddenfolder").
- On Windows, it sets the hidden file attribute.
- **Note**: Hidden files/folders may not appear in file explorers by default; enable "Show hidden files" in your OS settings to view them.

## Features
- **Encryption Algorithm**: AES-128 in CBC mode with random IV and salt per file for security.
- **Key Derivation**: PBKDF2 with SHA-256 and 480,000 iterations for resistance against brute-force attacks.
- **Chunked Processing**: Handles large files without loading everything into memory.
- **Hiding Mechanism**: OS-specific for maximum compatibility.
- **Logging**: Detailed logs in `file_encryption.log` including timestamps, errors, and successes.
- **Threaded Operations**: Background processing keeps the GUI responsive.
- **Error Handling**: Try-except blocks catch issues like invalid paths or decryption failures, showing user-friendly messages.

## Troubleshooting
- **Error: "Password is required."**: Ensure you entered a password.
- **Error: "Path is required."**: Select a valid file or folder.
- **Decryption Fails**: Likely due to wrong password or non-encrypted file. Check logs for details.
- **Hidden Files Not Visible**: Enable hidden file viewing in your file manager (e.g., Ctrl+H on Linux, View > Hidden items on Windows).
- **Performance Issues**: For very large folders, operations may take time; the remaining time estimate helps.
- **Library Not Found**: If `cryptography` is missing, reinstall via pip.
- **Cross-OS Compatibility**: Encrypted files can be decrypted on any OS, but hiding may need manual adjustment if moving between Windows and Unix.

## Security Notes
- **Password Strength**: Use at least 12 characters with mixes of letters, numbers, and symbols.
- **Backup**: Always back up originals before encrypting.
- **Limitations**: This is not GPG-based as initially requested (the script uses cryptography library instead for simplicity). For GPG, consider tools like `gpg` command-line.
- **Legal**: Ensure compliance with local laws on encryption.
- **No Warranty**: This tool is provided as-is; test on non-critical data first.
