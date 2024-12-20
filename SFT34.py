import socket
import tkinter as tk
from tkinter import filedialog, messagebox
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Derive a key from a password
def derive_key_from_password(password: str, salt: bytes = b'some_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Encrypt file content
def encrypt_file(file_path, password):
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original_data = file.read()
    encrypted_data = fernet.encrypt(original_data)
    return encrypted_data

# Decrypt file content
def decrypt_file(encrypted_data, password):
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

# Send encrypted file
def send_file(server_ip, port, file_path, password):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, port))

        # Encrypt file content
        encrypted_data = encrypt_file(file_path, password)

        # Send file name and encrypted data length
        file_name = os.path.basename(file_path)
        file_name_length = len(file_name).to_bytes(4, 'big')
        encrypted_data_length = len(encrypted_data).to_bytes(8, 'big')  # Use 8 bytes for larger sizes
        client_socket.sendall(file_name_length + file_name.encode() + encrypted_data_length + encrypted_data)

        messagebox.showinfo("Success", "File sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send file: {e}")
    finally:
        client_socket.close()

# Receive file and decrypt
def receive_file(port, password):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(1)
    print(f"Listening on port {port}...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr} established!")

    try:
        # Receive file name and content
        file_name_length = int.from_bytes(conn.recv(4), 'big')
        file_name = conn.recv(file_name_length).decode()
        encrypted_data_length = int.from_bytes(conn.recv(8), 'big')

        # Read encrypted data in chunks
        encrypted_data = b""
        while len(encrypted_data) < encrypted_data_length:
            packet = conn.recv(4096)  # Adjust the buffer size if needed
            if not packet:
                break
            encrypted_data += packet

        # Check if the received data matches the expected length
        if len(encrypted_data) != encrypted_data_length:
            messagebox.showerror("Error", "Received data is incomplete.")
            return

        # Decrypt data
        decrypted_data = decrypt_file(encrypted_data, password)

        # Prompt to save the received file
        output_file = filedialog.asksaveasfilename(initialfile=file_name, title="Save Received File As")
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            messagebox.showinfo("Success", f"File received and saved as {output_file}!")
        else:
            messagebox.showwarning("Cancelled", "File save cancelled.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to receive or decrypt file: {e}")

    finally:
        conn.close()
        server_socket.close()

# Tkinter UI for selecting files and sending/receiving
def select_file():
    file_path = filedialog.askopenfilename(title="Select File to Send")
    if file_path:
        file_entry.config(state="normal")
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)
        file_entry.config(state="readonly")

def start_transfer():
    server_ip = ip_entry.get()
    file_path = file_entry.get()
    password = password_entry.get()
    if not server_ip or not file_path or not password:
        messagebox.showwarning("Missing Information", "Please enter the IP address, file path, and password.")
        return
    send_file(server_ip, 5001, file_path, password)

def start_server():
    password = receiver_password_entry.get()
    if not password:
        messagebox.showwarning("Missing Information", "Please enter the decryption password.")
        return
    receive_file(5001, password)

def switch_to_send_mode():
    main_frame.pack_forget()
    sender_frame.pack(pady=20)

def switch_to_receive_mode():
    main_frame.pack_forget()
    receiver_frame.pack(pady=20)

def go_back_to_main():
    sender_frame.pack_forget()
    receiver_frame.pack_forget()
    main_frame.pack(pady=20)

# GUI setup
root = tk.Tk()
root.title("Secure File Transfer with Encryption")
root.geometry("500x400")
root.configure(bg="#4682B4")

# Main frame with Send/Receive options
main_frame = tk.Frame(root, bg="#4682B4")
tk.Label(main_frame, text="Secure File Transfer", font=("Arial", 18), bg="#4682B4", fg="white").pack(pady=10)
tk.Button(main_frame, text="Send File", command=switch_to_send_mode, bg="#5F9EA0", fg="white", font=("Arial", 12)).pack(pady=5)
tk.Button(main_frame, text="Receive File", command=switch_to_receive_mode, bg="#5F9EA0", fg="white", font=("Arial", 12)).pack(pady=5)
main_frame.pack(pady=20)

# Sender Frame
sender_frame = tk.Frame(root, bg="#4682B4")
tk.Label(sender_frame, text="Receiver IP Address:", bg="#4682B4", fg="white", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(sender_frame, font=("Arial", 12), width=20)
ip_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Label(sender_frame, text="File to Send:", bg="#4682B4", fg="white", font=("Arial", 12)).grid(row=1, column=0, padx=5, pady=5)
file_entry = tk.Entry(sender_frame, font=("Arial", 12), width=20, state="readonly")
file_entry.grid(row=1, column=1, padx=5, pady=5)
tk.Button(sender_frame, text="Browse", command=select_file, bg="#5F9EA0", fg="white", font=("Arial", 10)).grid(row=1, column=2, padx=5)
tk.Label(sender_frame, text="Encryption Password:", bg="#4682B4", fg="white", font=("Arial", 12)).grid(row=2, column=0, padx=5, pady=5)
password_entry = tk.Entry(sender_frame, font=("Arial", 12), width=20, show="*")
password_entry.grid(row=2, column=1, padx=5, pady=5)
tk.Button(sender_frame, text="Send File", command=start_transfer, bg="#4CAF50", fg="white", font=("Arial", 14)).grid(row=3, columnspan=3, pady=20)
tk.Button(sender_frame, text="Back", command=go_back_to_main, bg="#D9534F", fg="white", font=("Arial", 12)).grid(row=4, columnspan=3, pady=10)

# Receiver Frame
receiver_frame = tk.Frame(root, bg="#2E8B57")
tk.Label(receiver_frame, text="Waiting for file on port 5001...", bg="#2E8B57", fg="white", font=("Arial", 12)).pack(pady=10)
tk.Label(receiver_frame, text="Decryption Password:", bg="#2E8B57", fg="white", font=("Arial", 12)).pack(pady=5)
receiver_password_entry = tk.Entry(receiver_frame, font=("Arial", 12), width=20, show="*")
receiver_password_entry.pack(pady=5)
tk.Button(receiver_frame, text="Start Receiving", command=start_server, bg="#4CAF50", fg="white", font=("Arial", 14)).pack(pady=20)
tk.Button(receiver_frame, text="Back", command=go_back_to_main, bg="#D9534F", fg="white", font=("Arial", 12)).pack(pady=10)

root.mainloop()
