from typing import Text
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import PhotoImage
from cryptography.fernet import InvalidToken
from PIL import Image, ImageTk

salt = b'K\x8d\xb9\x86\xf7\x11\\\x14\xe8\x84\x16l\x8d+X\xe3'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)

def keygenerate(password):
    return base64.urlsafe_b64encode(kdf.derive(password))

def hashpass(password):
    return hashlib.sha512(password.encode()).hexdigest()

def secure_del(file):
    try:
        delfile = open(file, 'wb')
        delfile.write(os.urandom(delfile.tell()))
        delfile.close()
        os.unlink(file)
    except Exception as err:
        print(err)

def encrypt(key, path):
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        filedata = file.read()
    encrypted = fernet.encrypt(filedata)
    output_file = path + '.protected'
    with open(output_file, 'wb') as efile:
        efile.write(encrypted)

def decrypt(key, path):
    fernet = Fernet(key)
    with open(path, 'rb') as file:
        filedata = file.read()
    decrypted = fernet.decrypt(filedata)
    output_file = path.replace('.protected', '')
    with open(output_file, 'wb') as efile:
        efile.write(decrypted)

def file_handler(file_path, key):
    if os.path.exists(file_path) and not file_path.endswith('.protected'):
        encrypt(key, file_path)
    elif os.path.exists(file_path) and file_path.endswith('.protected'):
        decrypt(key, file_path)
    else:
        messagebox.showerror("Error", "File does not exist.")

def get_password():
    password = password_entry.get()
    hashedpass = hashpass(password)
    key = keygenerate(password.encode())
    return key

def select_file():
    file_path = filedialog.askopenfilename()
    file_path_var.set(file_path)
    show_password_input()

def perform_operation():
    key = get_password()
    file_path = file_path_var.get()
    
    try:
        if operation_var.get() == 'Encrypt':
            file_handler(file_path, key)
            if delete_var.get():
                secure_del(file_path)
        elif operation_var.get() == 'Decrypt':
            file_handler(file_path, key)
            if delete_var.get():
                secure_del(file_path + '.protected')
    except InvalidToken:
        messagebox.showerror("Error", "Invalid password or file may have been tampered with.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        execute_button.config(state='disabled')

def show_password_input():
    password_label.grid(row=2, column=0, sticky="e", padx=10, pady=10)
    password_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=10)
    execute_button.grid(row=5, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

# Get the directory where this script is located
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores paths in sys._MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# Construct paths to assets
icon_path = resource_path('assets/logo.png')
image_path = resource_path('assets/ciphero.png')

# GUI setup
root = tk.Tk()
root.title("Ciphero")

root.geometry("320x520")
root.resizable(False, False)

# Set window icon
try:
    icon = PhotoImage(file=icon_path)
    root.iconphoto(False, icon)
except Exception as e:
    print(f"Failed to set icon: {e}")

# Load image
try:
    img = PhotoImage(file=image_path)
    image_label = tk.Label(root, image=img)
    image_label.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
except Exception as e:
    print(f"Failed to load image: {e}")

# GUI elements
tk.Button(root, text="Select File", command=select_file).grid(row=1, column=0, sticky="e", padx=10, pady=10)
file_path_var = tk.StringVar()
file_path_entry = tk.Entry(root, textvariable=file_path_var, width=30)
file_path_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=10)

password_label = tk.Label(root, text="Password:")
password_entry = tk.Entry(root, show="*", width=30)

operation_var = tk.StringVar(value='Encrypt')
tk.Radiobutton(root, text="Encrypt", variable=operation_var, value='Encrypt').grid(row=3, column=0, sticky="e", padx=10, pady=10)
tk.Radiobutton(root, text="Decrypt", variable=operation_var, value='Decrypt').grid(row=3, column=1, sticky="w", padx=10, pady=10)

delete_var = tk.BooleanVar()
tk.Checkbutton(root, text="Delete original file after operation", variable=delete_var).grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

execute_button = tk.Button(root, text="Execute", command=perform_operation)

root.mainloop()
