import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_core import encrypt_file, decrypt_file

def select_file(entry):
    path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, path)

def encrypt_action():
    input_path = entry_input.get()
    if not input_path:
        messagebox.showwarning("Missing Input", "Please select a file to encrypt.")
        return
    encrypt_file(input_path, "ciphertext.hex", "rsa_key.enc", "autokey.txt")
    messagebox.showinfo("Done", "File encrypted successfully!")

def decrypt_action():
    decrypt_file("ciphertext.hex", "rsa_key.enc", "autokey.txt", "decrypted.txt")
    messagebox.showinfo("Done", "File decrypted successfully!")

root = tk.Tk()
root.title("Hybrid File Encryptor")

tk.Label(root, text="Select file to encrypt:").grid(row=0, column=0, padx=10, pady=10)
entry_input = tk.Entry(root, width=50)
entry_input.grid(row=0, column=1, padx=10)
tk.Button(root, text="Browse", command=lambda: select_file(entry_input)).grid(row=0, column=2)

tk.Button(root, text="Encrypt", width=20, command=encrypt_action).grid(row=1, column=1, pady=10)
tk.Button(root, text="Decrypt", width=20, command=decrypt_action).grid(row=2, column=1, pady=10)

root.mainloop()
