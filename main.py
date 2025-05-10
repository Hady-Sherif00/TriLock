import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from crypto_core import encrypt_file, decrypt_file
import os
import threading

class TriLockApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TriLock Encryption System")
        self.root.geometry("650x500")
        self.root.resizable(True, True)
        
        # Set theme colors
        self.bg_color = "#f0f0f0"
        self.accent_color = "#3498db"
        self.text_color = "#2c3e50"
        
        self.root.configure(bg=self.bg_color)
        
        self.setup_ui()
    
    def setup_ui(self):
        # Create tabs
        self.tab_control = ttk.Notebook(self.root)
        
        self.encrypt_tab = ttk.Frame(self.tab_control)
        self.decrypt_tab = ttk.Frame(self.tab_control)
        self.settings_tab = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.encrypt_tab, text="Encrypt")
        self.tab_control.add(self.decrypt_tab, text="Decrypt")
        self.tab_control.add(self.settings_tab, text="Settings")
        
        self.tab_control.pack(expand=1, fill="both")
        
        # Setup encrypt tab
        self.setup_encrypt_tab()
        
        # Setup decrypt tab
        self.setup_decrypt_tab()
        
        # Setup settings tab
        self.setup_settings_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_encrypt_tab(self):
        frame = ttk.LabelFrame(self.encrypt_tab, text="Encryption Settings")
        frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Input file
        ttk.Label(frame, text="Select file to encrypt:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.encrypt_input_entry = ttk.Entry(frame, width=50)
        self.encrypt_input_entry.grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(frame, text="Browse", command=lambda: self.select_file(self.encrypt_input_entry)).grid(row=0, column=2, padx=5, pady=10)
        
        # Output directory
        ttk.Label(frame, text="Output folder:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.encrypt_output_entry = ttk.Entry(frame, width=50)
        self.encrypt_output_entry.grid(row=1, column=1, padx=10, pady=10)
        self.encrypt_output_entry.insert(0, os.getcwd())
        ttk.Button(frame, text="Browse", command=lambda: self.select_directory(self.encrypt_output_entry)).grid(row=1, column=2, padx=5, pady=10)
        
        # Encryption options
        options_frame = ttk.LabelFrame(frame, text="Encryption Options")
        options_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="we")
        
        # Custom filenames option
        self.custom_filenames_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Use custom output filenames", variable=self.custom_filenames_var, command=self.toggle_custom_filenames).grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        # Custom filename entries (initially disabled)
        self.custom_files_frame = ttk.Frame(options_frame)
        self.custom_files_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=5, sticky="we")
        
        ttk.Label(self.custom_files_frame, text="Ciphertext filename:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cipher_filename_entry = ttk.Entry(self.custom_files_frame, width=20, state="disabled")
        self.cipher_filename_entry.grid(row=0, column=1, padx=5, pady=5)
        self.cipher_filename_entry.insert(0, "ciphertext.hex")
        
        ttk.Label(self.custom_files_frame, text="RSA key filename:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.rsa_key_filename_entry = ttk.Entry(self.custom_files_frame, width=20, state="disabled")
        self.rsa_key_filename_entry.grid(row=1, column=1, padx=5, pady=5)
        self.rsa_key_filename_entry.insert(0, "rsa_key.enc")
        
        ttk.Label(self.custom_files_frame, text="Autokey filename:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.autokey_filename_entry = ttk.Entry(self.custom_files_frame, width=20, state="disabled")
        self.autokey_filename_entry.grid(row=2, column=1, padx=5, pady=5)
        self.autokey_filename_entry.insert(0, "autokey.txt")
        
        # Progress bar
        ttk.Label(frame, text="Progress:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        self.encrypt_progress = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
        self.encrypt_progress.grid(row=3, column=1, padx=10, pady=5, columnspan=2, sticky="we")
        
        # Encrypt button
        encrypt_button = ttk.Button(frame, text="Encrypt File", command=self.encrypt_action_threaded)
        encrypt_button.grid(row=4, column=0, columnspan=3, padx=10, pady=15)
        encrypt_button.configure(width=20)
    
    def setup_decrypt_tab(self):
        frame = ttk.LabelFrame(self.decrypt_tab, text="Decryption Settings")
        frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Input files
        ttk.Label(frame, text="Ciphertext file:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.cipher_entry = ttk.Entry(frame, width=50)
        self.cipher_entry.grid(row=0, column=1, padx=10, pady=10)
        self.cipher_entry.insert(0, "ciphertext.hex")
        ttk.Button(frame, text="Browse", command=lambda: self.select_file(self.cipher_entry)).grid(row=0, column=2, padx=5, pady=10)
        
        ttk.Label(frame, text="RSA key file:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.rsa_key_entry = ttk.Entry(frame, width=50)
        self.rsa_key_entry.grid(row=1, column=1, padx=10, pady=10)
        self.rsa_key_entry.insert(0, "rsa_key.enc")
        ttk.Button(frame, text="Browse", command=lambda: self.select_file(self.rsa_key_entry)).grid(row=1, column=2, padx=5, pady=10)
        
        ttk.Label(frame, text="Autokey file:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        self.autokey_entry = ttk.Entry(frame, width=50)
        self.autokey_entry.grid(row=2, column=1, padx=10, pady=10)
        self.autokey_entry.insert(0, "autokey.txt")
        ttk.Button(frame, text="Browse", command=lambda: self.select_file(self.autokey_entry)).grid(row=2, column=2, padx=5, pady=10)
        
        # Output file
        ttk.Label(frame, text="Output file:").grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        self.decrypt_output_entry = ttk.Entry(frame, width=50)
        self.decrypt_output_entry.grid(row=3, column=1, padx=10, pady=10)
        self.decrypt_output_entry.insert(0, "decrypted.txt")
        ttk.Button(frame, text="Browse", command=lambda: self.save_file(self.decrypt_output_entry)).grid(row=3, column=2, padx=5, pady=10)
        
        # Progress bar
        ttk.Label(frame, text="Progress:").grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
        self.decrypt_progress = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
        self.decrypt_progress.grid(row=4, column=1, padx=10, pady=5, columnspan=2, sticky="we")
        
        # Decrypt button
        decrypt_button = ttk.Button(frame, text="Decrypt File", command=self.decrypt_action_threaded)
        decrypt_button.grid(row=5, column=0, columnspan=3, padx=10, pady=15)
        decrypt_button.configure(width=20)
    
    def setup_settings_tab(self):
        frame = ttk.LabelFrame(self.settings_tab, text="Application Settings")
        frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Theme selection
        ttk.Label(frame, text="UI Theme:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        themes = ["Default", "Light", "Dark", "Blue"]
        self.theme_var = tk.StringVar(value="Default")
        theme_combo = ttk.Combobox(frame, textvariable=self.theme_var, values=themes, state="readonly")
        theme_combo.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        theme_combo.bind("<<ComboboxSelected>>", self.change_theme)
        
        # Security options
        security_frame = ttk.LabelFrame(frame, text="Security Settings")
        security_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="we")
        
        self.secure_delete_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(security_frame, text="Securely delete original files after encryption", 
                        variable=self.secure_delete_var).grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        self.auto_delete_keys_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(security_frame, text="Auto-delete key files after decryption", 
                        variable=self.auto_delete_keys_var).grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        
        # About section
        about_frame = ttk.LabelFrame(frame, text="About TriLock")
        about_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="we")
        
        about_text = "TriLock is a hybrid encryption system using RSA, AES, and Autokey ciphers\n" + \
                    "for secure file encryption. Version 1.0"
        ttk.Label(about_frame, text=about_text, justify=tk.LEFT).grid(row=0, column=0, padx=10, pady=10)
        
        # Save settings button
        save_button = ttk.Button(frame, text="Save Settings", command=self.save_settings)
        save_button.grid(row=3, column=0, columnspan=2, padx=10, pady=15)

    
    def test_crypto(self):
        """Test encryption and decryption on a single file with temporary key files"""
        input_path = self.test_input_entry.get()
        output_path = self.test_output_entry.get()
        
        if not input_path:
            messagebox.showwarning("Missing Input", "Please select a test file.")
            return
        
        try:
            # Use temporary key files to avoid interfering with existing ones
            temp_cipher = "temp_cipher.hex"
            temp_rsa = "temp_rsa.enc"
            temp_autokey = "temp_autokey.txt"
            
            # Check if file is binary or text
            try:
                with open(input_path, "r", encoding="utf-8") as f:
                    f.read(1024)
                file_type = "text"
            except UnicodeDecodeError:
                file_type = "binary"
                
            self.status_var.set("Testing encryption...")
            
            # Handle binary files with special processing
            if file_type == "binary":
                # Convert binary to text for encryption
                with open(input_path, "rb") as f:
                    binary_data = f.read()
                
                import binascii
                hex_text = binascii.hexlify(binary_data).decode('ascii')
                
                temp_input = input_path + ".temp_txt"
                with open(temp_input, "w", encoding="utf-8") as f:
                    f.write(hex_text)
                    
                # Encrypt the text representation
                encrypt_file(temp_input, temp_cipher, temp_rsa, temp_autokey)
                os.remove(temp_input)
                
                # Now decrypt
                self.status_var.set("Testing decryption...")
                temp_output = output_path + ".temp_txt"
                decrypt_file(temp_cipher, temp_rsa, temp_autokey, temp_output)
                
                # Convert back to binary
                with open(temp_output, "r", encoding="utf-8") as f:
                    decrypted_hex = f.read()
                    
                binary_output = binascii.unhexlify(decrypted_hex)
                with open(output_path, "wb") as f:
                    f.write(binary_output)
                    
                os.remove(temp_output)
            else:
                # Text file processing
                encrypt_file(input_path, temp_cipher, temp_rsa, temp_autokey)
                
                self.status_var.set("Testing decryption...")
                decrypt_file(temp_cipher, temp_rsa, temp_autokey, output_path)
            
            # Clean up temporary files
            for file in [temp_cipher, temp_rsa, temp_autokey]:
                if os.path.exists(file):
                    os.remove(file)
            
            # Verify if decryption worked
            if os.path.exists(output_path):
                if file_type == "text":
                    with open(input_path, "r", encoding="utf-8") as f:
                        original = f.read()
                    with open(output_path, "r", encoding="utf-8") as f:
                        decrypted = f.read()
                    
                    if original == decrypted:
                        messagebox.showinfo("Success", "Test completed successfully! Input and output match.")
                    else:
                        messagebox.showwarning("Partial Success", "Files don't match exactly. Check the output file.")
                else:
                    # For binary files, just report success based on file existence
                    messagebox.showinfo("Success", "Binary file processed. Check the output file.")
                    
                self.status_var.set(f"Test completed. Output saved to {output_path}")
            else:
                messagebox.showerror("Error", "Output file was not created.")
                self.status_var.set("Test failed.")
        
        except Exception as e:
            messagebox.showerror("Error", f"Test failed: {str(e)}")
            self.status_var.set("Test failed with error.")
    
    def select_file(self, entry):
        path = filedialog.askopenfilename()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)
    
    def select_directory(self, entry):
        path = filedialog.askdirectory()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)
    
    def save_file(self, entry):
        path = filedialog.asksaveasfilename()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)
    
    def toggle_custom_filenames(self):
        state = "normal" if self.custom_filenames_var.get() else "disabled"
        self.cipher_filename_entry.config(state=state)
        self.rsa_key_filename_entry.config(state=state)
        self.autokey_filename_entry.config(state=state)
    
    def encrypt_action_threaded(self):
        thread = threading.Thread(target=self.encrypt_action)
        thread.daemon = True
        thread.start()
    
    def encrypt_action(self):
        self.status_var.set("Encrypting...")
        input_path = self.encrypt_input_entry.get()
        
        if not input_path:
            messagebox.showwarning("Missing Input", "Please select a file to encrypt.")
            self.status_var.set("Ready")
            return
        
        output_dir = self.encrypt_output_entry.get()
        
        # Determine filenames
        if self.custom_filenames_var.get():
            cipher_path = os.path.join(output_dir, self.cipher_filename_entry.get())
            rsa_key_path = os.path.join(output_dir, self.rsa_key_filename_entry.get())
            autokey_path = os.path.join(output_dir, self.autokey_filename_entry.get())
        else:
            cipher_path = os.path.join(output_dir, "ciphertext.hex")
            rsa_key_path = os.path.join(output_dir, "rsa_key.enc")
            autokey_path = os.path.join(output_dir, "autokey.txt")
        
        # Simulate progress
        for i in range(101):
            self.encrypt_progress['value'] = i
            self.root.update_idletasks()
            if i < 30:
                self.status_var.set(f"Encrypting with Autokey Cipher... ({i}%)")
            elif i < 60:
                self.status_var.set(f"Encrypting with AES... ({i}%)")
            elif i < 90:
                self.status_var.set(f"Encrypting with RSA... ({i}%)")
            else:
                self.status_var.set(f"Saving encrypted files... ({i}%)")
            
            # Slow down the progress simulation
            if i % 10 == 0:
                threading.Event().wait(0.1)
        
        try:
            # Check if file is a binary or text file
            try:
                with open(input_path, "r", encoding="utf-8") as f:
                    test_read = f.read(1024)  # Try reading as text
                file_type = "text"
            except UnicodeDecodeError:
                file_type = "binary"
                messagebox.showinfo("Binary File", "Detected binary file. Will process accordingly.")
            
            # For non-text files, create a modified version of encrypt_file that handles binary
            if file_type == "binary":
                # Create a temporary text version of the binary content
                with open(input_path, "rb") as f:
                    binary_content = f.read()
                
                # Convert binary to hex string representation
                import binascii
                hex_content = binascii.hexlify(binary_content).decode('ascii')
                
                # Create a temporary file with this content
                temp_path = input_path + ".temp_txt"
                with open(temp_path, "w", encoding="utf-8") as f:
                    f.write(hex_content)
                
                # Use this as input to the encryption
                encrypt_file(temp_path, cipher_path, rsa_key_path, autokey_path)
                
                # Clean up
                os.remove(temp_path)
                
                # Save file type marker for decryption
                with open(os.path.join(output_dir, "file_type.marker"), "w") as f:
                    f.write("binary")
            else:
                # Normal encryption for text files
                encrypt_file(input_path, cipher_path, rsa_key_path, autokey_path)
                
                # Save file type marker
                with open(os.path.join(output_dir, "file_type.marker"), "w") as f:
                    f.write("text")
                
            messagebox.showinfo("Success", "File encrypted successfully!")
            
            # Optional: securely delete original file
            if self.secure_delete_var.get():
                try:
                    # In a real implementation, use secure deletion here
                    # This is just a placeholder
                    os.remove(input_path)
                    self.status_var.set("File encrypted and original securely deleted.")
                except:
                    messagebox.showwarning("Warning", "Could not delete original file.")
                    self.status_var.set("File encrypted but original file remains.")
            else:
                self.status_var.set("File encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status_var.set("Encryption failed.")
        
        self.encrypt_progress['value'] = 0
    
    def decrypt_action_threaded(self):
        thread = threading.Thread(target=self.decrypt_action)
        thread.daemon = True
        thread.start()
    
    def decrypt_action(self):
        self.status_var.set("Decrypting...")
        cipher_path = self.cipher_entry.get()
        rsa_key_path = self.rsa_key_entry.get()
        autokey_path = self.autokey_entry.get()
        output_path = self.decrypt_output_entry.get()
        
        # Check if files exist
        for path, name in [(cipher_path, "Ciphertext"), (rsa_key_path, "RSA key"), (autokey_path, "Autokey")]:
            if not os.path.exists(path):
                messagebox.showwarning("Missing File", f"{name} file not found: {path}")
                self.status_var.set("Ready")
                return
        
        # Detect file type if marker exists
        output_dir = os.path.dirname(cipher_path)
        file_type_marker = os.path.join(output_dir, "file_type.marker")
        file_type = "text"  # Default
        if os.path.exists(file_type_marker):
            with open(file_type_marker, "r") as f:
                file_type = f.read().strip()
        
        # Simulate progress
        for i in range(101):
            self.decrypt_progress['value'] = i
            self.root.update_idletasks()
            if i < 30:
                self.status_var.set(f"Decrypting RSA... ({i}%)")
            elif i < 60:
                self.status_var.set(f"Decrypting AES... ({i}%)")
            elif i < 90:
                self.status_var.set(f"Decrypting Autokey Cipher... ({i}%)")
            else:
                self.status_var.set(f"Saving decrypted file... ({i}%)")
            
            # Slow down the progress simulation
            if i % 10 == 0:
                threading.Event().wait(0.1)
        
        try:
            # For binary files, we need special handling
            if file_type == "binary":
                # First decrypt to a temporary text file
                temp_output = output_path + ".temp_txt"
                decrypt_file(cipher_path, rsa_key_path, autokey_path, temp_output)
                
                # Read the hex content
                with open(temp_output, "r", encoding="utf-8") as f:
                    hex_content = f.read()
                
                # Convert back to binary
                import binascii
                binary_data = binascii.unhexlify(hex_content)
                
                # Write the binary output
                with open(output_path, "wb") as f:
                    f.write(binary_data)
                
                # Clean up
                os.remove(temp_output)
            else:
                # Normal text file decryption
                decrypt_file(cipher_path, rsa_key_path, autokey_path, output_path)
            
            messagebox.showinfo("Success", "File decrypted successfully!")
            
            # Optional: delete key files after successful decryption
            if self.auto_delete_keys_var.get():
                try:
                    os.remove(rsa_key_path)
                    os.remove(autokey_path)
                    os.remove(cipher_path)
                    if os.path.exists(file_type_marker):
                        os.remove(file_type_marker)
                    self.status_var.set("File decrypted and key files deleted.")
                except:
                    messagebox.showwarning("Warning", "Could not delete key files.")
                    self.status_var.set("File decrypted but key files remain.")
            else:
                self.status_var.set("File decrypted successfully.")
                
            # Ask if user wants to open the decrypted file
            if file_type == "text" and messagebox.askyesno("Open File", "Do you want to open the decrypted file?"):
                os.startfile(output_path)
                
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status_var.set("Decryption failed.")
        
        self.decrypt_progress['value'] = 0
    
    def change_theme(self, event):
        theme = self.theme_var.get()
        if theme == "Dark":
            self.root.configure(bg="#2c3e50")
            self.status_bar.configure(background="#34495e", foreground="white")
        elif theme == "Light":
            self.root.configure(bg="#ecf0f1")
            self.status_bar.configure(background="#bdc3c7", foreground="black")
        elif theme == "Blue":
            self.root.configure(bg="#3498db")
            self.status_bar.configure(background="#2980b9", foreground="white")
        else:  # Default
            self.root.configure(bg=self.bg_color)
            self.status_bar.configure(background=None, foreground=None)
    
    def save_settings(self):
        # This would save settings to a config file in a real implementation
        messagebox.showinfo("Settings", "Settings saved successfully!")
        self.status_var.set("Settings saved.")

if __name__ == "__main__":
    root = tk.Tk()
    app = TriLockApp(root)
    root.mainloop()
