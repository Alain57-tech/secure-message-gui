import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.fernet import Fernet, InvalidToken
import os

current_key = None  # Will hold the loaded key

def generate_key_file():
    key = Fernet.generate_key()
    filepath = filedialog.asksaveasfilename(
        title="Save New Key File",
        defaultextension=".key",
        filetypes=[("Key Files", "*.key")]
    )
    if filepath:
        try:
            with open(filepath, "wb") as f:
                f.write(key)
            messagebox.showinfo("Key Saved", f"New key saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save key:\n{e}")

def load_key_file():
    global current_key
    filepath = filedialog.askopenfilename(
        title="Load Key File",
        filetypes=[("Key Files", "*.key")]
    )
    if filepath and os.path.isfile(filepath):
        try:
            with open(filepath, "rb") as f:
                current_key = f.read()
            key_label.config(text=f"Loaded key: {os.path.basename(filepath)}", foreground="green")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load key:\n{e}")
            current_key = None
            key_label.config(text="No key loaded", foreground="red")

def encrypt_message():
    if current_key is None:
        messagebox.showerror("Error", "No key loaded.")
        return

    message = input_text.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Message is empty.")
        return

    try:
        fernet = Fernet(current_key)
        encrypted = fernet.encrypt(message.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted.decode())
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_message():
    if current_key is None:
        messagebox.showerror("Error", "No key loaded.")
        return

    encrypted_message = input_text.get("1.0", tk.END).strip()
    if not encrypted_message:
        messagebox.showerror("Error", "Encrypted message is empty.")
        return

    try:
        fernet = Fernet(current_key)
        decrypted = fernet.decrypt(encrypted_message.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted.decode())
    except InvalidToken:
        messagebox.showerror("Decryption Error", "Invalid key or message.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("🔐 AL secured")
root.geometry("650x600")
root.resizable(False, False)

style = ttk.Style()
style.configure("TLabel", font=("Segoe UI", 11))
style.configure("TButton", font=("Segoe UI", 11), padding=6)
style.configure("TEntry", font=("Segoe UI", 11))

main_frame = ttk.Frame(root, padding="20")
main_frame.pack(fill="both", expand=True)

# Key Management
ttk.Label(main_frame, text="🗝️ Key File:").pack(anchor="w")

key_controls = ttk.Frame(main_frame)
key_controls.pack(fill="x", pady=5)

ttk.Button(key_controls, text="📂 Load Key File", command=load_key_file).pack(side="left", padx=5)
ttk.Button(key_controls, text="🧾 Generate & Save New Key", command=generate_key_file).pack(side="left", padx=5)

key_label = ttk.Label(main_frame, text="No key loaded", foreground="red")
key_label.pack(anchor="w", pady=(5, 10))

# Input
ttk.Label(main_frame, text="📝 Input Message / Encrypted Text:").pack(anchor="w")
input_text = tk.Text(main_frame, height=7, font=("Consolas", 10), wrap=tk.WORD)
input_text.pack(fill="x", pady=5)

# Buttons
button_frame = ttk.Frame(main_frame)
button_frame.pack(pady=10)

ttk.Button(button_frame, text="🔒 Encrypt", command=encrypt_message).pack(side="left", padx=10)
ttk.Button(button_frame, text="🔓 Decrypt", command=decrypt_message).pack(side="left", padx=10)

# Output
ttk.Label(main_frame, text="📤 Output:").pack(anchor="w", pady=(10, 0))
output_text = tk.Text(main_frame, height=7, font=("Consolas", 10), wrap=tk.WORD, bg="#f8f8f8")
output_text.pack(fill="x", pady=5)

# Start GUI
root.mainloop()