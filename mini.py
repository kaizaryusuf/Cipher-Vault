import sys
from tkinter import *
from tkinter import ttk, filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import base64
from Crypto.Cipher import AES
import os
import qrcode
from PIL import Image, ImageTk

# Predefined secret keys for each encryption technique
SECRET_KEYS = {
    "Caesar Cipher": "1234",
    "Base64": "5678",
    "AES": "mysecretkey12345"
}

# Function for Caesar Cipher encryption
def caesar_encrypt(message, shift):
    encrypted_message = ''.join(
        chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else
        chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char
        for char in message
    )
    return encrypted_message

# Function for Caesar Cipher decryption
def caesar_decrypt(message, shift):
    return caesar_encrypt(message, -shift)

# Function for AES encryption
def aes_encrypt(key, message):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

# Function for AES decryption
def aes_decrypt(key, encrypted_message):
    encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
    nonce, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Function to validate the secret key
def validate_key(technique, entered_key):
    correct_key = SECRET_KEYS.get(technique)
    if entered_key == correct_key:
        return True
    return False

# Typing effect function for the output field
def show_typing_effect(widget, text, index=0):
    if index < len(text):
        widget.insert('end', text[index])
        widget.update()
        screen.after(50, show_typing_effect, widget, text, index + 1)

# Function to handle encryption based on selected technique
def encrypt():
    technique = encryption_technique.get()
    entered_key = code.get()
    message = text1.get(1.0, END).strip()

    if not technique:  # Check if the encryption technique is selected
        messagebox.showerror("Error", "Please select an encryption technique.")
        return

    if not message:
        messagebox.showwarning("Encryption", "Please enter a message to encrypt.")
        return

    if not validate_key(technique, entered_key):
        messagebox.showerror("Encryption", "Incorrect secret key.")
        return

    try:
        text2.delete(1.0, END)  # Clear the output field
        if technique == "Base64":
            encoded_message = base64.b64encode(message.encode("ascii")).decode("ascii")
            show_animation()
            show_typing_effect(text2, encoded_message)
        elif technique == "Caesar Cipher":
            shift = int(SECRET_KEYS["Caesar Cipher"])  # Use the predefined key for Caesar Cipher
            encrypted_message = caesar_encrypt(message, shift)
            show_animation()
            show_typing_effect(text2, encrypted_message)
        elif technique == "AES":
            encrypted_message = aes_encrypt(SECRET_KEYS["AES"], message)
            show_animation()
            show_typing_effect(text2, encrypted_message)
        else:
            messagebox.showerror("Encryption", "Please select a valid encryption technique.")
    except Exception as e:
        messagebox.showerror("Encryption", f"An error occurred: {e}")

# Function to handle decryption based on selected technique
def decrypt():
    technique = encryption_technique.get()
    entered_key = code.get()
    message = text1.get(1.0, END).strip()

    if not technique:  # Check if the encryption technique is selected
        messagebox.showerror("Error", "Please select an encryption technique.")
        return

    if not message:
        messagebox.showwarning("Decryption", "Please enter a message to decrypt.")
        return

    if not validate_key(technique, entered_key):
        messagebox.showerror("Decryption", "Incorrect secret key.")
        return

    try:
        text2.delete(1.0, END)  # Clear the output field
        if technique == "Base64":
            decoded_message = base64.b64decode(message.encode("ascii")).decode("ascii")
            show_animation()
            show_typing_effect(text2, decoded_message)
        elif technique == "Caesar Cipher":
            shift = int(SECRET_KEYS["Caesar Cipher"])  # Use the predefined key for Caesar Cipher
            decrypted_message = caesar_decrypt(message, shift)
            show_animation()
            show_typing_effect(text2, decrypted_message)
        elif technique == "AES":
            decrypted_message = aes_decrypt(SECRET_KEYS["AES"], message)
            show_animation()
            show_typing_effect(text2, decrypted_message)
        else:
            messagebox.showerror("Decryption", "Please select a valid decryption technique.")
    except Exception as e:
        messagebox.showerror("Decryption", f"An error occurred: {e}")

# Function to reset all fields
def reset():
    code.set("")
    text1.delete(1.0, END)
    text2.delete(1.0, END)
    encryption_technique.set("")

# Function to save the output to a file
def save_to_file():
    output_message = text2.get(1.0, END).strip()
    if not output_message:
        messagebox.showwarning("Save to File", "No output to save.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "w") as file:
                file.write(output_message)
            messagebox.showinfo("Save to File", "File saved successfully!")
        except Exception as e:
            messagebox.showerror("Save to File", f"An error occurred: {e}")

# Function to load a message from a file
def load_from_file():
    file_path = filedialog.askopenfilename(
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "r") as file:
                content = file.read()
            text1.delete(1.0, END)
            text1.insert(END, content)
        except Exception as e:
            messagebox.showerror("Load from File", f"An error occurred: {e}")

# Function to create simple animation
def show_animation():
    progress_bar.start(10)
    screen.after(1000, progress_bar.stop)

# Function to generate QR code from encrypted text
def generate_qr_code():
    encrypted_text = text2.get(1.0, END).strip()
    if not encrypted_text:
        messagebox.showwarning("QR Code", "Please encrypt a message first.")
        return

    try:
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # Higher error correction
            box_size=10,
            border=4,
        )
        qr.add_data(encrypted_text)  # Directly use the encrypted text
        qr.make(fit=True)

        # Create QR code image in black and white
        qr_image = qr.make_image(fill_color="black", back_color="white")

        # Save QR code
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All Files", "*.*")]
        )
        if file_path:
            qr_image.save(file_path)
            messagebox.showinfo("QR Code", "QR code saved successfully!")
            
            # Show QR code in a new window
            show_qr_code(qr_image, encrypted_text)
    except Exception as e:
        messagebox.showerror("QR Code", f"An error occurred: {e}")

# Function to display QR code in a new window
def show_qr_code(qr_image, text):
    qr_window = tb.Toplevel()
    qr_window.title("QR Code Preview")
    qr_window.geometry("400x450")

    # Convert PIL image to PhotoImage
    photo = ImageTk.PhotoImage(qr_image)
    
    # Create label with QR code image
    qr_label = tb.Label(qr_window, image=photo)
    qr_label.image = photo  # Keep a reference
    qr_label.pack(pady=20)
    
    # Add encrypted text display
    text_label = tb.Label(
        qr_window,
        text="Encrypted text:",
        font=("calibri", 12)
    )
    text_label.pack()
    
    text_display = tb.Label(
        qr_window,
        text=text,
        font=("calibri", 10),
        wraplength=350,
        bootstyle="info"
    )
    text_display.pack(pady=10)

# Main Tkinter screen
def main_screen(initial_message=''):
    global screen, code, text1, text2, encryption_technique, progress_bar

    screen = tb.Window(themename="solar")
    screen.geometry("600x700")
    screen.title("CipherVault")

    # Title Label
    tb.Label(
        screen,
        text="CipherVault",
        bootstyle="primary",
        font=("calibri", 20, "bold"),
        anchor="center",
        padding=(10, 10)
    ).pack(fill=X, pady=10)

    # Encryption Technique Selection
    tb.Label(screen, text="Select encryption technique:", font=("calibri", 13)).pack(pady=10)
    encryption_technique = StringVar()
    tb.Combobox(
        screen,
        textvariable=encryption_technique,
        values=["Base64", "Caesar Cipher", "AES"],
        state="readonly",
        bootstyle="info"
    ).pack(pady=5)

    # Message Input
    tb.Label(screen, text="Enter the message:", font=("calibri", 13)).pack(pady=10)
    text1 = tb.Text(screen, font=("calibri", 12), height=5, width=50, wrap=WORD)
    text1.pack(pady=5)
    
    # Pre-populate the message if provided
    if initial_message:
        text1.insert('1.0', initial_message)

    # Secret Key Input (Masked)
    tb.Label(screen, text="Enter secret key:", font=("calibri", 13)).pack(pady=10)
    code = StringVar()
    tb.Entry(screen, textvariable=code, show="*", font=("calibri", 12)).pack(pady=5)

    # Buttons
    button_frame = tb.Frame(screen)
    button_frame.pack(pady=15)
    tb.Button(button_frame, text="Encrypt", bootstyle="danger-outline", command=encrypt).grid(row=0, column=0, padx=10)
    tb.Button(button_frame, text="Decrypt", bootstyle="success-outline", command=decrypt).grid(row=0, column=1, padx=10)
    tb.Button(button_frame, text="Reset", bootstyle="info-outline", command=reset).grid(row=0, column=2, padx=10)

    # Output Section
    tb.Label(screen, text="Output:", font=("calibri", 13)).pack(pady=10)
    text2 = tb.Text(screen, font=("calibri", 12), height=5, width=50, wrap=WORD, state='normal')
    text2.pack(pady=5)

    # File Load/Save Buttons
    file_frame = tb.Frame(screen)
    file_frame.pack(pady=15)
    tb.Button(file_frame, text="Load from File", bootstyle="warning-outline", command=load_from_file).grid(row=0, column=0, padx=10)
    tb.Button(file_frame, text="Save to File", bootstyle="secondary-outline", command=save_to_file).grid(row=0, column=1, padx=10)
    tb.Button(file_frame, text="Generate QR Code", bootstyle="info-outline", command=generate_qr_code).grid(row=0, column=2, padx=10)

    # Progress Bar for Animation
    progress_bar = tb.Progressbar(screen, mode="indeterminate", bootstyle="info-striped")
    progress_bar.pack(fill=X, pady=20, padx=50)

    screen.mainloop()

if __name__ == "__main__":
    # Get message from command line arguments if provided
    initial_message = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ''
    main_screen(initial_message)