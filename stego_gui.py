import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
import requests
import json
import threading
# from stego_core import encode_image, decode_image, generate_key, encrypt_message, decrypt_message

try:
    from stego_core import encode_image, decode_image, generate_key, encrypt_message, decrypt_message
except ImportError:
    print("Warning: 'stego_core.py' not found. Using mock functions.")
    from cryptography.fernet import Fernet
    import base64

    def generate_key():
        return Fernet.generate_key()

    def encrypt_message(message, key):
        f = Fernet(key)
        return f.encrypt(message.encode('utf-8'))

    def decrypt_message(encrypted_message, key):
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode('utf-8')

    def encode_image(image_path, message, save_path):
        # This is a placeholder and doesn't actually perform steganography
        img = Image.open(image_path)
        if isinstance(message, bytes):
            # For demonstration, we'll save the message in a text file alongside the image
            with open(save_path + ".txt", "wb") as f:
                f.write(message)
        else:
            with open(save_path + ".txt", "w") as f:
                f.write(message)
        img.save(save_path)


    def decode_image(image_path):
        # This is a placeholder and doesn't actually perform steganography
        # It assumes a .txt file with the same name exists
        txt_path = os.path.splitext(image_path)[0] + ".png.txt" # Based on how the mock encode saves it
        if os.path.exists(txt_path):
             with open(txt_path, "rb") as f:
                return f.read()
        raise ValueError("Mock decode: No message found for this image.")
# --- End of Mock ---


class StegoApp:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_variables()
        self.create_widgets()
        self.setup_layout()
        root.report_callback_exception = self.report_callback_exception

    def report_callback_exception(self, exc, val, tb):
        import traceback
        messagebox.showerror("Unhandled Error", f"{val}\n{''.join(traceback.format_exception(exc, val, tb))}")

    def setup_window(self):
        self.root.title("Steganography Tool")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        self.root.configure(bg='#1a1a1a')
        
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1000 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"1000x700+{x}+{y}")

    def setup_variables(self):
        self.img_path = tk.StringVar(value="No image selected")
        self.encrypt_var = tk.BooleanVar()
        self.key_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.img_preview = None
        self.buttons = [] # To easily disable/enable all buttons

    def create_widgets(self):

        # Main container
        self.main_frame = tk.Frame(self.root, bg='#1a1a1a', padx=30, pady=30)
        
        # Header
        self.header_frame = tk.Frame(self.main_frame, bg='#1a1a1a')
        self.title_label = tk.Label(self.header_frame, text="Steganography Tool", 
                                    font=('Segoe UI', 24, 'bold'), fg='#00d4ff', bg='#1a1a1a')
        self.subtitle_label = tk.Label(self.header_frame, text="Hide and reveal secret messages in images", 
                                        font=('Segoe UI', 11), fg='#b3b3b3', bg='#1a1a1a')
        
        # Create two-column layout frames
        self.content_frame = tk.Frame(self.main_frame, bg='#1a1a1a')
        self.left_column = tk.Frame(self.content_frame, bg='#1a1a1a')
        self.right_column = tk.Frame(self.content_frame, bg='#1a1a1a')

        # --- Left column widgets ---
        # Image selection frame
        self.img_frame = tk.LabelFrame(self.left_column, text="Image Selection", 
                                       font=('Segoe UI', 12, 'bold'), fg='#00d4ff', bg='#2a2a2a', 
                                       relief='flat', bd=1, padx=20, pady=15)
        self.img_path_label = tk.Label(self.img_frame, textvariable=self.img_path, font=('Segoe UI', 10), 
                                       fg='#b3b3b3', bg='#2a2a2a', wraplength=350, justify='left')
        self.choose_img_btn = tk.Button(self.img_frame, text="Choose Image", 
                                        command=self.choose_image, font=('Segoe UI', 11, 'bold'),
                                        bg='#00d4ff', fg='#1a1a1a', relief='flat', bd=0, padx=20, pady=8)
        self.img_preview_label = tk.Label(self.img_frame, text="Image preview will appear here", 
                                          font=('Segoe UI', 10), fg='#b3b3b3', bg='#2a2a2a')
        
        # Encryption frame
        self.encrypt_frame = tk.LabelFrame(self.left_column, text="Encryption Settings", 
                                           font=('Segoe UI', 12, 'bold'), fg='#00d4ff', bg='#2a2a2a', 
                                           relief='flat', bd=1, padx=20, pady=15)
        self.encrypt_check = tk.Checkbutton(self.encrypt_frame, text="Encrypt message before hiding", 
                                            variable=self.encrypt_var, command=self.toggle_encryption,
                                            font=('Segoe UI', 10), fg='#ffffff', bg='#2a2a2a', 
                                            selectcolor='#1a1a1a', activebackground='#2a2a2a', activeforeground='#ffffff')
        self.key_frame = tk.Frame(self.encrypt_frame, bg='#2a2a2a')
        self.key_label = tk.Label(self.key_frame, text="Encryption Key:", 
                                  font=('Segoe UI', 11, 'bold'), fg='#00d4ff', bg='#2a2a2a')
        self.key_entry = tk.Entry(self.key_frame, textvariable=self.key_var, width=30, show="*",
                                  font=('Consolas', 10), bg='#3a3a3a', fg='#ffffff', 
                                  insertbackground='#00d4ff', relief='flat', bd=1)
        self.gen_key_btn = tk.Button(self.key_frame, text="Generate Key", command=self.gen_key, 
                                     font=('Segoe UI', 10), bg='#3a3a3a', fg='#ffffff', 
                                     relief='flat', bd=1, padx=12, pady=6)
        self.show_key_btn = tk.Button(self.key_frame, text="👁", command=self.toggle_key_visibility, 
                                      font=('Segoe UI', 10), bg='#3a3a3a', fg='#ffffff', 
                                      relief='flat', bd=1, padx=8, pady=6)
        
        # Message frame
        self.msg_frame = tk.LabelFrame(self.left_column, text="Message", 
                                       font=('Segoe UI', 12, 'bold'), fg='#00d4ff', bg='#2a2a2a', 
                                       relief='flat', bd=1, padx=20, pady=15)
        self.msg_label = tk.Label(self.msg_frame, text="Enter your secret message:", 
                                  font=('Segoe UI', 11, 'bold'), fg='#00d4ff', bg='#2a2a2a')
        self.msg_text_frame = tk.Frame(self.msg_frame, bg='#2a2a2a') # Frame for text and scrollbar
        self.msg_text = tk.Text(self.msg_text_frame, height=6, wrap=tk.WORD, 
                                font=('Consolas', 11), bg='#3a3a3a', fg='#ffffff',
                                insertbackground='#00d4ff', selectbackground='#00d4ff',
                                relief='flat', bd=1)
        self.msg_scroll = tk.Scrollbar(self.msg_text_frame, orient="vertical", command=self.msg_text.yview)
        self.msg_text.configure(yscrollcommand=self.msg_scroll.set)
        
        # Action buttons
        self.action_frame = tk.Frame(self.left_column, bg='#1a1a1a')
        self.encode_btn = tk.Button(self.action_frame, text="Encode & Save", command=self.encode, 
                                    font=('Segoe UI', 11, 'bold'), bg='#00d4ff', fg='#1a1a1a', 
                                    relief='flat', bd=0, padx=20, pady=10)
        self.decode_btn = tk.Button(self.action_frame, text="Decode Message", command=self.decode, 
                                    font=('Segoe UI', 11, 'bold'), bg='#00d4ff', fg='#1a1a1a', 
                                    relief='flat', bd=0, padx=20, pady=10)
        
        # --- Right column widgets ---
        self.output_frame = tk.LabelFrame(self.right_column, text="Output", 
                                          font=('Segoe UI', 12, 'bold'), fg='#00d4ff', bg='#2a2a2a', 
                                          relief='flat', bd=1, padx=20, pady=15)
        self.output_label = tk.Label(self.output_frame, text="Decoded message will appear here:", 
                                     font=('Segoe UI', 11, 'bold'), fg='#00d4ff', bg='#2a2a2a')
        
        self.output_notebook = ttk.Notebook(self.output_frame)
        
        # Original message tab
        self.original_frame = tk.Frame(self.output_notebook, bg='#2a2a2a')
        self.output_text = tk.Text(self.original_frame, height=8, wrap=tk.WORD, 
                                   font=('Consolas', 11), bg='#3a3a3a', fg='#ffffff', state='disabled',
                                   insertbackground='#00d4ff', selectbackground='#00d4ff',
                                   relief='flat', bd=1)
        self.output_scroll = tk.Scrollbar(self.original_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=self.output_scroll.set)
        
        # Translation tab
        self.translation_frame = tk.Frame(self.output_notebook, bg='#2a2a2a')
        self.translation_controls = tk.Frame(self.translation_frame, bg='#2a2a2a')
        self.lang_from = ttk.Combobox(self.translation_controls, values=['auto', 'en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'ja', 'ko', 'zh'], 
                                      width=8, state='readonly')
        self.lang_to = ttk.Combobox(self.translation_controls, values=['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'ja', 'ko', 'zh'], 
                                    width=8, state='readonly')
        self.translate_btn = tk.Button(self.translation_controls, text="Translate", command=self.translate_message, 
                                       font=('Segoe UI', 10), bg='#3a3a3a', fg='#ffffff', 
                                       relief='flat', bd=1, padx=12, pady=6)
        self.lang_detected_label = tk.Label(self.translation_controls, text="", 
                                            font=('Segoe UI', 10), fg='#b3b3b3', bg='#2a2a2a')
        self.translation_text = tk.Text(self.translation_frame, height=8, wrap=tk.WORD, 
                                        font=('Consolas', 11), bg='#3a3a3a', fg='#ffffff', state='disabled',
                                        insertbackground='#00d4ff', selectbackground='#00d4ff',
                                        relief='flat', bd=1)
        self.translation_scroll = tk.Scrollbar(self.translation_frame, orient="vertical", command=self.translation_text.yview)
        self.translation_text.configure(yscrollcommand=self.translation_scroll.set)

        self.lang_from.set('auto')
        self.lang_to.set('en')

        self.output_notebook.add(self.original_frame, text="Original")
        self.output_notebook.add(self.translation_frame, text="Translation")
        
        # --- Status Bar ---
        self.status_frame = tk.Frame(self.main_frame, bg='#1a1a1a')
        self.status_label = tk.Label(self.status_frame, textvariable=self.status_var, 
                                     font=('Segoe UI', 10), fg='#b3b3b3', bg='#1a1a1a')
        self.progress = ttk.Progressbar(self.status_frame, mode='indeterminate')

        # Collect buttons to manage state
        self.buttons.extend([
            self.choose_img_btn, self.gen_key_btn, self.show_key_btn,
            self.encode_btn, self.decode_btn, self.translate_btn
        ])

    def setup_layout(self):
        self.main_frame.pack(fill='both', expand=True)
        
        self.header_frame.pack(fill='x', pady=(0, 20))
        self.title_label.pack(anchor='w')
        self.subtitle_label.pack(anchor='w', pady=(5, 0))
        
        self.content_frame.pack(fill='both', expand=True)
        self.left_column.pack(side='left', fill='both', expand=True, padx=(0, 15))
        self.right_column.pack(side='right', fill='both', expand=True, padx=(15, 0))
        
        # --- Left column layout ---
        self.img_frame.pack(fill='x', pady=(0, 20))
        self.img_path_label.pack(anchor='w', pady=(0, 10))
        self.choose_img_btn.pack(anchor='w', pady=(0, 10))
        self.img_preview_label.pack(anchor='w', pady=(5, 0))
        
        self.encrypt_frame.pack(fill='x', pady=(0, 20))
        self.encrypt_check.pack(anchor='w', pady=(0, 10))
        # key_frame is packed/unpacked in toggle_encryption
        
        self.key_label.pack(side='left', anchor='w', pady=(0, 8))
        self.key_entry.pack(side='left', fill='x', expand=True, padx=(10, 8))
        self.gen_key_btn.pack(side='left', padx=(0, 8))
        self.show_key_btn.pack(side='left')
        
        self.msg_frame.pack(fill='both', expand=True, pady=(0, 20))
        self.msg_label.pack(anchor='w', pady=(0, 10))
        self.msg_text_frame.pack(fill='both', expand=True)
        self.msg_scroll.pack(side='right', fill='y')
        self.msg_text.pack(side='left', fill='both', expand=True)
        
        self.action_frame.pack(fill='x')
        self.encode_btn.pack(side='left', padx=(0, 15))
        self.decode_btn.pack(side='left')
        
        # --- Right column layout ---
        self.output_frame.pack(fill='both', expand=True)
        self.output_label.pack(anchor='w', pady=(0, 15))
        
        self.output_notebook.pack(fill='both', expand=True)
        
        # Original tab layout
        self.output_scroll.pack(side='right', fill='y')
        self.output_text.pack(fill='both', expand=True)
        
        # Translation tab layout
        self.translation_controls.pack(fill='x', pady=10)
        self.lang_from.pack(side='left', padx=(0, 8))
        tk.Label(self.translation_controls, text="→", font=('Segoe UI', 10), fg='#b3b3b3', bg='#2a2a2a').pack(side='left', padx=8)
        self.lang_to.pack(side='left', padx=(0, 15))
        self.translate_btn.pack(side='left', padx=(0, 15))
        self.lang_detected_label.pack(side='left')
        
        self.translation_scroll.pack(side='right', fill='y')
        self.translation_text.pack(fill='both', expand=True)

        # Status bar layout
        self.status_frame.pack(fill='x', pady=(20, 0))
        self.status_label.pack(side='left')
        
        # Initially hide encryption key
        self.toggle_encryption()

    # --- THREADING HELPER METHODS ---
    def start_task(self, status_message):
        """Prepares UI for a long-running task."""
        self.start_progress()
        self.update_status(status_message)
        for btn in self.buttons:
            btn.config(state='disabled')
        self.root.update_idletasks()

    def end_task(self):
        """Resets UI after a long-running task."""
        self.stop_progress()
        for btn in self.buttons:
            btn.config(state='normal')
        
    def run_in_thread(self, target_func, callback_func, *args):
        """General purpose function to run a task in a thread."""
        def worker():
            try:
                result = target_func(*args)
                # Schedule the callback to run on the main thread
                self.root.after(0, callback_func, True, result)
            except Exception as e:
                # Schedule the callback with the error
                self.root.after(0, callback_func, False, e)
        
        threading.Thread(target=worker, daemon=True).start()

    def choose_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[("Image files", "*.png;*.bmp;*.tiff;*.jpg;*.jpeg"), ("All files", "*.*")]
        )
        if file_path:
            self.img_path.set(os.path.basename(file_path))
            self._full_img_path = file_path # Store full path internally
            self.update_image_preview(file_path)
            self.update_status("Image selected successfully")

    def update_image_preview(self, image_path):
        try:
            img = Image.open(image_path)
            img.thumbnail((300, 200), Image.Resampling.LANCZOS)
            self.img_preview = ImageTk.PhotoImage(img)
            self.img_preview_label.configure(image=self.img_preview, text="")
        except Exception as e:
            self.img_preview_label.configure(image="", text=f"Preview unavailable: {str(e)}")


    def toggle_encryption(self):
        if self.encrypt_var.get():
            self.key_frame.pack(fill='x', pady=(10, 0))
        else:
            self.key_frame.pack_forget()

    def toggle_key_visibility(self):
        if self.key_entry.cget('show') == '*':
            self.key_entry.configure(show='')
            self.show_key_btn.configure(text="🙈")
        else:
            self.key_entry.configure(show='*')
            self.show_key_btn.configure(text="👁")

    def gen_key(self):
        try:
            key = generate_key()
            self.key_var.set(key.decode('utf-8', 'ignore'))
            self.update_status("New encryption key generated")
        except Exception as e:
            self.show_error(f"Failed to generate key: {str(e)}")

    def update_status(self, message, is_error=False):
        self.status_var.set(message)
        self.status_label.configure(fg='#ff4757' if is_error else '#b3b3b3')

    def show_error(self, message):
        self.update_status(f"Error: {message}", is_error=True)
        messagebox.showerror("Error", message)

    def show_success(self, message):
        self.update_status(message)
        messagebox.showinfo("Success", message)

    def start_progress(self):
        self.progress.pack(side='right', padx=(10, 0))
        self.progress.start()

    def stop_progress(self):
        self.progress.stop()
        self.progress.pack_forget()

    # --- ENCODE ---
    def encode(self):
        if not hasattr(self, '_full_img_path') or not self._full_img_path:
            self.show_error("Please select an image file")
            return
        msg = self.msg_text.get("1.0", tk.END).strip()
        if not msg:
            self.show_error("Please enter a message to encode")
            return
        if self.encrypt_var.get() and not self.key_var.get():
            self.show_error("Please enter an encryption key or generate one")
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Encoded Image",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if not save_path:
            return

        self.start_task("Encoding message...")
        self.run_in_thread(self._do_encode_work, self._encode_callback, msg, save_path)

    def _do_encode_work(self, msg, save_path):
        """Worker function for encoding (runs in background thread)."""
        processed_msg = msg
        if self.encrypt_var.get():
            key = self.key_var.get()
            processed_msg = encrypt_message(msg, key.encode('utf-8'))
        
        encode_image(self._full_img_path, processed_msg, save_path)
        return save_path # Return save path for success message

    def _encode_callback(self, success, result):
        """Callback for when encoding finishes."""
        self.end_task()
        if success:
            save_path = result
            self.show_success(f"Message successfully encoded and saved to:\n{save_path}")
        else:
            error = result
            self.show_error(f"Encoding failed: {str(error)}")

    # --- DECODE ---
    def decode(self):
        file_path = filedialog.askopenfilename(
            title="Select Image to Decode",
            filetypes=[("PNG files", "*.png")]
        )
        if not file_path:
            return
        
        self.start_task("Decoding message...")
        self.run_in_thread(self._do_decode_work, self._decode_callback, file_path)

    def _do_decode_work(self, file_path):
        """Worker function for decoding."""
        hidden_data = decode_image(file_path)
        if self.encrypt_var.get():
            key = self.key_var.get()
            if not key:
                raise ValueError("Decryption key is missing.")
            return decrypt_message(hidden_data, key.encode('utf-8'))
        
        # If not encrypted, it's likely bytes that need decoding
        if isinstance(hidden_data, bytes):
            try:
                return hidden_data.decode('utf-8')
            except UnicodeDecodeError:
                 raise ValueError("Could not decode message. It might be encrypted or corrupted.")
        return hidden_data

    def _decode_callback(self, success, result):
        """Callback for when decoding finishes."""
        self.end_task()
        if success:
            hidden_text = result
            self.output_text.config(state='normal')
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, hidden_text)
            self.output_text.config(state='disabled')
            
            self.translation_text.config(state='normal')
            self.translation_text.delete("1.0", tk.END)
            self.translation_text.config(state='disabled')

            self.update_status("Message decoded successfully")
            self.output_notebook.select(0) # Switch to original tab
        else:
            error = result
            self.show_error(f"Decoding failed: {str(error)}")

    # --- TRANSLATE ---
    def translate_message(self):
        original_text = self.output_text.get("1.0", tk.END).strip()
        if not original_text:
            self.show_error("No message to translate. Please decode a message first.")
            return

        self.start_task("Translating message...")
        self.run_in_thread(self._do_translate_work, self._translate_callback, original_text)

    def _do_translate_work(self, text):
        """Worker function for translation."""
        source_lang = self.lang_from.get()
        if source_lang == 'auto':
            source_lang = self.detect_language(text)
        
        target_lang = self.lang_to.get()
        
        if source_lang == target_lang:
            return {'translated': text, 'detected': source_lang, 'needed_translation': False}

        url = "https://api.mymemory.translated.net/get"
        params = {'q': text, 'langpair': f"{source_lang}|{target_lang}"}
        
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status() # Raise an exception for bad status codes
        data = response.json()
        
        if data['responseStatus'] != 200:
            raise Exception(data.get('responseDetails', 'Unknown API error'))

        return {
            'translated': data['responseData']['translatedText'],
            'detected': source_lang,
            'needed_translation': True
        }

    def _translate_callback(self, success, result):
        """Callback for when translation finishes."""
        self.end_task()
        if success:
            translated_text = result['translated']
            source_lang = result['detected']
            needed_translation = result['needed_translation']

            self.lang_detected_label.config(text=f"Detected: {source_lang.upper()}" if self.lang_from.get() == 'auto' else "")

            self.translation_text.config(state='normal')
            self.translation_text.delete("1.0", tk.END)
            self.translation_text.insert(tk.END, translated_text)
            self.translation_text.config(state='disabled')
            
            self.output_notebook.select(1) # Switch to translation tab
            
            if needed_translation:
                self.update_status(f"Translation completed ({source_lang.upper()} → {self.lang_to.get().upper()})")
            else:
                 self.update_status("No translation needed - same language")
        else:
            error = result
            self.show_error(f"Translation failed: {str(error)}")

    def detect_language(self, text):
        """Simple language detection based on character patterns."""
        if any('\u4e00' <= char <= '\u9fff' for char in text): return 'zh'
        if any('\u3040' <= char <= '\u309f' or '\u30a0' <= char <= '\u30ff' for char in text): return 'ja'
        if any('\uac00' <= char <= '\ud7af' for char in text): return 'ko'
        if any('\u0400' <= char <= '\u04ff' for char in text): return 'ru'
        return 'en' # Default

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()