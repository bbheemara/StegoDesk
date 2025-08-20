import os
import tkinter as tk
from tkinter import messagebox, filedialog, StringVar, OptionMenu
from PIL import Image, ImageTk
import zlib
import numpy as np
import tempfile
from .stego import (
            encrypt_bytes,
            decrypt_bytes,
            pass_embed_to_image,
            simple_extract_from_image,
            detect_file_type,
            stream_compress_encrypt_to_file,
            embed_payload_from_file_to_cover,
            decrypt_stream_file_to_output,
)

#Contains NavBar and shows the Encode page at first
class DashboardPage(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master)
        self.configure(bg="white")

        option_frame = tk.Frame(self, bg="#e9e9e9", height=50,bd=1,relief="solid")
        option_frame.pack(side="top", fill="x")

        self.subpage_container = tk.Frame(self, bg="white",relief='solid')
        self.subpage_container.pack(fill="both", expand=True)

        self.subpages = {}
        for F in (EncodePage, DecodePage, HidePasswordPage):
            page_name = F.__name__
            frame = F(self.subpage_container, controller)
            self.subpages[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_subpage("EncodePage")

        btn_container = tk.Frame(option_frame,relief='solid', bg="#e9e9e9")
        btn_container.pack(pady=10)
        tk.Label(btn_container,text='StegoDesk',bg='#e9e9e9',font=('Arial',14)).pack(side="left",padx=50)
        tk.Button(
            btn_container,
            text="Encode Image 🔐",
            bg="#8bffa8",
            command=lambda: self.show_subpage("EncodePage"),activebackground="#ffc1c1", 
    relief="flat", padx=10, pady=5
        ).pack(side="left", padx=20)

        tk.Button(
            btn_container,
            text="Decode Image 🔓 ",
            bg="#8bffa8",
            command=lambda: self.show_subpage("DecodePage"), activebackground="#ffc1c1", 
    relief="flat", padx=10, pady=5
        ).pack(side="left", padx=20)

        tk.Button(
            btn_container,
            text="Encode/Decode Password ⛓️‍💥",
            bg="#8bffa8",
            command=lambda: self.show_subpage("HidePasswordPage"),activebackground="#ffc1c1", 
    relief="flat", padx=10, pady=5
        ).pack(side="left", padx=20)

        tk.Button(btn_container,text='Exit ➡️', activebackground="#ffc1c1", bg="#ffc1c1",
        relief="flat", padx=10, pady=5,command=master.quit
            ).pack(side="right", padx=100)

    def show_subpage(self, page_name):
        frame = self.subpages[page_name]
        if page_name == "EncodePage":
            frame.ResetPage()
        frame.tkraise()

#Encode page UI
class EncodePage(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master, bg="white")
        self.controller = controller
        
        
        tk.Label(self, text="Encode Image", font=("Arial", 14,"bold"), bg="white").pack(
            padx=700
        )

        self.img_upload_btn_e = tk.Button(
            self, text="Upload a Cover Image", command=self.ImageOpen,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5
        )
        self.img_upload_btn_e.pack(pady=20)

        self.imaage_label_e = tk.Label(self, bg="white")
        self.imaage_label_e.pack(pady=10, padx=50)

        options = [
            "Select data type",
            "Hide Text in Image",
            "Hide Image in Image",
            "Hide Documents in Image",
        ]
        self.clicked = StringVar()
        self.clicked.set(options[0])
        self.drop = OptionMenu(self, self.clicked, *options, command=self.option)
        self.drop.pack(pady=20)
        self.drop.forget()

        self.text_label_e = tk.Label(self, text="Enter the Secret Text to Hide:",font=("Helvetica", 12, "bold"), 
                 bg="white", fg="#333", 
                 padx=10, pady=5)
        self.text_input_msg_e = tk.Entry(self,font=("Helvetica", 12), 
                 fg="#333", 
                 bg="#f9f9f9", 
                 bd=1, 
                 relief="solid", 
                 insertbackground="blue")
        self.passw_label_e = tk.Label(self, text="Enter your password:",font=("Helvetica", 12, "bold"), 
                 bg="white", fg="#333", 
                 padx=10, pady=5)
        self.passw_input_e = tk.Entry(self,font=("Helvetica", 12), show="*",
                 fg="#333", 
                 bg="#f9f9f9", 
                 bd=1, 
                 relief="solid", 
                 insertbackground="blue")
        self.encode_btn_e = tk.Button(
            self, text="Encode", bg="#e6e6e6",activebackground="#ffc1c1", 
    relief="flat", padx=10, pady=5, command=self.EncodeTextImage, )
       

        self.sec_img_upload_btn_e = tk.Button(
            self,
            text="Upload a Secret Image to Encode ⬆️",
            command=self.SecImageOpen, activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5 )
       
        self.sec_imaage_label_e = tk.Label(self, bg="white")
        self.encode_imagei_btn_e = tk.Button(
            self, text="Encode", bg="#e6e6e6",activebackground="#ffc1c1", 
    relief="flat", padx=10, pady=5, command=self.EncryptImageImage)
        

        self.sec_file_upload_btn_e = tk.Button(
            self, text="Upload a Document to Encode", command=self.SecFileOpen,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5)
        

        self.msg_lable = tk.Label(self,text='Select a option from above',font=("Helvetica", 12, "bold"), 
                 bg="white", fg="#333", 
                 padx=10, pady=5)
        

        self.sec_file_label_e = tk.Label(self, bg="white")
        self.encode_file_btn_e = tk.Button(
            self, text="Encode", bg="#e6e6e6", command=self.EncryptFileImage ,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5)
       
        

        self.clear_option_widgets()

        self.cover_img_full = None
        self.sec_img_path = None
        self.sec_file_path = None
        

    def clear_option_widgets(self):
        for w in [
            self.text_label_e,
            self.text_input_msg_e,
            self.passw_label_e,
            self.passw_input_e,
            self.encode_btn_e,
            self.sec_img_upload_btn_e,
            self.sec_imaage_label_e,
            self.encode_imagei_btn_e,
            self.sec_file_upload_btn_e,
            self.sec_file_label_e,
            self.encode_file_btn_e,
            self.msg_lable
            
        ]:
            try:
                w.forget()
            except:
                pass

    def ImageOpen(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if file_path:
            img_full = Image.open(file_path).convert("RGB")
            self.cover_img_full = img_full.copy()

            preview = img_full.copy()
            preview.thumbnail((300, 300))
            self.tk_img_e = ImageTk.PhotoImage(preview)
            self.imaage_label_e.config(image=self.tk_img_e)

            self.drop.pack()

    def SecImageOpen(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if file_path:
            self.sec_img_path = file_path
            self.sec_imaage_label_e.config(
                text=f"Selected: {os.path.basename(file_path)}"
            )

    def SecFileOpen(self):
        file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if file_path:
            self.sec_file_path = file_path
            self.sec_file_label_e.config(text=f"Selected: {os.path.basename(file_path)}")

    def option(self, event):
        self.clear_option_widgets()

        if self.clicked.get() == "Hide Text in Image":
            self.text_label_e.pack(pady=10)
            self.text_input_msg_e.pack(pady=10)
            self.passw_label_e.pack()
            self.passw_input_e.pack(pady=10)
            self.encode_btn_e.pack(pady=20)

        elif self.clicked.get() == "Hide Image in Image":
            self.sec_img_upload_btn_e.pack(pady=10)
            self.sec_imaage_label_e.pack(pady=10, padx=50)
            self.passw_label_e.pack()
            self.passw_input_e.pack(pady=10)
            self.encode_imagei_btn_e.pack(pady=20)

        elif self.clicked.get() == "Hide Documents in Image":
            self.sec_file_upload_btn_e.pack(pady=10)
            self.sec_file_label_e.pack(pady=10, padx=50)
            self.passw_label_e.pack()
            self.passw_input_e.pack(pady=10)
            self.encode_file_btn_e.pack(pady=20)

        else:
            self.msg_lable.pack(pady=10)

    #takes encrypted data  embeds inside cover image
    def embed_payload_to_cover(self, encrypted):
        payload = len(encrypted).to_bytes(4, "big") + encrypted
        binary_secret = bytearray()

        for b in payload:
            for bitpos in range(7, -1, -1):
                binary_secret.append((b >> bitpos) & 1)

        img = self.cover_img_full
        if img is None:
            raise ValueError("No cover image selected.")

        data = np.array(img, dtype=np.uint8, copy=True)  
           
        flat = data.ravel()              

        if len(binary_secret) > flat.size:
            raise ValueError("Secret data too large for this cover image!")

        
        flat[:len(binary_secret)] = (flat[:len(binary_secret)] & 0xFE) | np.frombuffer(bytes(binary_secret), dtype=np.uint8)
        return Image.fromarray(data.astype("uint8"))

    #Encodes text into image with the help of helping funtions and saves
    def EncodeTextImage(self):
        if self.cover_img_full is None:
            messagebox.showerror("Error", "Please upload a cover image first")
            return

        secret_text = self.text_input_msg_e.get()
        password = self.passw_input_e.get()

        if not secret_text or not password:
            messagebox.showerror(
                "Error", "Secret text and password cannot be empty"
            )
            return

        try:
            compressed = zlib.compress(secret_text.encode("utf-8"))
            encrypted = encrypt_bytes(password, compressed)
            encoded_img = self.embed_payload_to_cover(encrypted)
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png", filetypes=[("PNG files", "*.png")]
            )

            if save_path:
                encoded_img.save(save_path)
                messagebox.showinfo(
                    "Success", f"Secret encoded and saved at:\n{save_path}"
                )
                self.ResetPage()
                self.drop.forget()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to encode text: {str(e)}")
            self.ResetPage()
            self.drop.forget()

    #Encrypts Secret image inside cover image with help of helping funtions
    def EncryptImageImage(self):
        if self.cover_img_full is None:
            messagebox.showerror("Error", "Please upload the cover image first")
            return

        if self.sec_img_path is None:
            messagebox.showerror("Error", "Please upload the secret image")
            return

        password = self.passw_input_e.get()

        if not password:
            messagebox.showerror("Error", "Please enter password")
            return

        try:
            with open(self.sec_img_path, "rb") as f:
                secret_bytes = f.read()
            
            compressed = zlib.compress(secret_bytes)
            encrypted = encrypt_bytes(password, compressed)
            encoded_img = self.embed_payload_to_cover(encrypted)
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png", filetypes=[("PNG files", "*.png")]
            )

            if save_path:
                encoded_img.save(save_path)
                messagebox.showinfo(
                    "Success",
                    f"Secret image encoded and saved at:\n{save_path}",
                )
                self.ResetPage()
                self.drop.forget()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to encode image: {str(e)}")
            self.ResetPage()
            self.drop.forget()

    #Encrypts file into cover image
    def EncryptFileImage(self):
        if self.cover_img_full is None:
            messagebox.showerror("Error", "Please upload the cover image first")
            return

        if self.sec_file_path is None:
            messagebox.showerror("Error", "Please upload file to hide")
            return

        password = self.passw_input_e.get()

        if not password:
            messagebox.showerror("Error", "Please enter password")
            return

        try:
            secret_size = os.path.getsize(self.sec_file_path)

            THRESHOLD_STREAM_BYTES = 2 * 1024 * 1024  

            if secret_size > THRESHOLD_STREAM_BYTES:
                enc_tmp = stream_compress_encrypt_to_file(self.sec_file_path, password)
                try:
                    encoded_img = embed_payload_from_file_to_cover(self.cover_img_full, enc_tmp)
                    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
                    if save_path:
                        encoded_img.save(save_path)
                        messagebox.showinfo("Success", f"Secret file encoded and saved at:\n{save_path}")
                        self.ResetPage()
                        self.drop.forget()
                finally:
                    try:
                        os.unlink(enc_tmp)
                    except Exception:
                        pass
            else:
                with open(self.sec_file_path, "rb") as f:
                    secret_bytes = f.read()

                compressed = zlib.compress(secret_bytes)
                encrypted = encrypt_bytes(password, compressed)
                encoded_img = self.embed_payload_to_cover(encrypted)
                save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])

                if save_path:
                    encoded_img.save(save_path)
                    messagebox.showinfo("Success", f"Secret file encoded and saved at:\n{save_path}")
                    self.ResetPage()
                    self.drop.forget()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to encode file: {str(e)}")
            self.ResetPage()
            self.drop.forget()


    def ResetPage(self):
        self.cover_img_full = None
        self.imaage_label_e.config(image="")
        self.img_upload_btn_e.config(text="Upload a Cover Image")
        self.sec_img_path = None
        self.sec_file_path = None
        self.clear_option_widgets()

        try:
            self.text_input_msg_e.delete(0, tk.END)
        except:
            pass

        try:
            self.passw_input_e.delete(0, tk.END)
        except:
            pass

        self.clear_option_widgets()

#Decode Page UI
class DecodePage(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master, bg="white")
        self.controller = controller

        tk.Label(self, text="Decode Image", font=("Arial", 14,"bold"), bg="white").pack(
            padx=350
        )

        tk.Button(
            self, text="Upload a Stego Image", command=self.ImageOpen,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5

        ).pack(pady=20)

        self.imaage_label_d = tk.Label(self, bg="white")
        self.imaage_label_d.pack(pady=10, padx=50)

        self.passw_label_d = tk.Label(self, text="Enter the password:",font=("Helvetica", 12, "bold"), 
                 bg="white", fg="#333", 
                 padx=10, pady=5)
        self.passw_label_d.forget()

        self.passw_input_d = tk.Entry(self,font=("Helvetica", 12), show="*",
                 fg="#333", 
                 bg="#f9f9f9", 
                 bd=1, 
                 relief="solid", 
                 insertbackground="blue")
        self.passw_input_d.forget()

        self.decode_btn_d = tk.Button(
            self, text="Decode", bg="#e6e6e6", command=self.DecodeAny,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5
        )
        self.decode_btn_d.forget()

        self.stego_img_full = None
        self.ResetPage()

    def ImageOpen(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )

        if file_path:
            img_full = Image.open(file_path).convert("RGB")
            self.stego_img_full = img_full.copy()

            preview = img_full.copy()
            preview.thumbnail((300, 300))
            self.tk_img_d = ImageTk.PhotoImage(preview)
            self.imaage_label_d.config(image=self.tk_img_d)

            self.passw_label_d.pack(padx=20)
            self.passw_input_d.pack(pady=10)
            self.decode_btn_d.pack()

    #extracts data from image (here i took some help from LLMds to understand and implement things)
    def extract_payload_bytes_from_image(self, data_flat):
        all_bytes = bytearray()
        current_byte = 0
        bits_collected = 0
        expected_total = None

        for i in range(len(data_flat)):
            bit = int(data_flat[i]) & 1
            current_byte = (current_byte << 1) | bit
            bits_collected += 1

            if bits_collected == 8:
                all_bytes.append(current_byte & 0xFF)
                current_byte = 0
                bits_collected = 0

                if len(all_bytes) == 4:
                    payload_len = int.from_bytes(all_bytes[:4], "big")

                    if payload_len < 0 or payload_len > 100 * 1024 * 1024:
                        raise ValueError("Invalid payload length.")
                    expected_total = 4 + payload_len

                if expected_total is not None and len(all_bytes) >= expected_total:
                    break

        return bytes(all_bytes)
    

    #extract payload bytes, but if payload is large, write directly into a temp file to avoid memory usage increase (took help from LLMs)
    def extract_payload_bytes_or_to_tempfile(self, data_flat, stream_threshold=2 * 1024 * 1024):
        
        all_bytes = bytearray()
        current_byte = 0
        bits_collected = 0
        total_len = None
        idx = 0

       
        tmpf = None
        bytes_written_after_header = 0

        for i in range(len(data_flat)):
            bit = int(data_flat[i]) & 1
            current_byte = (current_byte << 1) | bit
            bits_collected += 1

            if bits_collected == 8:
                all_bytes.append(current_byte & 0xFF)
                current_byte = 0
                bits_collected = 0

                if len(all_bytes) == 4 and total_len is None:
                    total_len = int.from_bytes(all_bytes[:4], "big")
                    if total_len < 0 or total_len > 200 * 1024 * 1024:
                        raise ValueError("Invalid payload length.")
                    if total_len > stream_threshold:
                        tmpf = tempfile.NamedTemporaryFile(delete=False)

                elif total_len is not None:
                    if tmpf:
                        tmpf.write(bytes([all_bytes[-1]]))
                        bytes_written_after_header += 1

                    if (tmpf and bytes_written_after_header >= total_len) or (not tmpf and len(all_bytes) >= 4 + total_len):
                        break

        if total_len is None:
            if tmpf:
                tmpf.close()
                os.unlink(tmpf.name)
            raise ValueError("No payload length found.")

        if tmpf:
            tmpf.close()
            return tmpf.name
        else:
            return bytes(all_bytes[4:4 + total_len])
        
    #reads stego image, extracts data, decrypts, decompresses detect file type and provide the hidden data
    def DecodeAny(self):
        if self.stego_img_full is None:
            messagebox.showerror("Error", "Please upload a stego image first")
            return

        password = self.passw_input_d.get()

        if not password:
            messagebox.showerror("Error", "Password cannot be empty")
            return

        try:
            img = self.stego_img_full
            data = np.array(img)
            data_flat = data.flatten()

            THRESHOLD_STREAM_BYTES = 2 * 1024 * 1024

            extracted_or_path = self.extract_payload_bytes_or_to_tempfile(data_flat, stream_threshold=THRESHOLD_STREAM_BYTES)

            if isinstance(extracted_or_path, str):
                enc_tmp_path = extracted_or_path
                out_tmp = tempfile.NamedTemporaryFile(delete=False)
                out_tmp.close()
                try:
                    decrypt_stream_file_to_output(enc_tmp_path, password, out_tmp.name)
                    with open(out_tmp.name, "rb") as f:
                        decompressed = f.read()
                finally:
                    try:
                        os.unlink(enc_tmp_path)
                    except Exception:
                        pass
                    try:
                        os.unlink(out_tmp.name)
                    except Exception:
                        pass
            else:
                encrypted = extracted_or_path
                decrypted = decrypt_bytes(password, encrypted)
                decompressed = zlib.decompress(decrypted)

            ftype = detect_file_type(decompressed)

            if ftype == "text":
                text = decompressed.decode("utf-8", errors="replace")
                messagebox.showinfo("Decoded Text", f"Secret message:\n\n{text}")

            elif ftype in ("png", "jpg"):
                default_ext = ".png" if ftype == "png" else ".jpg"
                save_path = filedialog.asksaveasfilename(
                    defaultextension=default_ext,
                    filetypes=[(f"{ftype.upper()} files", f"*{default_ext}"), ("All files", "*.*")],
                )

                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(decompressed)
                    messagebox.showinfo("Success", f"Extracted image saved to:\n{save_path}")

            elif ftype in ("pdf", "docx"):
                ext_map = {"pdf": ".pdf", "docx": ".docx"}
                save_path = filedialog.asksaveasfilename(
                    defaultextension=ext_map[ftype],
                    filetypes=[(f"{ftype.upper()} file", f"*{ext_map[ftype]}"), ("All files", "*.*")],
                )

                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(decompressed)
                    messagebox.showinfo("Success", f"Extracted {ftype.upper()} saved to:\n{save_path}")

            else:
                save_path = filedialog.asksaveasfilename(
                    defaultextension=".bin", filetypes=[("Binary file", "*.bin"), ("All files", "*.*")]
                )

                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(decompressed)
                    messagebox.showinfo("Success", f"Extracted binary saved to:\n{save_path}")

            self.ResetPage()

        except (ValueError, AssertionError) as e:
            messagebox.showwarning("Error", "Failed to decode (Incorrect password or corrupted data)")

        except Exception as e:
            messagebox.showwarning(
                "Error", "Failed to Decode (Incorrect password or corrupted data)"
            )


    def ResetPage(self):
        self.stego_img_full = None
        self.imaage_label_d.config(image="")
        try:
            self.passw_input_d.delete(0, tk.END)
        except:
            pass
        self.passw_input_d.forget()
        self.passw_label_d.forget()
        self.decode_btn_d.forget()
        
#Hide Password Page UI
class HidePasswordPage(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master, bg="white")

        self.controller = controller

        
        tk.Label(self, text="Encode/Decode Password", font=("Arial", 14, 'bold'), bg="white").pack(padx=350)

        self.img_upload_btn = tk.Button(self,text='Upload a Image', command=self.ImageOpen,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5)
        self.img_upload_btn.pack(pady=20)
        self.img_label=tk.Label(self, bg="white")
        self.img_label.pack(pady=10) 


        options = [
            'Select Method',
            'Encode Password',
            'Decode Passwoed'
        ]

        self.clicked = StringVar()
        self.clicked.set(options[0])
        self.drop = OptionMenu(self, self.clicked, *options, command=self.option)
        
        


        
        self.password_label = tk.Label(self,text='Enter the password to be stored:',
                              font=("Helvetica", 12, "bold"), 
                 bg="white", fg="#333", 
                 padx=10, pady=5)
        self.password_label.pack(pady=10)
        self.password_input = tk.Entry(self,font=("Helvetica", 12), show="*",
                 fg="#333", 
                 bg="#f9f9f9", 
                 bd=1, 
                 relief="solid", 
                 insertbackground="blue")
        self.password_input.pack(pady=10)

        self.encode_btn = tk.Button(self,text='Encode',command=self.EncodePass,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5)
        self.encode_btn.pack(pady=10)

        self.decode_btn = tk.Button(self,text='Decode',command=self.DecodePass,activebackground="#c4ffc7", 
    relief="flat", padx=10, pady=5)
        self.decode_btn.pack(pady=10)

        self.msg_lable = tk.Label(self,text='Select a option from above')
        self.msg_lable.pack(pady=10)
        
        self.password_label.forget()
        self.password_input.forget()
        self.encode_btn.forget()
        self.decode_btn.forget()
        self.msg_lable.forget()

    
    def clear_option_widgets(self):
         for w in [
            self.img_label, self.password_input, self.password_label, self.encode_btn, self.decode_btn,self.drop
        ]:
            try: w.forget()
            except: pass
    
    def ImageOpen(self):
            file_path = filedialog.askopenfilename(
                        filetypes=[
                         ("Image Files", "*.png;*.jpg;*.jpeg")                        
                         ]
                )
            
            
            if file_path:
                img_full = Image.open(file_path).convert("RGB")
                self.cover_img_full = img_full.copy()

                preview = img_full.copy()

                
                preview.thumbnail((300,300))

                self.tk_img = ImageTk.PhotoImage(preview)
                self.img_label.config(image=self.tk_img) 
                
                self.img_label.pack(pady=10)
                self.drop.pack(pady=10)
                messagebox.showwarning('Warning', "Please don't share the image with anyone. Store it on your system because the passwords aren't protected. Instead, use Encode Image for Better Protection:)")


    
    def option(self,event):
        

        if self.clicked.get() == 'Encode Password':
            self.msg_lable.forget()
            self.decode_btn.forget()

            self.password_label.pack(pady=10) 
            self.password_input.pack(pady=10)
            self.encode_btn.pack(pady=10)

            

        elif self.clicked.get() == 'Decode Passwoed':
            self.msg_lable.forget()
            self.password_label.forget()
            self.password_input.forget()
            self.encode_btn.forget()
            self.decode_btn.pack(pady=10)

        else:
            self.msg_lable.forget()
            self.password_label.forget()
            self.password_input.forget()
            self.encode_btn.forget()
            self.decode_btn.forget()

            self.msg_lable.pack()

    #Encodes the password provided by user without any encryption/extra password protection
    def EncodePass(self):

        if not hasattr(self, "cover_img_full") or self.cover_img_full is None:
            messagebox.showerror('Error' , 'Please Upload a cover image first')
            return
            
        secret_pass = self.password_input.get()

        if not secret_pass:
            messagebox.showerror('Error', 'Password cannot be empty') 
            return
        
        try:
            encoded_img = pass_embed_to_image(self.cover_img_full, secret_pass)
            save_path = filedialog.asksaveasfilename(defaultextension='.png', 
                filetypes=[
                    ("PNG files", "*.png")
                ])
            
            if save_path:
                encoded_img.save(save_path)
                messagebox.showinfo("Success", f"Password stored in image at:\n{save_path}")
                self.clear_option_widgets()

        

        except Exception as e: 
            messagebox.showerror('Error', f"Failed to encode password: {e}") 
            
    
    #Decodes the password and copies to clipboard
    def DecodePass(self):
   
        if not hasattr(self, "cover_img_full") or self.cover_img_full is None:
            file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
            if not file_path:
                return
            if file_path.lower().endswith((".jpg", ".jpeg")):
                messagebox.showwarning("Warning", "JPEG is lossy — the hidden payload may be corrupted. Continue if you know this is the original stego file.")
            try:
                img = Image.open(file_path).convert("RGB")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open image: {e}")
                return

            preview = img.copy()
            preview.thumbnail((300, 300))
            self.tk_img = ImageTk.PhotoImage(preview)
            self.img_label.config(image=self.tk_img)
            self.cover_img_full = img.copy()
        else:
            img = self.cover_img_full

        try:
            secret = simple_extract_from_image(img)

            if not secret:
                raise ValueError("No password found in image.")

            try:
                root = self.winfo_toplevel()
                root.clipboard_clear()
                root.clipboard_append(secret)  
            except Exception:
                pass

            messagebox.showinfo("Decoded Password", f"Password:\n{secret}\n\ncopied to clipboard:)")
            self.clear_option_widgets()
            self.msg_lable.forget()
        except Exception as e:
            messagebox.showwarning(
                "Error",
                f"Failed to decode password:\n"
                "- The image doesn't contain a hidden password or corrupted\n"
               
            )    
            self.clear_option_widgets()
            self.msg_lable.forget()

         
