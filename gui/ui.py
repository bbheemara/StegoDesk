
import tkinter as tk
from tkinter import messagebox,filedialog,StringVar,OptionMenu
from PIL import Image,ImageTk
import zlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64



class DashboardPage(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master)
        self.configure(bg="white")

        option_frame = tk.Frame(self, bg="#e9e9e9", height=50)
        option_frame.pack(side="top", fill="x")

        self.subpage_container = tk.Frame(self, bg='white')
        self.subpage_container.pack(fill='both', expand=True)

        self.subpages = {}
        for F in (EncodePage, DecodePage):
            page_name = F.__name__
            frame = F(self.subpage_container, controller)
            self.subpages[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_subpage('EncodePage')

        btn_container = tk.Frame(option_frame, bg="#e9e9e9")
        btn_container.pack(pady=10)  
        
        btn_encode = tk.Button(
            btn_container,
            text='Encode Image',
            bg="#e6e6e6",
            command=lambda: self.show_subpage('EncodePage')
        )
        btn_encode.pack(side="left", padx=10)

        btn_decode = tk.Button(
            btn_container,
            text='Decode Image',
            bg="#e6e6e6",
            command=lambda: self.show_subpage('DecodePage')
        )
        btn_decode.pack(side="left", padx=10)

    def show_subpage(self, page_name):
        frame = self.subpages[page_name]
        if page_name == "EncodePage":
            frame.ResetPage()
        frame.tkraise()
                   
                  

class EncodePage(tk.Frame):
    def __init__(self, master, controller):
        super().__init__(master, bg="white")
        self.controller = controller
        
        tk.Label(self, text='Encode Image', font=("Arial", 14), bg="white").pack(padx=700)
        self.img_upload_btn_e = tk.Button(self, text='Upload a Image', command=self.ImageOpen)
        self.img_upload_btn_e.pack(pady=20)
        self.imaage_label_e = tk.Label(self, bg='white')
        self.imaage_label_e.pack(pady=10, padx=50)
        
        options = [
            'Select data type',
            'Hide Text in Image',
            'Hide Image in Image',
            'Hide Documents in Image'
        ]
        self.clikced = StringVar()
        self.clikced.set(options[0])
        self.drop = OptionMenu(self, self.clikced, *options, command=self.option)
        self.drop.pack(pady=20)
        self.drop.forget()
        
        self.text_label_e = tk.Label(self, text='Enter the Secret Text to Hide:')
        self.text_input_msg_e = tk.Entry(self, bg="#f7f7f7")
        self.passw_label_e = tk.Label(self, text='Enter your password:')
        self.passw_input_e = tk.Entry(self, bg='#f7f7f7', show='*')
        self.encode_btn_e = tk.Button(self, text='Encode', bg='#e6e6e6', command=self.EncodeTextImage)
        
        self.sec_img_upload_btn_e = tk.Button(self, text='Upload a Image to Encode', command=self.SecImageOpen)
        self.sec_imaage_label_e = tk.Label(self, bg='white')
        self.encode_imagei_btn_e = tk.Button(self, text='Encode', bg='#e6e6e6', command=self.EncodeTextImage)

        self.clear_option_widgets()

        self.original_img_e = None
    def clear_option_widgets(self):
        self.text_label_e.forget()
        self.text_input_msg_e.forget()
        self.passw_label_e.forget()
        self.passw_input_e.forget()
        self.encode_btn_e.forget()
        self.sec_img_upload_btn_e.forget()
        self.sec_imaage_label_e.forget()
        self.encode_imagei_btn_e.forget()

    def ImageOpen(self):
                    file_path = filedialog.askopenfilename(
                        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
                    )
                    
                    if file_path:
                        self.img_upload_btn_e.config(text='Image Uploaded ✅')

                        img_e = Image.open(file_path)
                        img_e.thumbnail((300, 300))
                        self.original_img_e = img_e
                        self.tk_img_e = ImageTk.PhotoImage(img_e)
                        self.imaage_label_e.config(image=self.tk_img_e)

                        self.drop.pack()

    def SecImageOpen(self):
                    file_path = filedialog.askopenfilename(
                        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
                    )
                    
                    if file_path:
                        self.sec_img_upload_btn_e.config(text='Image Uploaded ✅')
                        sec_img_e = Image.open(file_path)
                        sec_img_e.thumbnail((150, 150))
                        self.sec_img_e = sec_img_e
                        self.tk_sec_img_e = ImageTk.PhotoImage(sec_img_e)
                        self.sec_imaage_label_e.config(image=self.tk_sec_img_e)

                        self.drop.pack()           

    def hide_all_option_widgets(self):
        self.text_label_e.forget()
        self.text_input_msg_e.forget()
        self.passw_label_e.forget()
        self.passw_input_e.forget()
        self.encode_btn_e.forget()
        if hasattr(self, 'sec_img_upload_btn_e'):
            self.sec_img_upload_btn_e.forget()
        if hasattr(self, 'sec_imaage_label_e'):
            self.sec_imaage_label_e.forget()
        if hasattr(self, 'encode_imagei_btn_e'):
            self.encode_imagei_btn_e.forget()

    def option(self, event):
        self.clear_option_widgets()
        if self.clikced.get() == 'Hide Text in Image':
            self.text_label_e.pack()
            self.text_input_msg_e.pack(pady=10)
            self.passw_label_e.pack()
            self.passw_input_e.pack(pady=10)
            self.encode_btn_e.pack(pady=20)
        elif self.clikced.get() == 'Hide Image in Image':
            self.sec_img_upload_btn_e.pack(pady=10)
            self.sec_imaage_label_e.pack(pady=10, padx=50)
            self.passw_label_e.pack()
            self.passw_input_e.pack(pady=10)
            self.encode_imagei_btn_e.pack(pady=20)
        else:
            self.clear_option_widgets()


                        

    def EncodeTextImage(self):
                    if self.original_img_e is None:
                        messagebox.showerror("Error", "Please upload an image first")
                        return
                    
                    secret_text = self.text_input_msg_e.get()
                    password = self.passw_input_e.get()
                    if not secret_text or not password:
                        messagebox.showerror("Error", "Secret text and password cannot be empty")
                        return

                    try:
                        compressed_text = zlib.compress(secret_text.encode())

                        encrypted_text = self.EncryptText(password, compressed_text)

                        delimiter = '\xFE'
                        full_text = encrypted_text + delimiter
                        binary_secret = ''.join(format(ord(c), '08b') for c in full_text)

                        img = self.original_img_e.convert('RGB')
                        data = np.array(img)
                        data_flat = data.flatten()

                        if len(binary_secret) > len(data_flat):
                            messagebox.showerror("Error", "Secret text too long for this image!")
                            return

                        for i in range(len(binary_secret)):
                            pixel_val = int(data_flat[i])
                            pixel_val = (pixel_val & ~1) | int(binary_secret[i])
                            data_flat[i] = np.uint8(pixel_val)

                        encoded_data = data_flat.reshape(data.shape)
                        encoded_img = Image.fromarray(encoded_data.astype('uint8'))

                        save_path = filedialog.asksaveasfilename(defaultextension=".png",filetypes=[("PNG files", "*.png")])

                        if save_path:
                            encoded_img.save(save_path)
                            messagebox.showinfo("Success", f"Secret encoded and saved at:\n{save_path}")
                            self.ResetPage()

                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to encode image: {str(e)}")

    def ResetPage(self): 
          self.original_img_e=None
          self.imaage_label_e.config(image='')

          self.text_input_msg_e.delete(0,tk.END)          
          self.text_label_e.forget()
          self.text_input_msg_e.forget()

          self.passw_input_e.delete(0,tk.END)
          self.passw_label_e.forget()
          self.passw_input_e.forget()
          self.encode_btn_e.forget()




    def EncryptText(self, password, plaintext_bytes):
                    salt = get_random_bytes(16)
                    key = PBKDF2(password, salt, dkLen=32)
                    cipher = AES.new(key, AES.MODE_GCM)
                    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)

                    encrypted = salt + cipher.nonce + tag + ciphertext
                    return base64.b64encode(encrypted).decode()

                 

class DecodePage(tk.Frame):
      def __init__(self, master, controller):
        super().__init__(master, bg="white")
        
        self.controller = controller
        
        tk.Label(self, text='Decode Image', font=("Arial", 14), bg="white").pack(expand=True, padx=350)

        img_upload_btn_d = tk.Button(self, text='Upload a Image', command=self.ImageOpen)
        img_upload_btn_d.pack(pady=10)

        self.imaage_label_d = tk.Label(self, bg='white')
        self.imaage_label_d.pack(pady=10, padx=50)

        self.passw_label_d = tk.Label(self, text='Enter the password:')
        self.passw_label_d.pack(padx=20)
        self.passw_label_d.forget()

        self.passw_input_d = tk.Entry(self, bg="#f7f7f7")
        self.passw_input_d.pack(pady=10)
        self.passw_input_d.forget()

        self.decode_btn_d = tk.Button(self, text='Decode', bg='#e6e6e6', command=self.DecodeImage)
        self.decode_btn_d.pack()
        self.decode_btn_d.forget()
        

        self.original_img_d = None
        self.ResetPage()
      
 

      def ImageOpen(self):
                    file_path = filedialog.askopenfilename(
                        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
                    )
                    
                    if file_path:
                        img_d = Image.open(file_path)
                        img_d.thumbnail((300, 300))
                        self.original_img_d = img_d
                        self.tk_img_d = ImageTk.PhotoImage(img_d)
                        self.imaage_label_d.config(image=self.tk_img_d)
                       
                        self.passw_label_d.pack()
                        self.passw_input_d.pack(pady=10)

                        self.decode_btn_d.pack()

      def DecodeImage(self):
        if self.original_img_d is None:
            messagebox.showerror("Error", "Please upload an image first")
            return

        password=self.passw_input_d.get() 

        if not password:
              messagebox.showerror("Error", "Secret text and password cannot be empty")
              return
        try:
            img=self.original_img_d.convert('RGB')
            data=np.array(img)
            data_flat=data.flatten()

            bits=[]

            for i in range(len(data_flat)):
                  bits.append(str(data_flat[i] & 1))

            chars=[]

            for i in range(0,len(bits),8):
                  bytes=bits[i:i+8]

                  if len(bytes)<8:
                        break

                  char=chr(int(''.join(bytes),2))

                  if char=='\xFE':
                        break


                  chars.append(char) 

            encry_text=''.join(chars)    


            decry_bytes = self.DecryptText(password, encry_text)

            if not decry_bytes:
                  return
            
            decompressed_text=zlib.decompress(decry_bytes).decode()


            
            messagebox.showinfo("Decoded Text", f"Secret message:\n{decompressed_text}")
            self.ResetPage()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decode image: {str(e)}")



      def DecryptText(self,password,encrypted_text):
            try:
               encrypted = base64.b64decode(encrypted_text)
               salt=encrypted[:16]
               nonce=encrypted[16:32]
               tag=encrypted[32:48]
               ciphertext = encrypted[48:]



               key=PBKDF2(password, salt, dkLen=32)

               cipher=AES.new(key,AES.MODE_GCM, nonce=nonce)
               plaintext = cipher.decrypt_and_verify(ciphertext, tag)
               return plaintext
            
            except (ValueError,KeyError):
                messagebox.showerror("Error", "Incorrect password or corrupted data")
                return None
       

      
      def ResetPage(self):
          self.original_img_d=None
          self.imaage_label_d.config(image='')

          self.passw_input_d.delete(0,tk.END)          
          self.passw_input_d.forget()
          self.passw_label_d.forget()

          self.decode_btn_d.forget()

