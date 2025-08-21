## StegoDesk 

StegoDesk is a cross-platform desktop GUI for LSB steganography with AES-GCM encryption and streaming compression.

Users can hide text, images,arbitrary files or passwords inside cover images and extract them later using a password.

Features
--------
- Hide text in an image.

- Hide an image inside another image.

- Hide arbitrary files inside an image 

- Decode stego images and auto-detect the hidden payload type (text, PNG, JPG, PDF, etc..).

- Store/retrieve simple passwords/text inside images (without encryption).

Work-flow
---------
**Encode Image Page**
1. Upload a cover image in which you want to hide data.
2. Select  data type: Hide Text, Hide Image, or Hide Documents.
3. Enter password and click Encode, then save the generated   stego image and share it.

**Decode Image Page**
1. Upload a previously saved stego image.
2. Enter the password used during encoding and click Decode.
3. See/Save according to the type of data


**Encode/Decode Password Page**
1. Upload a cover or stego image.
2. Select Method: Encode Password / Decode Password and perform the action.
(Use this and store image only in your system because the passwords are not encrypted)


Architecture & functions
---------------------------
- **GUI layer (Tkinter):** DashboardPage, EncodePage, DecodePage, HidePasswordPage, handles previews, dialogs, and user work-flows.

- **Stego layer (stego.py):** Functions including `encrypt_bytes`, `decrypt_bytes`, `stream_compress_encrypt_to_file`, `decrypt_stream_file_to_output`. 

- **LSB embed/extract functions:** `embed_payload_from_file_to_cover`, `pass_embed_to_image`, `simple_extract_from_image`. 


Memory optimization techniques 
-------------------------------------
- **Streaming compress + encrypt to disk for large inputs.**  
  Files larger than the configured threshold are compressed and encrypted in chunks and written to a temporary file so the original file is not fully loaded into RAM.

- **Chunked embedding (32 KiB).**  
  `embed_payload_from_file_to_cover()` reads an encrypted temporary file in 32 KiB chunks and embeds each chunk into image LSBs.

- **Streaming decrypt → write to temporary file.**  
  The `decrypt_stream_file_to_output()` function decrypts and decompresses in chunks (streamed) to another temporary file rather than building one large bytes object.
  
-   #### The UI creates a small thumbnail for display to reduce preview memory.

#### Check out the App here: https://github.com/bbheemara/StegoDesk/releases/download/v1.0/StegoDesk.exe
