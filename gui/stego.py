from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import tempfile
import os
import zlib


PBKDF2_ITERS = 100_000

"""
This Function is used to embed a password without a protection password using LSB method by iterating through each pixel of the image
and changing its pixel value
"""
def pass_embed_to_image(img, secret_pass):
    payload = len(secret_pass).to_bytes(4, 'big') + secret_pass.encode('utf-8')
    data = np.array(img)  
    flat = data.ravel()

    total_bits = len(payload) * 8

    if total_bits > flat.size:
        raise ValueError("Secret too large for this image!")

    idx = 0

    for b in payload:
        for bits_pos in range(7, -1, -1):
            bit = (b >> bits_pos) & 1
            flat[idx] = (int(flat[idx]) & 0xFE) | bit

            idx += 1

    return Image.fromarray(data.astype("uint8"))  

#This Function is used to extract the password from the image 
def simple_extract_from_image(img):
  
    data = np.array(img).flatten()
    all_bytes = bytearray()
    current_byte = 0
    bits_collected = 0
    total_len = None  

    for i in range(len(data)):
        bit = int(data[i]) & 1
        current_byte = (current_byte << 1) | bit
        bits_collected += 1

        if bits_collected == 8:
            all_bytes.append(current_byte & 0xFF)
            current_byte = 0
            bits_collected = 0

            if len(all_bytes) >= 4 and total_len is None:
                total_len = int.from_bytes(all_bytes[:4], "big")
                if total_len < 0 or total_len > 10 * 1024 * 1024:
                    raise ValueError("Invalid payload length.")

            if total_len is not None and len(all_bytes) >= 4 + total_len:
                break

    if total_len is None:
        raise ValueError("No payload length found.")

    payload_bytes = bytes(all_bytes[4:4 + total_len])
    return payload_bytes.decode("utf-8", errors="replace")


# Takes input and returns true/false if the input is text/ASCII UTF-8 or not
def looks_like_text(data):
    try:
        s = data.decode("utf-8")
    except Exception:
        return False

    for ch in s:
        code = ord(ch)
        if code in (9, 10, 13):
            continue
        if not (32 <= code <= 126):
            return False

    return True

#Used to detect data type while decoding the image and save is as its's extension
def detect_file_type(data):
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"

    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return "jpg"

    if len(data) >= 4 and data[:4] == b"%PDF":
        return "pdf"

    if len(data) >= 4 and data[:4] == b"PK\x03\x04":
        return "docx"

    if looks_like_text(data):
        return "text"

    return "unknown"


#encrypts plain text with password protection Using AES, derives a key from the password using PBKDF2 + random salt, uses AES-GCM with a 12-byte nonce
def encrypt_bytes(password, plaintext_bytes):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERS)
    nonce = get_random_bytes(12)  
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return salt + nonce + ciphertext + tag

#decrypts the encrypted bytes by checking password
def decrypt_bytes(password, encrypted_bytes):
    if len(encrypted_bytes) < 16 + 12 + 16:
        raise ValueError("Encrypted payload too short.")
    salt = encrypted_bytes[:16]
    nonce = encrypted_bytes[16:28]
    tag = encrypted_bytes[-16:]
    ciphertext = encrypted_bytes[28:-16]
    key = PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERS)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag) 
    return plaintext

#for input files, compress and encrypt in a streaming way and save to a temporary file, optimizes the RAM usage by avoiding reading the whole file into RAM 
def stream_compress_encrypt_to_file(input_path, password, compress_level=6):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERS)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    comp = zlib.compressobj(level=compress_level)
    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp.write(salt)
        tmp.write(nonce)

        with open(input_path, "rb") as inf:
            while True:
                chunk = inf.read(64 * 1024)  
                if not chunk:
                    break
                comp_chunk = comp.compress(chunk)
                if comp_chunk:
                    enc = cipher.encrypt(comp_chunk)
                    tmp.write(enc)

            tail = comp.flush()
            if tail:
                tmp.write(cipher.encrypt(tail))

        tag = cipher.digest()
        tmp.write(tag)
        tmp.flush()
        tmp.close()
        return tmp.name
    except Exception:
        try:
            tmp.close()
            os.unlink(tmp.name)
        except Exception:
            pass
        raise

"""
embeds the whole encrypted file provided by stream_compress_encrypt_to_file funtion into LSBs of a image,
Stream-read the encrypted file in chunks (32 KiB) to avoid reading the entire file at once in memory
"""
def embed_payload_from_file_to_cover(img, encrypted_file_path):
    file_size = os.path.getsize(encrypted_file_path)
    payload_len_bytes = file_size.to_bytes(4, "big")

    data = np.array(img, dtype=np.uint8, copy=True)  
    flat = data.ravel()

    total_bits_needed = (4 + file_size) * 8

    if total_bits_needed > flat.size:
        raise ValueError("Secret too large for this image!")

    write_index = 0

    def write_byte_as_bits(byte_val):
        nonlocal write_index
        for bitpos in range(7, -1, -1):
            bit = (byte_val >> bitpos) & 1
            flat[write_index] = (int(flat[write_index]) & 0xFE) | bit
            write_index += 1

    for b in payload_len_bytes:
        write_byte_as_bits(b)

    with open(encrypted_file_path, "rb") as f:
        while True:
            chunk = f.read(32 * 1024)
            if not chunk:
                break
            for b in chunk:
                write_byte_as_bits(b)

    encoded = data.reshape(data.shape)
    return Image.fromarray(encoded.astype("uint8"))

#reverse process of stream_compress_encrypt_to_file, decompress and write to out_path
def decrypt_stream_file_to_output(encrypted_file_path, password, out_path):
    filesize = os.path.getsize(encrypted_file_path)
    if filesize < 16 + 12 + 16:
        raise ValueError("Encrypted file too short.")

    with open(encrypted_file_path, "rb") as inf:
        salt = inf.read(16)
        nonce = inf.read(12)
        ciphertext_len = filesize - (16 + 12 + 16)
        key = PBKDF2(password, salt, dkLen=32, count=PBKDF2_ITERS)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decompressor = zlib.decompressobj()

        bytes_remaining = ciphertext_len
        chunk_size = 64 * 1024

        with open(out_path, "wb") as outf:
            while bytes_remaining > 0:
                read_size = min(chunk_size, bytes_remaining)
                chunk = inf.read(read_size)
                if not chunk:
                    raise EOFError("Unexpected EOF while reading ciphertext.")
                plain_chunk = cipher.decrypt(chunk)
                if plain_chunk:
                    dec = decompressor.decompress(plain_chunk)
                    if dec:
                        outf.write(dec)
                bytes_remaining -= len(chunk)

            tag = inf.read(16)
            tail = decompressor.flush()
            if tail:
                outf.write(tail)

        cipher.verify(tag)