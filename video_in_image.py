from PIL import Image
import numpy as np
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DELIMITER = b'ENDVID'  # marker to detect end of hidden video

# ---------- AES ENCRYPTION / DECRYPTION ----------
def aes_encrypt(data: bytes, password: str) -> bytes:
    # prepare 32-byte key for AES-256
    key = password.encode('utf-8').ljust(32, b'\0')[:32]
    aes = AESGCM(key)
    nonce = os.urandom(12)  # random nonce for AES-GCM
    ciphertext = aes.encrypt(nonce, data, None)
    return nonce + ciphertext

def aes_decrypt(data: bytes, password: str) -> bytes:
    key = password.encode('utf-8').ljust(32, b'\0')[:32]
    aes = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aes.decrypt(nonce, ciphertext, None)

# ---------- BYTE/BIT CONVERSIONS ----------
def bytes_to_bits(data: bytes) -> str:
    # convert each byte to 8-bit string
    return ''.join(f'{b:08b}' for b in data)

def bits_to_bytes(bits):
    # convert 8-bit chunks back to bytes
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        byte_str = ''.join(str(b) for b in byte_bits)
        out.append(int(byte_str, 2))
    return out

# ---------- LSB STEGANOGRAPHY ----------
def hide_video(image_path, video_path, output_image, password):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    with open(video_path, "rb") as f:
        video_bytes = f.read()

    # encrypt video with AES before hiding
    encrypted = aes_encrypt(video_bytes, password) + DELIMITER
    bits = bytes_to_bits(encrypted)

    # calculate LSB capacity
    capacity_bits = pixels.size
    capacity_mb = capacity_bits / 8 / 1024 / 1024
    print(f"[+] Image LSB capacity: {capacity_mb:.2f} MB")
    print(f"[+] Video size: {len(video_bytes) / 1024 / 1024:.2f} MB")

    if len(bits) > capacity_bits:
        raise ValueError("Video does NOT fit inside this image (LSB capacity exceeded).")

    # hide bits in LSB of pixels
    idx = 0
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                if idx < len(bits):
                    pixels[i, j, k] = (pixels[i, j, k] & 0xFE) | int(bits[idx])
                    idx += 1

    Image.fromarray(pixels).save(output_image)
    print("[+] Video successfully encrypted and hidden inside image.")

def extract_video(image_path, output_video, password):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    # extract LSBs from pixels
    bits = []
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                bits.append(str(pixels[i, j, k] & 1))

    data = bits_to_bytes(bits)
    end = data.find(DELIMITER)

    if end == -1:
        raise ValueError("No hidden video found.")

    encrypted = data[:end]

    # decrypt video using AES password
    video_data = aes_decrypt(encrypted, password)

    with open(output_video, "wb") as f:
        f.write(video_data)

    print("[+] Video decrypted and extracted successfully.")

# ---------- MAIN ----------
if __name__ == "__main__":
    mode = input("Mode (e=embed, d=decode): ").lower()

    if mode == "e":
        img = input("Cover image (PNG): ")
        vid = input("Video file: ")
        out = input("Output image: ")
        password = input("AES password: ")
        hide_video(img, vid, out, password)

    elif mode == "d":
        img = input("Stego image: ")
        out = input("Recovered video name: ")
        password = input("AES password: ")
        extract_video(img, out, password)
