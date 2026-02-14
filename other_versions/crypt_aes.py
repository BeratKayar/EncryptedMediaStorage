from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

DELIMITER = b'#####'

# AES ENCRYPT
def aes_encrypt(message: bytes, password: str) -> bytes:
    key = password.encode("utf-8").ljust(32, b'\0')[:32]  # AES-256
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)
    return nonce + ciphertext

# AES DECRYPT
def aes_decrypt(data: bytes, password: str) -> bytes:
    key = password.encode("utf-8").ljust(32, b'\0')[:32]
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

# BYTES → BITS
def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{b:08b}' for b in data)

# BITS → BYTES
def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        out.append(int(''.join(byte), 2))
    return bytes(out)

# HIDE (ENCRYPT + LSB)
def hide(image_path, output_path, text, password):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    encrypted = aes_encrypt(text.encode("utf-8"), password) + DELIMITER
    bits = bytes_to_bits(encrypted)

    capacity = pixels.size
    if len(bits) > capacity:
        raise ValueError("The message is too long! Insufficient visual capacity.")

    idx = 0
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                if idx < len(bits):
                    pixels[i, j, k] = (pixels[i, j, k] & 0xFE) | int(bits[idx])
                    idx += 1

    Image.fromarray(pixels).save(output_path)
    print("[+] Encrypted with AES and hidden within the image.")

# REVEAL (LSB + DECRYPT)
def reveal(image_path, password):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    bits = []
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                bits.append(str(pixels[i, j, k] & 1))

    data = bits_to_bytes(bits)
    end = data.find(DELIMITER)

    if end == -1:
        raise ValueError("No private data found!")

    encrypted = data[:end]
    decrypted = aes_decrypt(encrypted, password)
    print("\n[+] Decrypted message:")
    print(decrypted.decode("utf-8", errors="replace"))

# MAIN
if __name__ == "__main__":
    mode = input("Choose mode (e = encrypt, d = decrypt): ").lower()

    if mode == "e":
        img_in = input("In visual (PNG): ")
        img_out = input("Out visual: ")
        text = input("Text to hide: ")
        password = input("AES password: ")
        hide(img_in, img_out, text, password)

    elif mode == "d":
        img = input("Crypted visual: ")
        password = input("AES password: ")
        reveal(img, password)

    else:
        print("Invalid mode!")
