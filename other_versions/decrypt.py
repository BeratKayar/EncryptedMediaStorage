from PIL import Image
import numpy as np

# XOR decryption
def xor_decrypt(data: bytes, key: bytes) -> bytes:
    decrypted = bytearray()
    for i in range(len(data)):
        decrypted.append(data[i] ^ key[i % len(key)])
    return bytes(decrypted)

# Extract bits from image
def extract_data(image_path, key):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    bits = []

    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):  # R, G, B
                bits.append(str(pixels[i, j, k] & 1))

    # Convert bits to bytes
    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        bytes_data.append(int(''.join(byte), 2))

    # Look for delimiter
    delimiter = b'#####'
    delimiter_index = bytes_data.find(delimiter)

    if delimiter_index == -1:
        raise ValueError("There is no hidden message in the image.")

    encrypted_bytes = bytes_data[:delimiter_index]

    key_bytes = key.encode("utf-8")
    decrypted_bytes = xor_decrypt(encrypted_bytes, key_bytes)

    return decrypted_bytes.decode("utf-8", errors="replace")

# MAIN
if __name__ == "__main__":
    image_path = "encrypted_image.png"
    key = input("Enter XOR key: ")

    message = extract_data(image_path, key)
    print("\n[+] Decrypted message: ")
    print(message)
