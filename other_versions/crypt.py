from PIL import Image
import numpy as np

# XOR encryption
def xor_encrypt(data: bytes, key: bytes) -> bytes:
    encrypted = bytearray()
    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % len(key)])
    return bytes(encrypted)

# Convert bytes to bit string
def bytes_to_bits(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

# Hide data in image using LSB
def hide_data(image_path, output_path, secret_text, key):
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img)

    secret_bytes = secret_text.encode("utf-8")
    key_bytes = key.encode("utf-8")

    encrypted_bytes = xor_encrypt(secret_bytes, key_bytes)

    delimiter = b'#####'
    encrypted_bytes += delimiter

    bit_string = bytes_to_bits(encrypted_bytes)
    capacity = pixels.size

    if len(bit_string) > capacity:
        raise ValueError("The message is too long! Insufficient visual capacity.")

    bit_index = 0

    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):  # R, G, B
                if bit_index < len(bit_string):
                    pixels[i, j, k] = (pixels[i, j, k] & 0xFE) | int(bit_string[bit_index])
                    bit_index += 1

    encoded_img = Image.fromarray(pixels)
    encoded_img.save(output_path)

    print("[+] Message successfully hidden.")

# MAIN
if __name__ == "__main__":
    image_path = "sea lion.png"
    output_path = "encrypted_image.png"

    secret_text = input("Enter message to hide: ")
    key = input("Enter XOR key: ")

    hide_data(image_path, output_path, secret_text, key)
