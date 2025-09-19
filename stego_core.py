from PIL import Image
from cryptography.fernet import Fernet

# ---------- ENCRYPTION HELPERS ----------
def generate_key():
    return Fernet.generate_key()

def encrypt_message(message: str, key: bytes) -> str:
    return Fernet(key).encrypt(message.encode()).decode()

def decrypt_message(message: str, key: bytes) -> str:
    return Fernet(key).decrypt(message.encode()).decode()

# ---------- STEGANOGRAPHY ----------
def encode_image(input_path: str, message: str, output_path: str):
    img = Image.open(input_path)
    encoded = img.copy()
    w, h = img.size

    data = message.encode("utf-8")
    length = len(data)
    binary = ''.join(format(byte, '08b') for byte in length.to_bytes(4, "big") + data)

    index = 0
    for y in range(h):
        for x in range(w):
            pixel = list(img.getpixel((x, y)))
            for n in range(3):
                if index < len(binary):
                    pixel[n] = (pixel[n] & ~1) | int(binary[index])
                    index += 1
            encoded.putpixel((x, y), tuple(pixel))
            if index >= len(binary):
                encoded.save(output_path)
                return True
    raise ValueError("Message too long for image")

def decode_image(path: str) -> str:
    img = Image.open(path)
    w, h = img.size

    bits = ""
    for y in range(h):
        for x in range(w):
            for n in range(3):
                bits += str(img.getpixel((x, y))[n] & 1)

    # Convert bits to bytes, but only process what we need
    all_bytes = [bits[i:i+8] for i in range(0, len(bits), 8)]
    
    # Check if we have enough bits for a valid message (at least 4 bytes for length)
    if len(all_bytes) < 4:
        raise ValueError("Image does not contain a valid steganographic message")
    
    try:
        # Read the first 32 bits (4 bytes) as the length
        length_bits = "".join(all_bytes[:4])
        length = int(length_bits, 2)
    except (ValueError, IndexError):
        raise ValueError("Image does not contain a valid steganographic message")
    
    # More reasonable length validation - check against image capacity
    max_capacity = (w * h * 3) // 8 - 4  # Subtract 4 bytes for length header
    if length < 0 or length > max_capacity:
        raise ValueError("Image does not contain a valid steganographic message")
    
    if len(all_bytes) < 4 + length:
        raise ValueError("Image does not contain complete message data")
    
    # Extract message bytes (skip the first 4 bytes which contain the length)
    message_bytes = [int(b, 2) for b in all_bytes[4:4 + length]]
    
    # Decode and return the message
    if length > 0:
        try:
            decoded_text = bytes(message_bytes).decode("utf-8")
            return decoded_text
        except UnicodeDecodeError as e:
            # Try with error handling for partial data
            try:
                return bytes(message_bytes).decode("utf-8", errors="replace")
            except:
                raise ValueError(f"Message contains invalid UTF-8 data: {str(e)}")
    
    raise ValueError("Image does not contain a valid steganographic message")
