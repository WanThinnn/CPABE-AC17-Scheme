import base64
import os

def generate_random_base64(length):
    random_bytes = os.urandom(length)
    return base64.b64encode(random_bytes).decode('utf-8')

def generate_random_hex(length):
    return os.urandom(length).hex()

def main():
    base64_str = generate_random_base64(32)  # Tạo chuỗi Base64 ngẫu nhiên
    hex_str = generate_random_hex(16)  # Tạo chuỗi HEX ngẫu nhiên
    base64_len = len(base64_str)

    with open('output.txt', 'w') as f:
        f.write(f"{base64_str} {hex_str} {base64_len}")

if __name__ == "__main__":
    main()
