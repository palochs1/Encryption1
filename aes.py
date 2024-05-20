from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# ฟังก์ชันสำหรับการเข้ารหัส
def encrypt_aes(key, plaintext):
    iv = os.urandom(16)  # สร้างค่า IV (Initialization Vector) ขนาด 16 ไบต์
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding ข้อความให้มีความยาวที่เป็นไปตามบล็อกของ AES (16 ไบต์)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# ฟังก์ชันสำหรับการถอดรหัส
def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]  # แยกค่า IV จากข้อความที่เข้ารหัส
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext

# ตัวอย่างการใช้งาน
key = os.urandom(32)  # สร้างคีย์ขนาด 32 ไบต์ (256 บิต)
plaintext = b'Hello, World! This is a test message.'  # ข้อความที่ต้องการเข้ารหัส

# เข้ารหัส
ciphertext = encrypt_aes(key, plaintext)
print(f'Ciphertext: {ciphertext.hex()}')

# ถอดรหัส
decrypted_plaintext = decrypt_aes(key, ciphertext)
print(f'Decrypted Plaintext: {decrypted_plaintext.decode()}')
