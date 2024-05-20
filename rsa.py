from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ฟังก์ชันสำหรับสร้างคู่คีย์ RSA และแปลงเป็น PEM format
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private_key, pem_public_key

# ฟังก์ชันสำหรับโหลดคีย์ส่วนตัวจาก PEM format
def load_private_key(pem_private_key):
    return serialization.load_pem_private_key(
        pem_private_key,
        password=None,
    )

# ฟังก์ชันสำหรับโหลดคีย์สาธารณะจาก PEM format
def load_public_key(pem_public_key):
    return serialization.load_pem_public_key(
        pem_public_key,
    )

# ฟังก์ชันสำหรับเข้ารหัสข้อความ
def encrypt_rsa(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# ฟังก์ชันสำหรับถอดรหัสข้อความ
def decrypt_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# การใช้งาน
pem_private_key, pem_public_key = generate_keys()
private_key = load_private_key(pem_private_key)
public_key = load_public_key(pem_public_key)

# แสดงคีย์เพื่อให้คุณนำไปใช้ในการเข้ารหัสและถอดรหัส
print(f'Private Key:\n{pem_private_key.decode()}')
print(f'Public Key:\n{pem_public_key.decode()}')

plaintext = b'Hello, World! This is a test message.'

# เข้ารหัส
ciphertext = encrypt_rsa(public_key, plaintext)
print(f'Ciphertext: {ciphertext.hex()}')

# ถอดรหัส
try:
    decrypted_plaintext = decrypt_rsa(private_key, ciphertext)
    print(f'Decrypted Plaintext: {decrypted_plaintext.decode()}')
    print("ถอดรหัสสำเร็จ!")
except Exception as e:
    print(f'ถอดรหัสล้มเหลว: {str(e)}')
