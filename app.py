from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

app = Flask(__name__)

# ฟังก์ชันสำหรับสร้างคู่คีย์ RSA
def generate_keys(password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # ใช้รหัสผ่านในการเข้ารหัส private key
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )
    
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private_key, pem_public_key, base64.urlsafe_b64encode(salt)

# ฟังก์ชันสำหรับโหลดคีย์ส่วนตัวจาก PEM format
def load_private_key(pem_private_key, password, salt):
    salt = base64.urlsafe_b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    private_key = serialization.load_pem_private_key(
        pem_private_key.encode(),
        password=key,
    )
    return private_key

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
    return base64.urlsafe_b64encode(ciphertext)

# ฟังก์ชันสำหรับถอดรหัสข้อความ
def decrypt_rsa(private_key, ciphertext):
    ciphertext = base64.urlsafe_b64decode(ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']
        pem_private_key, pem_public_key, salt = generate_keys(password)
        
        return render_template('keys.html', private_key=pem_private_key.decode(), public_key=pem_public_key.decode(), salt=salt.decode())
    
    return render_template('index.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        pem_private_key = request.form['private_key']
        password = request.form['password']
        salt = request.form['salt']
        ciphertext = request.form['ciphertext']
        
        try:
            private_key = load_private_key(pem_private_key, password, salt)
            plaintext = decrypt_rsa(private_key, ciphertext)
            return render_template('decrypt.html', plaintext=plaintext.decode(), success=True)
        except Exception as e:
            return render_template('decrypt.html', error=str(e), success=False)
    
    return render_template('decrypt.html', success=False)

if __name__ == '__main__':
    app.run(debug=True)
