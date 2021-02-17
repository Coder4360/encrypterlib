class asymmetric:
    from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    def generate_key(size=4096):
        global default_backend, rsa
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
    def generate_public_key(key: _RSAPrivateKey):
        return key.public_key()
    def generate_private_bytes_from_key(key: _RSAPrivateKey):
        global serialization
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
            )
    def generate_public_bytes_from_key(key: _RSAPublicKey):
        global serialization
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    def generate_key_from_private_bytes(bytes: bytes):
        global default_backend, serialization
        return serialization.load_pem_private_key(
            bytes,
            password=None,
            backend=default_backend()
            )
    def generate_key_from_public_bytes(bytes: bytes):
        global default_backend, serialization
        return serialization.load_pem_public_key(
            bytes,
            backend=default_backend()
            )
    def decrypt(encrypted: bytes, private_key: _RSAPrivateKey):
        return private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
    def encrypt(bytes: bytes, public_key: _RSAPublicKey):
        return public_key.encrypt(
            bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
    #Code from https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

class symmetric:
    import base64
    import os
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    def generate_random_key():
        global Fernet
        return Fernet.generate_key()
    def generate_key_from_password(password: str):
        global PDFK2HMAC, hashes, default_backend
        password = password.encode()  # Convert to type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'?i\xfbI\xce\x03\x16\x19\x92X\x19)\x1fA\x9e\xd3',
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    def encrypt(message: str, password: str):
        global Fernet
        return Fernet(encrypter.generate_key_from_password(password)).encrypt(message.encode())
    def decrypt(encrypted_message: bytes, password: str):
        global Fernet
        return Fernet(encrypter.generate_key_from_password(password)).decrypt(encrypted_message).decode()
    #Code from https://www.thepythoncode.com/article/encrypt-decrypt-files-symmetric-python 
