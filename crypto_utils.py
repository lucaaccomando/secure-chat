from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hashlib
import os


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None)


def generate_ecdh_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()

def serialize_ecdh_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_ecdh_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

def derive_shared_key(my_ecdh_private, peer_ecdh_public):
    raw = my_ecdh_private.exchange(ec.ECDH(), peer_ecdh_public)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure-chat v3'
    ).derive(raw)


def generate_aes_key():
    return os.urandom(32)


# GCM: nonce (12) + tag (16) + ciphertext
def aes_encrypt_gcm(plaintext, key):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(plaintext.encode('utf-8')) + enc.finalize()
    return nonce + enc.tag + ciphertext

def aes_decrypt_gcm(data, key):
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    dec = cipher.decryptor()
    return (dec.update(ciphertext) + dec.finalize()).decode('utf-8')


# CBC kept for benchmarks only
def aes_encrypt_cbc(plaintext, key):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()

def aes_decrypt_cbc(data, key):
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')


def aes_encrypt(plaintext, key, mode='gcm'):
    if mode == 'gcm':
        return aes_encrypt_gcm(plaintext, key)
    return aes_encrypt_cbc(plaintext, key)

def aes_decrypt(data, key, mode='gcm'):
    if mode == 'gcm':
        return aes_decrypt_gcm(data, key)
    return aes_decrypt_cbc(data, key)


def encrypt_key_with_rsa(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_key_with_rsa(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def sign_message(message_bytes, private_key):
    return private_key.sign(
        message_bytes,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(message_bytes, signature_bytes, public_key):
    try:
        public_key.verify(
            signature_bytes,
            message_bytes,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# sha256 fingerprint of a public key, colon-separated hex (ssh style)
def key_fingerprint(public_key):
    digest = hashlib.sha256(serialize_public_key(public_key)).digest()
    return ':'.join(f'{b:02x}' for b in digest)
