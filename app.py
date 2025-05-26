from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)
CORS(app)

# Key Generation
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_public_key = rsa_private_key.public_key()
aes_key = os.urandom(32)  # AES-256
dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
dh_private_key = dh_parameters.generate_private_key()
dh_public_key = dh_private_key.public_key()
peer_private_key = dh_parameters.generate_private_key()
peer_public_key = peer_private_key.public_key()
shared_key = dh_private_key.exchange(peer_public_key)
dh_shared_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)

# Key export
rsa_private = rsa_private_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
).decode()

rsa_public = rsa_public_key.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

dh_private = dh_private_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()

dh_public = dh_public_key.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

aes_key_b64 = base64.b64encode(aes_key).decode()
dh_shared_b64 = base64.b64encode(dh_shared_key).decode()

# Encrypt functions
def encrypt_with_rsa(message: str) -> str:
    encrypted = rsa_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def encrypt_with_aes(message: str, key: bytes) -> str:
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

# API endpoints
@app.route('/generate-keys', methods=['GET'])
def get_keys():
    return jsonify({
        'rsa': {
            'public_key': rsa_public,
            'private_key': rsa_private
        },
        'aes': {
            'key': aes_key_b64
        },
        'dh': {
            'public_key': dh_public,
            'private_key': dh_private,
            'shared_secret': dh_shared_b64
        }
    })

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data.get('message', '')
    method = data.get('method', '').lower()

    if not message or method not in ['rsa', 'aes', 'dh']:
        return jsonify({'error': 'Invalid input'}), 400

    try:
        if method == 'rsa':
            encrypted = encrypt_with_rsa(message)
        elif method == 'aes':
            encrypted = encrypt_with_aes(message, aes_key)
        elif method == 'dh':
            encrypted = encrypt_with_aes(message, dh_shared_key)
        else:
            return jsonify({'error': 'Unsupported method'}), 400

        return jsonify({'encrypted': encrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/")
def serve_index():
    return send_from_directory('.', 'echo_shield_modern_full.html')

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=10000)
