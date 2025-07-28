"""
encryption.py
Implements secure private messaging with:
- Ephemeral ECDH per message for forward secrecy
- AES-256-GCM for encryption + integrity
- Permanent ECC keys for identity

"""

from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import base64

# ============================================================
# Permanent ECC Key Management
# ============================================================

def generate_ecc_keypair():
    """
    Generate a permanent ECC key pair (P-256 curve).
    Returns: (private_key_pem, public_key_pem)
    """
    key = ECC.generate(curve='P-256')
    return key.export_key(format='PEM'), key.public_key().export_key(format='PEM')


def import_private_key(pem):
    """Load ECC private key from PEM data."""
    return ECC.import_key(pem)


def import_public_key(pem):
    """Load ECC public key from PEM data."""
    return ECC.import_key(pem)

# ============================================================
# Shared Secret Derivation (ECDH + HKDF)
# ============================================================

def derive_shared_key(my_private, peer_public):
    """
    Compute AES key using ECDH shared secret and HKDF-SHA256.
    Args:
        my_private: ECC private key object
        peer_public: ECC public key object
    Returns:
        bytes: 32-byte AES key
    """
    # ECDH scalar multiplication
    shared_point = my_private.d * peer_public.pointQ
    shared_secret = int(shared_point.x).to_bytes(32, 'big')

    # HKDF to derive AES key
    return HKDF(shared_secret, 32, b'', SHA256)

# ============================================================
# AES-256-GCM Encryption / Decryption
# ============================================================

def aes_encrypt(message, key):
    """Encrypt message using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, ciphertext, tag


def aes_decrypt(nonce, ciphertext, tag, key):
    """Decrypt message using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# ============================================================
# High-Level Functions (Ephemeral ECDH per message)
# ============================================================

def encrypt_for_user(message, recipient_pub_pem):
    """
    Encrypt a message for recipient using:
    1. Generate ephemeral ECC key pair
    2. Derive AES key (ephemeralPriv + recipientPub)
    3. Encrypt with AES-256-GCM
    4. Include ephemeral public key in payload

    Returns: payload dict (Base64 fields)
    """
    # Import recipient's permanent public key
    recipient_pub = import_public_key(recipient_pub_pem)

    # Generate ephemeral key pair for this message
    ephemeral_priv = ECC.generate(curve='P-256')
    ephemeral_pub_pem = ephemeral_priv.public_key().export_key(format='PEM')


    # Derive shared AES key
    aes_key = derive_shared_key(ephemeral_priv, recipient_pub)

    # Encrypt message
    nonce, ciphertext, tag = aes_encrypt(message, aes_key)

    # Return Base64 encoded payload + ephemeral pub key
    return {
        "ephemeral_pub": base64.b64encode(ephemeral_pub_pem.encode()).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_received(payload, my_priv_pem):
    """
    Decrypt received message using:
    1. Extract sender's ephemeral public key from payload
    2. Derive AES key (myPriv + ephemeralPub)
    3. Decrypt ciphertext
    """
    # Load my private key
    my_priv = import_private_key(my_priv_pem)

    # Decode fields
    ephemeral_pub_pem = base64.b64decode(payload["ephemeral_pub"]).decode()
    ephemeral_pub = import_public_key(ephemeral_pub_pem)
    nonce = base64.b64decode(payload["nonce"])
    tag = base64.b64decode(payload["tag"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    # Derive AES key
    aes_key = derive_shared_key(my_priv, ephemeral_pub)

    # Decrypt
    return aes_decrypt(nonce, ciphertext, tag, aes_key)
