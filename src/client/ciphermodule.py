"""
encryption.py
Implements secure private messaging with:
- Ephemeral ECDH per message for forward secrecy
- AES-256-GCM for encryption + integrity
- Permanent ECC keys for identity

"""

from Crypto.PublicKey import ECC, DSA           # Key generation & management
from Crypto.Cipher import AES                   # Symmetric encryption  
from Crypto.Protocol.KDF import HKDF, PBKDF2    # Key derivation
from Crypto.Hash import SHA256                  # Hashing for signatures
from Crypto.Signature import DSS                # Digital signature operations
import base64                                   # Binary data encoding
import json                                     # Data structure serialization
import time                                     # Timestamps

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
    # PEM is a standard base64-encoded text format for keys


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

    # HKDF to derive AES key (will always produce same value for same inputs)
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
# Derive a 256-bit AES key from a password and salt
# ============================================================
def derive_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    return PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=None)

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


# ============================================================
# DSA Digital Signatures 
# ============================================================

def generate_dsa_keypair():
    """Generate DSA key pair (1024-bit for speed)."""
    # Create a new DSA key with 1024-bit length (faster than 2048-bit)
    key = DSA.generate(1024)
    
    # Export both private and public keys in PEM format (text-based)
    private_pem = key.export_key(format='PEM')          # Private key for signing
    public_pem = key.public_key().export_key(format='PEM')  # Public key for verification
    
    # Ensure they are strings, not bytes
    if isinstance(private_pem, bytes):
        private_pem = private_pem.decode('utf-8')
    if isinstance(public_pem, bytes):
        public_pem = public_pem.decode('utf-8')
    
    return private_pem, public_pem


def sign_message(message, private_key_pem):
    """Sign message with DSA private key."""
    # Load the DSA private key from PEM string
    private_key = DSA.import_key(private_key_pem)
    
    # Create SHA256 hash of the message (DSA signs hashes, not raw text)
    hash_obj = SHA256.new(message.encode('utf-8'))
    
    # Create DSA signer using FIPS 186-3 standard
    signer = DSS.new(private_key, 'fips-186-3')
    
    # Generate the digital signature
    signature = signer.sign(hash_obj)
    
    # Return signature encoded in Base64 for easy transmission
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(message, signature_b64, public_key_pem):
    """Verify DSA signature."""
    try:
        # Load the DSA public key from PEM string
        public_key = DSA.import_key(public_key_pem)
        
        # Decode the Base64 signature back to raw bytes
        signature = base64.b64decode(signature_b64)
        
        # Create the same SHA256 hash of the original message
        hash_obj = SHA256.new(message.encode('utf-8'))
        
        # Create DSA verifier using same FIPS 186-3 standard
        verifier = DSS.new(public_key, 'fips-186-3')
        
        # Verify signature matches the hash
        verifier.verify(hash_obj, signature)
        
        # If we reach here, signature is valid
        return True
    
    except:
        # Any exception means signature is invalid
        return False

# ============================================================
# Combined Operations (Integration Functions)
# ============================================================

def encrypt_and_sign_for_user(message, recipient_ecc_pub_pem, sender_dsa_priv_pem):
    """
    Complete secure messaging: Sign with DSA + Encrypt with ECC DH + AES
    
    This combines all three assignment requirements:
    ✓ AES for symmetric encryption
    ✓ ECC DH for key exchange  
    ✓ DSA for digital signatures
    
    Process:
    1. Sign the original message with DSA private key
    2. Create signed payload (message + signature + timestamp)
    3. Encrypt signed payload using your existing encrypt_for_user()
    """
    # Step 1: Sign the original message
    signature = sign_message(message, sender_dsa_priv_pem)
    
    # Step 2: Create signed payload with timestamp
    signed_payload = {
        'message': message,
        'signature': signature,
        'timestamp': time.time()
    }
    
    # Step 3: Convert to JSON and encrypt using your existing function
    signed_payload_json = json.dumps(signed_payload)
    encrypted_package = encrypt_for_user(signed_payload_json, recipient_ecc_pub_pem)
    
    # Step 4: Mark as secure message
    encrypted_package['type'] = 'secure_message'
    
    return encrypted_package

def decrypt_and_verify_received(payload, recipient_ecc_priv_pem, sender_dsa_pub_pem):
    """
    Complete secure receiving: Decrypt with ECC DH + AES + Verify DSA signature
    
    Process:
    1. Decrypt payload using your existing decrypt_received()
    2. Parse the signed payload (JSON)
    3. Verify the DSA signature
    
    Returns: (message, signature_valid, timestamp)
    """
    try:
        # Step 1: Decrypt using your existing function
        decrypted_json = decrypt_received(payload, recipient_ecc_priv_pem)
        
        # Step 2: Parse the signed payload. Taking the JSON string and converting it back to Python dictionary
        signed_payload = json.loads(decrypted_json)
        
        # Step 3: Verify the DSA signature
        is_signature_valid = verify_signature(
            signed_payload['message'],
            signed_payload['signature'],
            sender_dsa_pub_pem
        )
        
        # Step 4: Return results
        return (
            signed_payload['message'],
            is_signature_valid,
            signed_payload.get('timestamp')
        )
        
    except Exception as e:
        print(f"Decryption/verification error: {e}")
        return None, False, None

def generate_user_keypairs():
    """
    Generate both ECC and DSA key pairs for a user.
    
    Returns: Dictionary with all 4 keys needed for secure messaging
    """
    ecc_private, ecc_public = generate_ecc_keypair()
    dsa_private, dsa_public = generate_dsa_keypair()
    
    return {
        'ecc_private': ecc_private,
        'ecc_public': ecc_public,
        'dsa_private': dsa_private,
        'dsa_public': dsa_public
    }

# ============================================================
# Test Function for checking (not necessary, can delete later on)
# ============================================================

def test_complete_crypto():
    """Test all crypto functions working together."""
    # Generate keys
    alice_keys = generate_user_keypairs()
    bob_keys = generate_user_keypairs()
    
    # Alice sends secure message to Bob
    message = "Secret meeting at 3pm!"
    secure_msg = encrypt_and_sign_for_user(
        message,
        bob_keys['ecc_public'],
        alice_keys['dsa_private']
    )
    
    # Bob receives and verifies
    decrypted, signature_valid, timestamp = decrypt_and_verify_received(
        secure_msg,
        bob_keys['ecc_private'],
        alice_keys['dsa_public']
    )
    
    # Results
    print(f"Original: {message}")
    print(f"Decrypted: {decrypted}")
    print(f"Signature valid: {signature_valid}")
    print(f"Test result: {'PASS' if decrypted == message and signature_valid else 'FAIL'}")

if __name__ == "__main__":
    test_complete_crypto()