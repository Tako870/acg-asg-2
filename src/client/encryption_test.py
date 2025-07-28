"""This script simulates a secure message exchange between Alice and Bob using ECC for key exchange and AES for encryption.
It demonstrates the generation of permanent ECC keys, encryption of a message using an ephemeral key, and decryption by the recipient."""

from ciphermodule import generate_ecc_keypair, encrypt_for_user, decrypt_received
import base64

# STEP 1: Generate permanent ECC key pairs for Alice and Bob
print("\n=== STEP 1: Generate Permanent ECC Key Pairs ===")
alice_priv, alice_pub = generate_ecc_keypair()
bob_priv, bob_pub = generate_ecc_keypair()

print("[Alice] Permanent Private Key:\n", alice_priv)
print("[Alice] Permanent Public Key:\n", alice_pub)
print("[Bob] Permanent Private Key:\n", bob_priv)
print("[Bob] Permanent Public Key:\n", bob_pub)

# STEP 2: Alice wants to send a secure message to Bob
message = "Hello Bob! Secure message."
print("\n=== STEP 2: Alice Encrypts a Message for Bob ===")
print("[Alice] Message to send:", message)

# Encrypt message using Alice's ephemeral key and Bob's permanent public key
payload = encrypt_for_user(message, bob_pub)

print("\n[Encryption Payload Sent Over Network]:")
print("Full Ephemeral Public Key PEM:\n", base64.b64decode(payload["ephemeral_pub"]).decode())
print("Nonce (Base64):", payload["nonce"])
print("Tag (Base64):", payload["tag"])
print("Ciphertext (Base64):", payload["ciphertext"])

# STEP 3: Bob receives the payload and decrypts it
print("\n=== STEP 3: Bob Decrypts the Message ===")
decrypted_message = decrypt_received(payload, bob_priv)

# Show intermediate details
ephemeral_pub_decoded = base64.b64decode(payload["ephemeral_pub"]).decode()
print("[Bob] Received Alice's Ephemeral Public Key:\n", ephemeral_pub_decoded)
print("[Bob] Using his permanent private key to derive shared AES key...")
print("[Bob] Nonce:", payload["nonce"])
print("[Bob] Tag:", payload["tag"])
print("[Bob] Ciphertext:", payload["ciphertext"])

print("\n[Bob] Decrypted Message:", decrypted_message)

# STEP 4: Confirm correctness
print("\n=== RESULT ===")
print("Original Message:", message)
print("Decrypted Message:", decrypted_message)
print("Match:", message == decrypted_message)
