# Needed to connect to a server and send/receive messages
import socket
# Needed for threading to handle simultaneous sending and receiving of messages
import threading
# needed for command line arguments and printing messages
import sys
# Import our cryptographic functions
from Crypto.Random import get_random_bytes
from ciphermodule import generate_user_keypairs, encrypt_and_sign_for_user, decrypt_and_verify_received, derive_key, aes_decrypt, aes_encrypt
# For JSON handling and file operations
import json
import os
import base64
# Global variables for cryptographic keys
user_keys = None
other_users_public_keys = {}  # username -> {'ecc_public': key, 'dsa_public': key}


def load_or_generate_keys(username: str, password: str):
    """
    Load existing encrypted keys (decrypting with password) or generate new ones,
    encrypt with password-derived key, and save to disk.
    """

    global user_keys
    keys_dir = "users_keys"
    os.makedirs(keys_dir, exist_ok=True)

    keys_file = os.path.join(keys_dir, f"{username}_keys.json")

    if os.path.exists(keys_file):
        # Load and decrypt existing keys
        print(f"[*] Loading and decrypting existing keys for {username}")
        with open(keys_file, 'r') as f:
            stored = json.load(f)

        # Extract and decode
        salt = base64.b64decode(stored["salt"])
        nonce = base64.b64decode(stored["nonce"])
        ciphertext = base64.b64decode(stored["ciphertext"])
        tag = base64.b64decode(stored["tag"])

        # Derive same key from password & salt
        aes_key = derive_key(password, salt)

        # Decrypt JSON payload and parse
        plaintext = aes_decrypt(nonce, ciphertext, tag, aes_key)
        user_keys = json.loads(plaintext)

        print(f"[*] Successfully decrypted keys for {username}")
    else:
        # Generate new keypairs (must return a JSON-serializable dict)
        print(f"[*] Generating new cryptographic keys for {username}")
        user_keys = generate_user_keypairs()

        # Serialize to JSON string
        blob = json.dumps(user_keys)

        # New random salt for KDF
        salt = get_random_bytes(16)
        aes_key = derive_key(password, salt)

        # Encrypt JSON blob
        nonce, ciphertext, tag = aes_encrypt(blob, aes_key)

        # Store everything Base64-encoded
        stored = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }

        # Write to file with restricted permissions
        with open(keys_file, 'w') as f:
            json.dump(stored, f, indent=2)
        os.chmod(keys_file, 0o600)

        print(f"[*] Encrypted keys saved to {keys_file}")

    return user_keys


def send_public_keys(sock, username):
    """Send our public keys to the server for distribution."""
    public_key_msg = {
        'type': 'public_keys',
        'username': username,
        'ecc_public': user_keys['ecc_public'],
        'dsa_public': user_keys['dsa_public']
    }
    sock.sendall(json.dumps(public_key_msg).encode())


def handle_secure_message(payload):
    """Handle incoming secure messages."""
    try:
        # Extract sender info
        sender = payload.get('sender')
        encrypted_data = payload.get('encrypted_data')

        # Get sender's public keys
        if sender not in other_users_public_keys:
            print(f"[!] No public keys for {sender}")
            return

        sender_dsa_pub = other_users_public_keys[sender]['dsa_public']

        # Decrypt and verify
        message, signature_valid, timestamp = decrypt_and_verify_received(
            encrypted_data,
            user_keys['ecc_private'],
            sender_dsa_pub
        )

        if message:
            status = "✓ VERIFIED" if signature_valid else "✗ INVALID SIGNATURE"
            print(f"\n[SECURE] {sender}: {message} [{status}]")
        else:
            print(f"\n[!] Failed to decrypt message from {sender}")

    except Exception as e:
        print(f"\n[!] Error handling secure message: {e}")


def handle_public_keys(payload):
    """Handle incoming public key announcements."""
    try:
        username = payload['username']
        if username != user_keys.get('username'):  # Don't store our own keys
            other_users_public_keys[username] = {
                'ecc_public': payload['ecc_public'],
                'dsa_public': payload['dsa_public']
            }
            print(f"\n[*] Received public keys for {username}")
    except Exception as e:
        print(f"\n[!] Error handling public keys: {e}")

# Function to get messages


def receive_messages(sock):
    # Infinite loop to receive messages from the server
    while True:
        try:
            # Receive message from the server
            msg = sock.recv(1024)
            # If no message is received, break the loop
            if not msg:
                break

            # Try to parse as JSON (for secure messages)
            try:
                data = json.loads(msg.decode())
                message_type = data.get('type')
                if message_type == 'secure_message':
                    handle_secure_message(data)
                elif message_type == 'public_keys':
                    handle_public_keys(data)
                else:
                    sys.stdout.write("\r" + str(data) + "\n> ")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                # Regular text message
                sys.stdout.write("\r" + msg.decode() + "\n> ")
                sys.stdout.flush()
        except:
            break

# Function to start the client
def start_client(server_ip, port=12345):
    # Initialize a socket and connect to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Attempt to connect to the server
    sock.connect((server_ip, port))
    # Confirm connection
    print(f"[*] Connected to server {server_ip}:{port}")

    while True:
        # Prompt for username and send it to the server
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()

        # Load or generate cryptographic keys
        try:
            # Attempt to load or generate the encrypted keyfile
            load_or_generate_keys(username, password)
        except ValueError:
            print("[*] Incorrect password or corrupted key file. Please try again.\n")
            continue

        # If we reach here, credentials worked
        sock.sendall(username.encode())
        # Wait for server response
        response = sock.recv(1024).decode().strip()

        try:
            data = json.loads(response)
            if data.get("status") == "error":
                print(f"[!] Server error: {data.get('message')}")
                sock.close()
                return  # Exit the function or retry loop
        except json.JSONDecodeError:
            # If it's not JSON, assume it's a regular message
            print("[!] Unexpected response from server.")
            sock.close()
            return
        user_keys['username'] = username
        print(f"[*] Credentials accepted for {username}\n")
        break

    # Send our public keys to the server
    send_public_keys(sock, username)

    # Start a thread to receive messages from the server
    # A thread is used to allow simultaneous sending and receiving of messages
    # This thread will run in the background
    # This means that the main thread can continue to accept user input
    threading.Thread(target=receive_messages,
                     args=(sock,), daemon=True).start()

    # Main loop to send messages to the server
    # This loop will run until the user decides to quit
    print("[*] You can start sending messages. Type '/quit' to exit.")
    print("[*] Use '/secure <username> <message>' for encrypted messages.")
    print("[*] Use '/keys' to see available public keys.")

    try:
        while True:
            msg = input("> ")

            # Handle secure messaging command
            if msg.startswith("/secure "):
                handle_secure_command(sock, msg, username)
            # Handle keys listing command
            elif msg.strip() == "/keys":
                print(
                    f"Available public keys: {list(other_users_public_keys.keys())}")
            # Regular message or other commands
            else:
                sock.sendall(msg.encode())

                # If the user types '/quit', break the loop and close the connection
                if msg.strip() == "/quit":
                    print("[*] Disconnecting.")
                    break

    except KeyboardInterrupt:
        print("\n[*] Disconnected via keyboard interrupt.")
    finally:
        sock.close()


def handle_secure_command(sock, msg, username):
    """Handle /secure command for sending encrypted messages."""
    try:
        # Parse command: /secure <recipient> <message>
        parts = msg.split(' ', 2)
        if len(parts) < 3:
            print("Usage: /secure <recipient> <message>")
            return

        recipient = parts[1]
        message = parts[2]

        # Check if we have recipient's public keys
        if recipient not in other_users_public_keys:
            print(
                f"No public keys available for {recipient}. They may not be online.")
            return

        # Encrypt and sign the message
        recipient_ecc_pub = other_users_public_keys[recipient]['ecc_public']
        encrypted_package = encrypt_and_sign_for_user(
            message,
            recipient_ecc_pub,
            user_keys['dsa_private']
        )
        
        # Send secure message to server
        secure_msg = {
            'type': 'secure_message',
            'sender': username,
            'recipient': recipient,
            'encrypted_data': encrypted_package
        }

        sock.sendall(json.dumps(secure_msg).encode())
        print(f"[*] Secure message sent to {recipient}")

    except Exception as e:
        print(f"[!] Error sending secure message: {e}")


if __name__ == "__main__":
    # Usage: python3 src/client/client.py <server-domain-or-ip>
    if len(sys.argv) != 2:
        print("Usage: python3 src/client/client.py <server-domain-or-ip>")
        sys.exit(1)

    # Get the server domain or IP from command line arguments
    server_domain = sys.argv[1]
    start_client(server_domain)
