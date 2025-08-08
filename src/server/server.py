import socket
import threading
import json  # Added for handling JSON messages

# List of connected users and their inboxes
# user_sockets maps usernames to their socket connections
user_sockets = {}  # username -> conn
inboxes = {}       # username -> list of (sender, message)
user_public_keys = {}  # username -> {'ecc_public': key, 'dsa_public': key}

# Function to handle incoming client connections
def handle_client(conn, addr):
    try:
        # Receive username from the client
        username = conn.recv(1024).decode().strip()
        
        # Save connection and initialize inbox
        user_sockets[username] = conn
        inboxes[username] = []

        # Notify all users about the new connection
        print(f"[+] {username} connected from {addr}")
        broadcast(f"{username} has joined the chat.".encode(), exclude=username)
        
        # Main loop to receive messages from the client
        while True:
            try:
                # Receive and decode the message. If no message is received, break the loop
                msg = conn.recv(1024)
                if not msg:
                    break
                
                try:
                    # Try to parse as JSON first (for crypto messages)
                    data = json.loads(msg.decode().strip())
                    handle_json_message(conn, username, data)
                except json.JSONDecodeError:
                    # Fall back to plain text handling
                    decoded = msg.decode().strip()
                    handle_text_message(conn, username, decoded)
                    
            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                # Client disconnected unexpectedly
                print(f"[!] {username} connection lost: {type(e).__name__}")
                break
            except Exception as e:
                # Other unexpected errors
                print(f"[!] Error handling {username}: {e}")
                break

    # On quit, handle disconnection and announce to other users
    finally:
        print(f"[-] {username} disconnected")
        broadcast(f"{username} has left the chat.".encode(), exclude=username)
        user_sockets.pop(username, None)
        inboxes.pop(username, None)
        user_public_keys.pop(username, None)  # Remove public keys
        conn.close()

# Function to handle JSON messages (crypto messages)
def handle_json_message(conn, username, data):
    """Handle JSON messages from crypto-enabled clients"""
    message_type = data.get('type')
    
    if message_type == 'public_keys':
        # Store user's public keys and distribute to others
        handle_public_keys(username, data)
        
    elif message_type == 'secure_message':
        # Route encrypted message to recipient
        handle_secure_message(conn, username, data)
        
    else:
        print(f"[!] Unknown JSON message type: {message_type}")

# Function to handle plain text messages (legacy support)
def handle_text_message(conn, username, decoded):
    """Handle plain text messages (backward compatibility)"""
    # Handle /msg. This allows users to send private messages
    if decoded.startswith("/msg"):
        handle_private_message(conn, username, decoded)
    
    # Handle /inbox. This allows users to check their private messages
    elif decoded == "/inbox":
        check_inbox(conn, username)
     
    # Handle /quit. This allows users to gracefully disconnect       
    elif decoded == "/quit":
        return False  # Signal to break the main loop
    
    # Otherwise, broadcast the message to all connected users
    else:
        # Otherwise, broadcast the message to all connected users
        broadcast(f"{username}: {decoded}".encode(), exclude=username)
    return True

# Function to handle public key distribution
def handle_public_keys(username, data):
    """Store and distribute user's public keys"""
    # Store the public keys
    user_public_keys[username] = {
        'ecc_public': data['ecc_public'],
        'dsa_public': data['dsa_public']
    }
    
    print(f"[*] Stored public keys for {username}")
    
    # Send this user's public keys to all other connected users
    key_announcement = {
        'type': 'public_keys',
        'username': username,
        'ecc_public': data['ecc_public'],
        'dsa_public': data['dsa_public']
    }
    
    key_msg = json.dumps(key_announcement).encode()
    
    for other_username, other_conn in user_sockets.items():
        if other_username != username:  # Don't send to self
            try:
                other_conn.sendall(key_msg)
            except:
                pass
    
    # Send all existing public keys to the new user
    for other_username, keys in user_public_keys.items():
        if other_username != username:  # Don't send user their own keys
            existing_key_msg = {
                'type': 'public_keys',
                'username': other_username,
                'ecc_public': keys['ecc_public'],
                'dsa_public': keys['dsa_public']
            }
            
            try:
                user_sockets[username].sendall(json.dumps(existing_key_msg).encode())
            except:
                pass

# Function to handle secure message routing
def handle_secure_message(conn, username, data):
    """Route encrypted messages to recipients"""
    recipient = data.get('recipient')
    
    if not recipient:
        print(f"[!] Secure message from {username} has no recipient")
        return
    
    if recipient not in user_sockets:
        conn.sendall(f"User '{recipient}' not found or not online.".encode())
        return
    
    # Forward the encrypted message to recipient
    try:
        user_sockets[recipient].sendall(json.dumps(data).encode())
        print(f"[*] Routed secure message: {username} -> {recipient}")
    except Exception as e:
        print(f"[!] Failed to route secure message: {e}")
        conn.sendall(b"Failed to deliver secure message.")

# Function to broadcast messages to all connected users except the sender
# This is used for public messages and notifications
def broadcast(message, exclude=None):
    disconnected_users = []
    for uname, client in user_sockets.items():
        if uname != exclude:
            try:
                client.sendall(message)
            except (ConnectionResetError, ConnectionAbortedError, OSError, BrokenPipeError):
                # Mark user for cleanup if connection is broken
                disconnected_users.append(uname)
            except Exception:
                pass  # Handle other errors silently
    
    # Clean up disconnected users
    for uname in disconnected_users:
        print(f"[!] Cleaning up disconnected user: {uname}")
        user_sockets.pop(uname, None)
        inboxes.pop(uname, None)
        user_public_keys.pop(uname, None)

# Function to handle private messages
# This allows users to send messages to specific users
def handle_private_message(conn, username, message):
    # Split the message into parts. The first part is the command, the second is the recipient, and the rest is the message
    parts = message.split(' ', 2)
    
    # If the message format is incorrect, send usage instructions
    if len(parts) < 3:
        conn.sendall(b"Usage: /msg <recipient> <message>\n")
        return

    # Extract recipient and message from the parts
    recipient, message = parts[1], parts[2]
    
    # If the recipient is not in the list of sockets that the server knows, notify the sender
    if recipient not in user_sockets:
        conn.sendall(f"User '{recipient}' not found.\n".encode())
    else:
        # Store in recipient's inbox
        inboxes[recipient].append((username, message))
        user_sockets[recipient].sendall(f"[PRIVATE] {username}: {message}".encode())

# Function to check the inbox of a user
def check_inbox(conn, username):
    # Check the inbox for the user
    user_inbox = inboxes.get(username, [])
    
    # If the inbox is empty, notify the user
    if not user_inbox:
        conn.sendall(b"No private messages.\n")
    else:
        # Send all messages in the inbox to the user
        for sender, message in user_inbox:
            conn.sendall(f"[FROM {sender}]: {message}\n".encode())
        inboxes[username] = []  # Clear inbox after reading

# Function to start the server
# This function binds the server to a host and port, and listens for incoming connections
def start_server(host='0.0.0.0', port=12345):
    # Create a socket and bind it to the specified host and port
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[*] Server listening on {host}:{port}")
    
    # Accept incoming connections in a loop
    # Each connection is handled in a separate thread to allow multiple clients to connect simultaneously
    # This allows the server to handle multiple clients at the same time
    # The daemon=True argument allows the thread to exit when the main program exits
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
