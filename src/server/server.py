import socket
import threading

# List of connected users and their inboxes
# user_sockets maps usernames to their socket connections
user_sockets = {}  # username -> conn
inboxes = {}       # username -> list of (sender, message)

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
            # Receive and decode the message. If no message is received, break the loop
            msg = conn.recv(1024)
            if not msg:
                break
            decoded = msg.decode().strip()
            
            # Handle /msg. This allows users to send private messages
            if decoded.startswith("/msg"):
                handle_private_message(conn, username, decoded)
            
            # Handle /inbox. This allows users to check their private messages
            elif decoded == "/inbox":
                check_inbox(conn, username)
             
            # Handle /quit. This allows users to gracefully disconnect       
            elif decoded == "/quit":
                break  # gracefully disconnect
            
            # Otherwise, broadcast the message to all connected users
            else:
                full_msg = f"{username}: {decoded}"
                broadcast(full_msg.encode(), exclude=username)

    # On quit, handle disconnection and announce to other users
    finally:
        print(f"[-] {username} disconnected")
        broadcast(f"{username} has left the chat.".encode(), exclude=username)
        user_sockets.pop(username, None)
        inboxes.pop(username, None)
        conn.close()

# Function to broadcast messages to all connected users except the sender
# This is used for public messages and notifications
def broadcast(message, exclude=None):
    for uname, client in user_sockets.items():
        if uname != exclude:
            try:
                client.sendall(message)
            except:
                pass  # Handle broken pipe silently for now

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
