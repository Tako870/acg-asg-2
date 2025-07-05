import socket
import threading

clients = []  # {conn: username}
user_sockets = {}  # username -> conn
inboxes = {}       # username -> list of (sender, message)

def handle_client(conn, addr):
    try:
        username = conn.recv(1024).decode().strip()
        clients.append(conn)
        user_sockets[username] = conn
        inboxes[username] = []

        clients[conn] = username
        print(f"[+] {username} connected from {addr}")
        broadcast(f"{username} has joined the chat.".encode(), conn)
        
        while True:
            msg = conn.recv(1024)
            if not msg:
                break
            decoded = msg.decode().strip()

            if decoded.startswith("/msg"):
                parts = decoded.split(' ', 2)
                if len(parts) < 3:
                    conn.sendall(b"Usage: /msg <recipient> <message>\n")
                    continue

                recipient, message = parts[1], parts[2]
                if recipient not in user_sockets:
                    conn.sendall(f"User '{recipient}' not found.\n".encode())
                else:
                    # Store in recipient inbox
                    inboxes[recipient].append((username, message))
                    user_sockets[recipient].sendall(f"[PRIVATE] {username}: {message}".encode())

            elif decoded == "/inbox":
                user_inbox = inboxes.get(username, [])
                if not user_inbox:
                    conn.sendall(b"No private messages.\n")
                else:
                    for sender, message in user_inbox:
                        conn.sendall(f"[FROM {sender}]: {message}\n".encode())
                    inboxes[username] = []  # Clear inbox after viewing

            else:
                full_msg = f"{username}: {decoded}"
                broadcast(full_msg.encode(), conn)

    finally:
        print(f"[-] {clients.get(conn, 'Unknown')} disconnected")
        broadcast(f"{clients.get(conn, 'Unknown')} has left the chat.".encode(), conn)
        clients.pop(conn, None)
        conn.close()

def broadcast(message, source_conn):
    for client in clients:
        if client != source_conn:
            try:
                client.sendall(message)
            except:
                pass

def start_server(host='0.0.0.0', port=12345):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[*] Server listening on {host}:{port}")
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
