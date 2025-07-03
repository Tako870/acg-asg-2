import socket
import threading

clients = {}  # {conn: username}

def handle_client(conn, addr):
    try:
        username = conn.recv(1024).decode().strip()
        clients[conn] = username
        print(f"[+] {username} connected from {addr}")
        broadcast(f"{username} has joined the chat.".encode(), conn)

        while True:
            msg = conn.recv(1024)
            if not msg:
                break
            full_msg = f"{username}: {msg.decode()}"
            print(f"[{addr}] {full_msg}")
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
