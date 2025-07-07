import socket
import threading
import sys

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024)
            if not msg:
                break
            sys.stdout.write("\r" + msg.decode() + "\n> ")
            sys.stdout.flush()
        except:
            break

def start_client(server_ip, port=12345):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    print(f"[*] Connected to server {server_ip}:{port}")

    username = input("Enter your username: ")
    sock.sendall(username.encode())

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    try:
        while True:
            msg = input("> ")
            sock.sendall(msg.encode())

            if msg.strip() == "/quit":
                print("[*] Disconnecting.")
                break

    except KeyboardInterrupt:
        print("\n[*] Disconnected via keyboard interrupt.")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 client.py <server-domain-or-ip>")
        sys.exit(1)

    server_domain = sys.argv[1]
    start_client(server_domain)
