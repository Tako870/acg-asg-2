import socket
import threading
import sys

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024)
            if not msg:
                break
            # Clear current input line, print the message, and reprint prompt
            sys.stdout.write("\r" + msg.decode() + "\n> ")
            sys.stdout.flush()
        except:
            break

def start_client(server_ip='DOMAIN', port=12345):  # Replace with your server IP/domain
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    
    username = input("Enter your username: ")
    sock.sendall(username.encode())  # <- This is correct

    
    print(f"[*] Connected to server {server_ip}:{port}")

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    try:
        while True:
            msg = input("> ")
            sock.sendall(msg.encode())
    except KeyboardInterrupt:
        print("\n[*] Disconnecting.")
    finally:
        sock.close()

if __name__ == "__main__":
    start_client()
