# Needed to connect to a server and send/receive messages
import socket
# Needed for threading to handle simultaneous sending and receiving of messages
import threading
# needed for command line arguments and printing messages
import sys

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
            # Print the received message
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

    # Prompt for username and send it to the server
    username = input("Enter your username: ")
    sock.sendall(username.encode())

    # Start a thread to receive messages from the server
    # A thread is used to allow simultaneous sending and receiving of messages
    # This thread will run in the background
    # This means that the main thread can continue to accept user input
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    # Main loop to send messages to the server
    # This loop will run until the user decides to quit
    print("[*] You can start sending messages. Type '/quit' to exit.")
    
    try:
        while True:
            msg = input("> ")
            sock.sendall(msg.encode())

            # If the user types '/quit', break the loop and close the connection
            if msg.strip() == "/quit":
                print("[*] Disconnecting.")
                break

    except KeyboardInterrupt:
        print("\n[*] Disconnected via keyboard interrupt.")
    finally:
        sock.close()

if __name__ == "__main__":
    # Usage: python3 client.py <server-domain-or-ip>
    if len(sys.argv) != 2:
        print("Usage: python3 client.py <server-domain-or-ip>")
        sys.exit(1)

    # Get the server domain or IP from command line arguments
    server_domain = sys.argv[1]
    start_client(server_domain)
