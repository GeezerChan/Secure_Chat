# server.py
import socket
import threading

# Server setup
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Port to listen on

# List to keep track of connected clients
clients = []

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    
    while True:
        try:
            message = conn.recv(1024).decode('utf-8')  # Receive message from client
            if message:
                print(f"[{addr}] {message}")
                broadcast(message, conn)
            else:
                break
        except:
            break
    
    # Remove client when they disconnect
    conn.close()
    clients.remove(conn)
    print(f"[DISCONNECTED] {addr} disconnected.")

# Function to broadcast message to all clients
def broadcast(message, sender_conn):
    for client in clients:
        if client != sender_conn:  # Send message to all clients except the sender
            try:
                client.send(message.encode('utf-8'))
            except:
                client.close()
                clients.remove(client)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()  # Accept new connection
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()