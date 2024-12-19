import socket
import threading
import sys

# Client setup
HOST = '127.0.0.1'
PORT = 65432

def handle_input(client_socket):
    while True:
        message = sys.stdin.readline().strip()  # Read user input
        if message:
            if message.lower() == 'show_online':
                client_socket.send(message.encode('utf-8'))
            elif message.lower() == 'join_chatroom':
                client_socket.send(message.encode('utf-8'))
            else:
                client_socket.send(message.encode('utf-8'))

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')  # Receive server message
            if message:
                print(f"[SERVER]: {message}")
            else:
                print("[INFO] Connection closed by the server.")
                break
        except (ConnectionResetError, ConnectionAbortedError):
            print("[ERROR] Server connection lost.")
            break
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred: {e}")
            break

def send_messages(client_socket):
    # Start a new thread for handling user input
    input_thread = threading.Thread(target=handle_input, args=(client_socket,))
    input_thread.daemon = True  # This allows the program to exit even if the thread is running
    input_thread.start()

    # Main thread will handle sending messages but is not checking for input
    while True:
        try:
            # Let the input thread send messages when necessary
            pass
        except Exception as e:
            print(f"[ERROR] An error occurred in the send loop: {e}")
            break

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Try to connect to the server and handle potential connection errors
    try:
        client.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to the server.")
        return

    # Start a thread to listen for incoming messages
    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    receive_thread.start()

    # Main thread will handle sending messages
    send_messages(client)

if __name__ == "__main__":
    start_client()