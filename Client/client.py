# client.py
import socket
import threading

# Client setup
HOST = '127.0.0.1'
PORT = 65432

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(f"[SERVER]: {message}")
            else:
                break
        except:
            print("[ERROR] Connection to server lost.")
            client_socket.close()
            break

def send_messages(client_socket):
    while True:
        message = input()
        
        # Command to show online users
        if message.lower() == 'show_online':
            client_socket.send(message.encode('utf-8'))
        elif message.lower().startswith('invite'):
            client_socket.send(message.encode('utf-8'))
        else:
            client_socket.send(message.encode('utf-8'))


def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    # Start a thread to listen for incoming messages
    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    receive_thread.start()

    # Main thread will handle sending messages
    send_messages(client)

if __name__ == "__main__":
    start_client()
