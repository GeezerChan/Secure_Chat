# server.py
import socket
import threading
import os
import sqlite3
import hashlib
from Crypto.PublicKey import RSA

# Server setup
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Port to listen on

# List to keep track of connected clients
clients = {}

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    
    username = None
    while True:
        try:
            conn.send("Enter 'register' or 'login': ".encode('utf-8'))
            choice = conn.recv(1024).decode('utf-8')

            if choice.lower() == 'register':
                conn.send("Registering new user:\nEnter username: ".encode('utf-8'))
                username = conn.recv(1024).decode('utf-8')

                conn.send("Enter password: ".encode('utf-8'))
                password = conn.recv(1024).decode('utf-8')

                registration_message = register_user(username, password)
                conn.send(registration_message.encode('utf-8'))

                if "successfully" in registration_message:
                    clients[username] = conn  # Store the client connection
            elif choice.lower() == 'login':
                conn.send("Enter username: ".encode('utf-8'))
                username = conn.recv(1024).decode('utf-8')

                conn.send("Enter password: ".encode('utf-8'))
                password = conn.recv(1024).decode('utf-8')

                if authenticate_user(username, password):
                    conn.send(f"Welcome '{username}'!\n".encode('utf-8'))
                    clients[username] = conn  # Store the client connection
                    # You can now proceed to the chatroom logic here
                    break  # Exit the loop to start chat
                else:
                    conn.send("Login failed. Try again.\n".encode('utf-8'))
            else:
                conn.send("Invalid option. Please try again.\n".encode('utf-8'))
        except Exception as e:
            print(f"[ERROR] {e}")
            break
    
    # Remove user from clients when done
    if username:
        del clients[username]
    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()  # Accept new connection
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

def initialize_db():
    # Get the absolute path of the directory where the script is located
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Construct the absolute path for the database file
    db_path = os.path.join(base_dir, 'users.db')
    
    if not os.path.exists(db_path):
        print("[INFO] Database does not exist. Creating database...")
    else:
        print("[INFO] Database found.")
    
    conn = sqlite3.connect(db_path, check_same_thread=False)  # Use the absolute path for the database
    c = conn.cursor()

    # Create the users table with an additional 'status' field
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL,
            status TEXT DEFAULT 'offline'
        )
    ''')

    conn.commit()
    conn.close()

# Function to register a new user
def register_user(username, password):
    # Define the directory to save private keys
    private_key_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'server')

    # Create the directory if it doesn't exist
    if not os.path.exists(private_key_dir):
        os.makedirs(private_key_dir)

    # Database path should be consistent across all functions
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')
    conn = sqlite3.connect(db_path, check_same_thread=False)
    c = conn.cursor()

    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Generate RSA key pair (2048 bits)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    try:
        # Insert user into the database
        c.execute("INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)",
                  (username, hashed_password, public_key.decode('utf-8')))
        conn.commit()
        print(f"[REGISTER] User '{username}' registered successfully.")
        
        # Save the private key locally for the user
        with open(os.path.join(private_key_dir, f"{username}_private.pem"), "wb") as f:
            f.write(private_key)

        return f"User '{username}' registered successfully.\n"
    except sqlite3.IntegrityError:
        print(f"[ERROR] Username '{username}' already exists.")
        return "Username already exists. Please choose a different username.\n"
    finally:
        conn.close()

    
# Function to authenticate user login
def authenticate_user(username, password):
    try:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')
        conn = sqlite3.connect(db_path, check_same_thread=False)
        c = conn.cursor()

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Check if the username and password are correct
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = c.fetchone()

        conn.close()

        if user:
            print(f"[LOGIN] User {username} authenticated successfully.")
            return True
        else:
            print(f"[ERROR] Authentication failed for {username}.")
            return False
    except sqlite3.Error as e:
        print(f"[ERROR] SQLite error: {e}")
        return False
    
def get_users_info():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.db')
    conn = sqlite3.connect(db_path, check_same_thread=False)
    c = conn.cursor()

    # Query to get all users and passwords
    c.execute("SELECT username, password FROM users")
    users = c.fetchall()

    conn.close()

    # Format user information for display
    if users:
        users_list = "\n".join([f"Username: {user[0]}, Password: {user[1]}" for user in users])
        return f"Registered Users:\n{users_list}\n"
    else:
        return "No registered users found.\n"
    
if __name__ == "__main__":
    initialize_db()  # Initialize the database
    start_server()    # Start the server