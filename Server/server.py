# server.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers

import socket
import threading
import os
import sqlite3
import hashlib
from Crypto.PublicKey import RSA

# Server setup
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Port to listen on

clients = {} # List to keep track of connected clients
chat_groups = {}  # Dictionary to track chat groups
symmetric_keys = {}
user_status = {}  # Track user status ('online' / 'offline')
client_lock = threading.Lock()  # Thread lock for protecting shared resources

def store_symmetric_key_for_user(username, sym_key):
    symmetric_keys[username] = sym_key

def get_symmetric_key_for_user(username):
    return symmetric_keys.get(username)

def encrypt_symmetric_key(sym_key, pub_key):
    """ Encrypt symmetric key using the receiver's public key """
    encrypted_key = pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_symmetric_key(encrypted_key, priv_key):
    """ Decrypt the symmetric key using the receiver's private key """
    return priv_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def generate_symmetric_key():
    """ Generate a random symmetric key for the chat session """
    return os.urandom(32)  # 256-bit key

def get_public_key(username):
    """ Fetch the public key of the user from a database or file """
    # This is just a placeholder, you'll need a real implementation
    return RSA.import_key(open(f"{username}_public.pem").read())

def encrypt_message(message, username):
    """ Encrypt the message using the symmetric key of the user """
    symmetric_key = get_symmetric_key_for_user(username)
    iv = os.urandom(16)  # Generate a random IV
    cipher = ciphers.Cipher(ciphers.algorithms.AES(symmetric_key), ciphers.modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the message to make it a multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_message  # Prepend IV to the encrypted message

def decrypt_message(encrypted_message, username):
    """ Decrypt the message using the symmetric key of the user """
    symmetric_key = get_symmetric_key_for_user(username)
    iv = encrypted_message[:16]  # Extract the IV
    cipher = ciphers.Cipher(ciphers.algorithms.AES(symmetric_key), ciphers.modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_message) + unpadder.finalize()


def invite_to_chat(conn, inviter, invitees):
    """ Handle the invite process """
    invited_online_users = [user for user in invitees if user in clients and user != inviter]

    if invited_online_users:
        # Create the chat group for the inviter if not already created
        if inviter not in chat_groups:
            chat_groups[inviter] = set()

        for user in invited_online_users:
            if user not in chat_groups[inviter]:
                chat_groups[inviter].add(user)

        # Notify invited users and the inviter
        for user in invited_online_users:
            clients[user].send(f"[INVITE] You have been invited to chat with '{inviter}'. Do you accept? (yes/no)".encode('utf-8'))

        # Inform the inviter that invites were sent
        conn.send(f"Invitations sent to: {', '.join(invited_online_users)}.\n".encode('utf-8'))

        # Now, wait for responses from invited users
        responses = {}
        for user in invited_online_users:
            response = clients[user].recv(1024).decode('utf-8').strip().lower()
            responses[user] = response

        # Check if all users accepted the invite
        if all(response == 'yes' for response in responses.values()):
            # All users accepted the invite, establish a chat session
            sym_key = generate_symmetric_key()

            # Encrypt the symmetric key for each user using their public key
            for user in chat_groups[inviter]:
                if user in clients:
                    public_key = get_public_key(user)  # Assume you have a way to get the user's public key
                    encrypted_key = encrypt_symmetric_key(sym_key, public_key)
                    clients[user].send(f"[KEY] Symmetric key encrypted: {encrypted_key}".encode('utf-8'))

            # Now that the key is distributed, users can begin chatting securely
            for user in chat_groups[inviter]:
                start_chat(user)  # Start the chat session for each user

        else:
            # If anyone declined the invite, inform the inviter
            conn.send("One or more users declined the invite.\n".encode('utf-8'))
    else:
        conn.send("No valid online users to invite.\n".encode('utf-8'))


def start_chat(username):
    """ Start the chat session for a user after the key distribution """
    conn = clients.get(username)
    if conn:
        conn.send(f"Chat session started with users: {', '.join(chat_groups[username])}\n".encode('utf-8'))

        # Main chat loop
        while True:
            message = conn.recv(1024).decode('utf-8')

            if message.lower() == 'exit':
                conn.send("You left the chat.\n".encode('utf-8'))
                break

            # Encrypt and send the message to the group
            send_group_message(username, message)

def send_group_message(sender, message):
    """ Send the message to all participants in the chat group, encrypting the message using the symmetric key """
    if sender in chat_groups:
        for participant in chat_groups[sender]:
            if participant in clients:
                # Encrypt the message using the symmetric key
                encrypted_message = encrypt_message(message, participant)

                # Send the encrypted message to the participant
                clients[participant].send(f"{sender}: {encrypted_message}".encode('utf-8'))

        # Send message to the sender too (encrypted)
        encrypted_message = encrypt_message(message, sender)
        clients[sender].send(f"You: {encrypted_message}".encode('utf-8'))
    else:
        if sender in clients:
            clients[sender].send("You are not in a chat group.\n".encode('utf-8'))

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    
    username = None
    while True:
        try:
            conn.send("Enter 'register', 'login', or 'exit' to disconnect: ".encode('utf-8'))
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
                    set_user_online(username)  # Set the user status to online when registered
            elif choice.lower() == 'login':
                conn.send("Enter username: ".encode('utf-8'))
                username = conn.recv(1024).decode('utf-8')

                conn.send("Enter password: ".encode('utf-8'))
                password = conn.recv(1024).decode('utf-8')

                if authenticate_user(username, password):
                    conn.send(f"Welcome '{username}'! You can enter 'show_online' to see online users, 'invite' to invite a user, or 'logout' to exit.\n".encode('utf-8'))
                    set_user_online(username)  # Set user status to 'online'
                    clients[username] = conn  # Store the client connection

                    # Chatroom or user interaction logic here
                    while True:
                        conn.send("Enter 'show_online', 'invite', or 'logout': ".encode('utf-8'))
                        user_command = conn.recv(1024).decode('utf-8')

                        if user_command.lower() == 'logout':
                            set_user_offline(username)  # Set user status to 'offline'
                            conn.send("Logged out successfully.\n".encode('utf-8'))
                            break  # Exit chat loop to return to register/login menu

                        elif user_command.lower() == 'show_online':
                            online_users = get_online_users()
                            if online_users:
                                conn.send(f"Online Users:\n{', '.join(online_users)}\n".encode('utf-8'))
                            else:
                                conn.send("No users are currently online.\n".encode('utf-8'))

                        elif user_command.lower() == 'invite':
                            conn.send("Enter usernames to invite (comma-separated): ".encode('utf-8'))
                            invitees = conn.recv(1024).decode('utf-8').split(',')
                            invitees = [invitee.strip() for invitee in invitees]

                            invite_to_chat(conn, username, invitees)

                        else:
                            conn.send("Invalid command. Please try again.\n".encode('utf-8'))
                else:
                    conn.send("Login failed. Try again.\n".encode('utf-8'))
            elif choice.lower() == 'exit':
                conn.send("Goodbye!\n".encode('utf-8'))
                break  # Exit the main loop to disconnect
            else:
                conn.send("Invalid option. Please try again.\n".encode('utf-8'))
        except Exception as e:
            print(f"[ERROR] {e}")
            break

    # Remove user from clients and close connection
    if username in clients:
        del clients[username]
    set_user_offline(username)  # Ensure user is marked offline when disconnecting
    conn.close()
    print(f"[DISCONNECTED] {addr} disconnected.")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 65432))
    server.listen()

    print(f"[LISTENING] Server is listening on 127.0.0.1:65432")

    while True:
        conn, addr = server.accept()  # Accept new connection
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
           
def invite_to_chat(conn, inviter, invitees):
    invited_online_users = [user for user in invitees if user in clients and user != inviter]
    
    if invited_online_users:
        # Initialize or add to the chat group
        if inviter not in chat_groups:
            chat_groups[inviter] = set()
        
        for user in invited_online_users:
            if user not in chat_groups[inviter]:
                chat_groups[inviter].add(user)
        
        # Notify invited users and the inviter
        for user in invited_online_users:
            clients[user].send(f"[INVITE] You have been invited to chat with '{inviter}'.".encode('utf-8'))
        
        conn.send(f"Invitations sent to: {', '.join(invited_online_users)}.\n".encode('utf-8'))
    else:
        conn.send("No valid online users to invite.\n".encode('utf-8'))
    

def show_logged_in_menu(conn, username):
    """Display menu options to logged-in users."""
    while True:
        try:
            # Display options only after logging in
            conn.send("Choose an option: 'show_online', 'invite', 'logout'\n".encode('utf-8'))
            command = conn.recv(1024).decode('utf-8').strip()

            if command.lower() == 'show_online':
                online_users = get_online_users()
                if online_users:
                    conn.send(f"Online Users:\n{', '.join(online_users)}\n".encode('utf-8'))
                else:
                    conn.send("No users are currently online.\n".encode('utf-8'))
            
            elif command.lower() == 'invite':
                conn.send("Enter usernames to invite (comma-separated): ".encode('utf-8'))
                invited_usernames = conn.recv(1024).decode('utf-8').split(',')

                for invited in invited_usernames:
                    invited = invited.strip()
                    if invited in clients:  # Check if the invited user is online
                        clients[invited].send(f"[INVITE] {username} has invited you to chat.".encode('utf-8'))
                conn.send("Invites sent to online users.\n".encode('utf-8'))

            elif command.lower() == 'logout':
                conn.send("Logging out...\n".encode('utf-8'))
                set_user_offline(username)
                break  # Exit the menu loop to disconnect

            else:
                conn.send("Invalid option. Please try again.\n".encode('utf-8'))
        except Exception as e:
            print(f"[ERROR] {e}")
            break

def get_online_users():
    # Return a list of users who are currently online
    return [user for user, status in user_status.items() if status == 'online']

def set_user_online(username):
    """ Mark a user as online """
    user_status[username] = 'online'

def set_user_offline(username):
    """ Mark a user as offline """
    if username in user_status:
        user_status[username] = 'offline'

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

        if user:
            # Update status to "online"
            c.execute("UPDATE users SET status = 'online' WHERE username = ?", (username,))
            conn.commit()
            print(f"[LOGIN] User {username} authenticated and set to 'online'.")
            return True
        else:
            print(f"[ERROR] Authentication failed for {username}.")
            return False
    except sqlite3.Error as e:
        print(f"[ERROR] SQLite error: {e}")
        return False
    finally:
        conn.close()

    
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