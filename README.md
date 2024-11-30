# Secure_Chat

Secure_Chat is a secure chat application designed to enable users to communicate confidentially. It features user authentication, secure message encryption, and support for digital signatures using RSA and DSA.

## Features

- User authentication with username and password.
- Real-time user status tracking (online/offline).
- Secure symmetric key distribution using public-key encryption.
- Encrypted chat messages using symmetric keys.
- Support for RSA and DSA digital signatures.
- Ability to invite multiple users to a chat session.
- Notifications for users who are not online.

## Getting Started

### Prerequisites

- Python 3.x
- Required Python libraries:
  - `pycryptodome` for cryptographic functions
  - `socket` for network communication
  - `threading` for handling multiple clients
  - `hashlib` for hashing
  - `sqlite3` lightweight database to store data persistently
  - `datetime` for handling time-related operations (track when users go online or offline)


### Installation

1. **Clone the Repository**

   Clone this repository to your local machine using:
   ```bash
   git clone https://github.com/your-username/Secure_Chat.git

2. **Install dependenciesr**
  pip install cryptography


3. **Host Clients**


### Progress

### Completed 

1. **Set Up the Project Structure**
Create the folders and organize the project files (e.g., client.py, server.py, users.db for the database).

2. **Set Up User Registration and Authentication (User Database)**
Goal: Set up a user authentication system.
Create the SQLite database for users.
Implement registration and login functions (hashing passwords with hashlib for security).
Test that users can register and log in.

### TO-DO

3. **Implement Basic Client-Server Communication**
Goal: Get the client and server to connect and exchange basic messages.
Implement a simple chat system using socket and threading libraries.

4. **Track User Status (Online/Offline)**
Goal: Implement online/offline status tracking.
Why: This is important for letting users know who’s available for chatting.
Update the server to keep track of online users, and allow users to query who’s online.

5. **Generate and Manage RSA/DSA Keys for Each User**
Goal: Generate public/private key pairs for each user upon registration.
Why: These keys are essential for securely sharing the symmetric key.
Use pycryptodome to generate and store keys.

6. **Implement Symmetric Key Distribution**
Goal: Have the server generate a symmetric AES key and distribute it securely to users.
Why: This allows the secure encryption of chat messages.
Encrypt the symmetric key using each user's public key and send it to the clients.

7. **Encrypt and Decrypt Messages Using the Symmetric Key**
Goal: Ensure all chat messages are encrypted using AES with the symmetric key.
Why: Message confidentiality is a core requirement of the project.
Implement AES encryption for sending and receiving messages.

8. **Add Digital Signatures (RSA/DSA)**
Goal: Allow users to sign messages and verify message authenticity.
Why: Digital signatures provide message integrity and authenticity.
Let users choose between RSA or DSA for signing.

9. **Handle User Joining/Leaving Conversations**
Goal: Implement logic for users to join and leave conversations.
Why: It’s important for the chatroom functionality to know when users enter or exit.
Update the online/offline status dynamically as users connect or disconnect.

10. **Test and Refine**
Goal: Ensure all components work together smoothly.
Why: Testing is crucial to identify bugs and improve performance.
Test multiple clients connecting and chatting securely.