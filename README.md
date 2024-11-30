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
- Required Python libraries (In requirements.txt):
  - pycryptodome      # Cryptographic functions (encryption, decryption, hashing)
  - cffi              # Foreign Function Interface for calling C functions
  - cryptography      # High-level and low-level cryptographic primitives
  - pycparser         # C parser for building C extensions, used by cryptographic libraries

### Installation

1. **Clone the Repository**

  - ```git clone https://github.com/GeezerChan/Secure_Chat.git```

2. **Install dependencies**
 
  - ```pip install -r requirements.txt```

3. **Host Server**
  - Open a terminal and cd into the Secure_Chat repository.
  - Cd into Server folder and run server.py 
    - e.g. = ```python3 server.py```
  
4. **Host Client**
  - Open a terminal and cd into the Secure_Chat repository.
  - Cd into Client folder and run client.py 
    - e.g. = ```python3 client.py```

- Open another terminal and open another client.py

5. **Register and Chat**
  - Register a new user with a username and password.
  - Login with the user that you registered.
    - After Logging in:
      - Can type ```show_online``` to show online users.
      - Join central chatroom.
        - Type ```join_chatroom``` to join Central Chatroom.
        - Start chatting with people in the chatroom. Or no one.
  