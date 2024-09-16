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
