# SSL\_Chat\_Room\_Homework

**Name:** 况旻諭
**Student ID:** 614430005

-----

## 1\. Overview

This project implements a **Multi-threaded Secure Chat Room** using **C language**, **OpenSSL**, and **POSIX Threads (pthread)** under **POSIX/Linux**.

  - The **Server** handles multiple concurrent clients using threads. It supports broadcasting messages to all users and relaying **private messages** (1-on-1) between specific users.
  - The **Client** connects to the server via a secure **SSL/TLS** channel. It uses `fork()` to handle sending user input and receiving server messages simultaneously (full-duplex).

The communication is encrypted using **SSL/TLS protocols**, ensuring that messages transmitted over the network are secure. The system relies on `SSL_read()` and `SSL_write()` instead of standard socket I/O.

-----

## 2\. Files

  - `chat_server.c` — SSL chat server implementation (Multi-threaded, Private messaging support)
  - `chat_client.c` — SSL chat client implementation (Full-duplex I/O)
  - `Makefile` — Build script for GNU `make`
  - `newreq.pem` — Self-signed certificate and private key for SSL encryption
  - `README.md` — This documentation

-----

## 3\. Build Instructions

**Prerequisite: Generate SSL Certificate**
Before compiling, you must generate the certificate file (`newreq.pem`):

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout newreq.pem -out newreq.pem
```

*(Press Enter to skip all prompts during generation)*

**Compile Source Code:**

To compile both the server and client:

```bash
make
```

To clean up compiled executables:

```bash
make clean
```

**Compiler:** `gcc`
**Flags:** `-lssl -lcrypto -lpthread`

-----

## 4\. Run Instructions

**Run the Server:**

```bash
sudo ./server 8888
```

The server will start listening on port `8888` and wait for incoming SSL connections.

**Run the Client:**

```bash
./client 127.0.0.1 8888
```

1.  **Enter Username:** Type your name when prompted.
2.  **Public Chat:** Type any text and press **Enter** to broadcast.
3.  **Private Chat:** Type `@TargetName Message` to send a secret message.
      - Example: `@Bob Hello Bob` (Only Bob can see this).
4.  **Exit:** Type `exit` or press **Ctrl + C** to quit.

-----

## 5\. Implementation Details

Key libraries and system calls used:

| Function / Library               | Description                                             |
| -------------------------------- | ------------------------------------------------------- |
| `<openssl/ssl.h>`                | OpenSSL library for SSL/TLS encryption.                 |
| `<pthread.h>`                    | POSIX threads for handling multiple clients on Server.  |
| `SSL_CTX_new()` / `SSL_new()`    | Creates SSL context and new SSL connection structures.  |
| `SSL_accept()` / `SSL_connect()` | Performs the SSL handshake (Server / Client).           |
| `SSL_read()` / `SSL_write()`     | Encrypted data transmission (replaces recv/send).       |
| `pthread_create()`               | Spawns a new thread for each connected client.          |
| `fork()`                         | Creates a child process in Client for simultaneous I/O. |
| `snprintf()`                     | Formats strings safely to prevent buffer overflows.     |

> **Note:** The server maintains a global `client_list` protected by a `mutex` to manage active users and route private messages correctly.

-----

## 6\. Example Execution

**Server Output:**

```text
Server listening on port 8888...
Client User001 connected.
Client User002 connected.
Client User003 connected.
[System]: Secret message sent to User003.
Client User003 disconnected.
```

**Client Output (User003):**

```text
Connected with TLS_AES_256_GCM_SHA384 encryption
Enter your username: User003
[System]: Welcome User003! Use '@name msg' for secret chat.
Hello everyone
@User001 This is a secret
[System]: Secret message sent to User001.
```

**Client Output (User001):**

```text
Connected with TLS_AES_256_GCM_SHA384 encryption
Enter your username: User001
[System]: Welcome User001! Use '@name msg' for secret chat.
[User003]: Hello everyone
[Secret from User003]: This is a secret
```

-----

## 7. Results

**Server Execution:** ![Server Output](https://raw.githubusercontent.com/BAGLE102/SSL_Chatroom_Homework/main/pic/server.png)

**Client Execution (Public & Private Chat):** *User001 1 (Sender - User001):* ![Client User 1](https://raw.githubusercontent.com/BAGLE102/SSL_Chatroom_Homework/main/pic/User001.png)

*User002 2 (Receiver - Bob):* ![Client User002](https://raw.githubusercontent.com/BAGLE102/SSL_Chatroom_Homework/main/pic/User002.png)

*User003 3 (Other User - Cannot see private messages):* ![Client User003](https://raw.githubusercontent.com/BAGLE102/SSL_Chatroom_Homework/main/pic/User003.png)



-----
