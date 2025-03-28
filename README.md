# SecureSoftware Mini Project 1
My solution for the first mini project of Secure Software development

### Helicopter view description
The solution is a CLI application, with a server part and a client part

- The server starts up, listening for connections on port 8000
- When a client connects to the server the two parts exchange public keys
- After public key exchange the server generates a session key, that is send to the client encrypted with the clients public key
- client and server communicates with messages encrypted with the session key

### How to use it

install requirements
```bash
pip install -r requirements.txt
```

launch a server in a terminal
```bash
python secure_chat.py server
```

launch a client in another terminal
```bash
python secure_chat.py
```

Chat!

### Hassles
This part took quite a while to understand (and actually I'm not sure I fully understand it yet)
I am not really sure what the public_exponent does, but after fiddling around with it, it works now
```python
self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
```

I also thought it would be fun to use 1024 bits for the session key, but just as the documentation actually says, 256 bits is the limit 
```python
def _generate_session_key(self):
    # Generate a random 256-bit (32-byte) session key
    self.session_key = secrets.token_bytes(32)
    print("Session key generated")
```
