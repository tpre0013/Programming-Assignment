import socket
from dtls import do_patch, DtlsSocket

# Apply DTLS patch
do_patch()

# AES encryption key
AES_KEY = get_random_bytes(16)  # In practice, securely share this key between client and server

# Setup client socket for DTLS
client_sock = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), keyfile="client-key.pem", certfile="client-cert.pem")
client_sock.connect(('127.0.0.1', 20220))

# Data to send (plaintext)
data = b'Hello from IoT device!'

# Encrypt data using AES
encrypted_data = encrypt_aes(data, AES_KEY)

# Send encrypted message over DTLS
client_sock.sendto(encrypted_data.encode('utf-8'), ('127.0.0.1', 20220))

# Receive server's encrypted response
response_data, addr = client_sock.recvfrom(1024)

# Decrypt the response
decrypted_response = decrypt_aes(response_data.decode('utf-8'), AES_KEY)
print(f"Decrypted response from server: {decrypted_response.decode('utf-8')}")
