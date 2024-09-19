import socket
from dtls import do_patch, DtlsSocket

# Apply DTLS patch
do_patch()

# AES encryption key (this must match the client's key)
AES_KEY = get_random_bytes(16)

# Setup server socket for DTLS
server_sock = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), keyfile="server-key.pem", certfile="server-cert.pem", server_side=True)
server_sock.bind(('0.0.0.0', 20220))

while True:
    # Receive encrypted data
    encrypted_data, addr = server_sock.recvfrom(1024)
    print(f"Encrypted data received from {addr}: {encrypted_data.decode('utf-8')}")

    # Decrypt the data
    decrypted_data = decrypt_aes(encrypted_data.decode('utf-8'), AES_KEY)
    print(f"Decrypted data: {decrypted_data.decode('utf-8')}")

    # Encrypt the response and send it back
    response = b"Hello IoT device! This is the server."
    encrypted_response = encrypt_aes(response, AES_KEY)
    server_sock.sendto(encrypted_response.encode('utf-8'), addr)