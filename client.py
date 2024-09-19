import socket
from dtls import do_patch, DtlsSocket

# Apply DTLS patch
do_patch()

# Setup client socket
client_sock = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), keyfile="client-key.pem", certfile="client-cert.pem")
client_sock.connect(('127.0.0.1', 20220))

# Send encrypted message
client_sock.sendto(b'Hello from IoT device!', ('127.0.0.1', 20220))

# Receive server's response
data, addr = client_sock.recvfrom(1024)
print(f"Received encrypted data from server: {data}")