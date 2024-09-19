import socket
from dtls import do_patch, DtlsSocket

# Apply DTLS patch to use in socket
do_patch()

# Setup server socket (UDP + DTLS)
server_sock = DtlsSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), keyfile="server-key.pem", certfile="server-cert.pem", server_side=True)
server_sock.bind(('0.0.0.0', 20220))

while True:
    data, addr = server_sock.recvfrom(1024)
    print(f"Received data from {addr}: {data}")
    # Echo back the data securely
    server_sock.sendto(data, addr)