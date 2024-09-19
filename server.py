import socket
from dtls import do_patch, DtlsSocket

# Apply DTLS patch to use in socket
do_patch()

# Pre-shared key for mutual authentication
PSK = b'my_shared_secret_key'

# Server callback for verifying PSK
def psk_callback(hint):
    print(f"Server received PSK identity hint: {hint}")
    # Return the pre-shared key for mutual authentication
    return PSK

# Setup server socket (UDP + DTLS) using PSK for authentication
server_sock = DtlsSocket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
    server_side=True,
    psk_callback=psk_callback,  # Specify the PSK callback for server-side PSK validation
    cipher_suites="PSK-AES128-CCM8"  # Specify a PSK cipher suite
)

server_sock.bind(('0.0.0.0', 20220))

while True:
    data, addr = server_sock.recvfrom(1024)
    print(f"Received encrypted data from {addr}: {data.decode('utf-8')}")
    # Echo back the data securely
    server_sock.sendto(data, addr)
