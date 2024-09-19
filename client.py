import socket
from dtls import do_patch, DtlsSocket

# Apply DTLS patch
do_patch()

# Pre-shared key for mutual authentication
PSK = b'my_shared_secret_key'

# Client callback for providing PSK to the server during handshake
def psk_callback(hint):
    print(f"Client received PSK identity hint: {hint}")
    return PSK

# Setup client socket (UDP + DTLS) using PSK for authentication
client_sock = DtlsSocket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
    psk_callback=psk_callback,  # Specify the PSK callback for client-side PSK validation
    cipher_suites="PSK-AES128-CCM8"  # Specify a PSK cipher suite
)

# Connect to the server
client_sock.connect(('127.0.0.1', 20220))

# Data to send (plaintext)
data = b'Hello from IoT device with PSK!'

# Send encrypted message over DTLS with PSK
client_sock.sendto(data, ('127.0.0.1', 20220))

# Receive server's encrypted response
response_data, addr = client_sock.recvfrom(1024)
print(f"Received encrypted response from server: {response_data.decode('utf-8')}")

