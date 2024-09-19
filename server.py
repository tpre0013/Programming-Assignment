import socket
from dtls import do_patch, DtlsSocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Apply DTLS patch to use in socket
do_patch()

# Pre-shared key for mutual authentication
PSK = b'my_shared_secret_key'
AES_KEY = b'sixteen_byte_key'  # 16 bytes for AES-128
IV_LENGTH = 16  # Initialization Vector length for AES CBC mode

# Server callback for verifying PSK
def psk_callback(hint):
    print(f"Server received PSK identity hint: {hint}")
    # Return the pre-shared key for mutual authentication
    return PSK

# Encrypt data using AES
def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Initialization vector
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')  # Encode to Base64 for transport

# Decrypt data using AES
def decrypt_aes(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:IV_LENGTH]
    ciphertext = encrypted_data[IV_LENGTH:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Setup server socket (UDP + DTLS) using PSK for authentication
server_sock = DtlsSocket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
    server_side=True,
    psk_callback=psk_callback,  # Specify the PSK callback for server-side PSK validation
    cipher_suites="PSK-AES128-CCM8"  # Specify a PSK cipher suite
)

server_sock.bind(('0.0.0.0', 20220))

print("Server is listening for IoT devices...")

while True:
    # Receive encrypted data
    encrypted_data, addr = server_sock.recvfrom(1024)
    print(f"Encrypted data received from {addr}: {encrypted_data.decode('utf-8')}")

    # Decrypt the data using AES
    decrypted_data = decrypt_aes(encrypted_data.decode('utf-8'), AES_KEY)
    print(f"Decrypted data from {addr}: {decrypted_data.decode('utf-8')}")

    # Encrypt the response and send it back
    response = b"Hello IoT device! This is the server."
    encrypted_response = encrypt_aes(response, AES_KEY)
    server_sock.sendto(encrypted_response.encode('utf-8'), addr)
