import socket
from dtls import do_patch, DtlsSocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Apply DTLS patch
do_patch()

# Pre-shared key for mutual authentication
PSK = b'my_shared_secret_key'
AES_KEY = b'sixteen_byte_key'  # 16 bytes for AES-128
IV_LENGTH = 16  # Initialization Vector length for AES CBC mode

# Client callback for providing PSK to the server during handshake
def psk_callback(hint):
    print(f"Client received PSK identity hint: {hint}")
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

# Encrypt the data using AES
encrypted_data = encrypt_aes(data, AES_KEY)

# Send encrypted message over DTLS with PSK
client_sock.sendto(encrypted_data.encode('utf-8'), ('127.0.0.1', 20220))

# Receive server's encrypted response
response_data, addr = client_sock.recvfrom(1024)

# Decrypt the response using AES
decrypted_response = decrypt_aes(response_data.decode('utf-8'), AES_KEY)
print(f"Decrypted response from server: {decrypted_response.decode('utf-8')}")
