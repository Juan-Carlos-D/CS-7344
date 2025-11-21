import socket

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

HOST = "127.0.0.1"  # server address
PORT = 5000         # same port as server
KEY  = b"mysecretkey"  # shared secret key (must match server)

def main():
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print(f"[*] Connected to server {HOST}:{PORT}")

        # Get a message from the user
        message = input("Enter a message to send to the server: ")
        data = message.encode('utf-8')

        # Encrypt data
        encrypted_data = xor_encrypt_decrypt(data, KEY)
        print(f"[>] Sending encrypted data: {encrypted_data}")

        # Send to server
        client_socket.sendall(encrypted_data)

        # Receive encrypted response
        encrypted_response = client_socket.recv(1024)
        print(f"[<] Encrypted response from server: {encrypted_response}")

        # Decrypt response
        decrypted_response = xor_encrypt_decrypt(encrypted_response, KEY)
        response_text = decrypted_response.decode('utf-8', errors='ignore')
        print(f"[<] Decrypted response from server: {response_text}")

if __name__ == "__main__":
    main()
