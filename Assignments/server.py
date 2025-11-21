import socket

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

HOST = "127.0.0.1"  # localhost
PORT = 5000         # any free port
KEY  = b"mysecretkey"  # shared secret key (must match client)

def main():
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[*] Server listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"[+] Connected by {addr}")

                # Receive encrypted data (up to 1024 bytes)
                encrypted_data = conn.recv(1024)
                if not encrypted_data:
                    print("[-] No data received, closing connection.")
                    continue

                # Decrypt the data
                decrypted_data = xor_encrypt_decrypt(encrypted_data, KEY)
                message = decrypted_data.decode('utf-8', errors='ignore')
                print(f"[>] Encrypted from client: {encrypted_data}")
                print(f"[>] Decrypted message from client: {message}")

                # Prepare a response
                response_text = f"Server received: {message}"
                response_bytes = response_text.encode('utf-8')

                # Encrypt response
                encrypted_response = xor_encrypt_decrypt(response_bytes, KEY)

                # Send encrypted response back to client
                conn.sendall(encrypted_response)
                print(f"[<] Encrypted response sent: {encrypted_response}")
                print("[*] Connection closed.\n")

if __name__ == "__main__":
    main()
