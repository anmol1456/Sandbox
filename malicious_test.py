import os
import socket
import time

# Create multiple files to simulate file system changes
def create_files():
    for i in range(10):
        with open(f"malicious_file_{i}.txt", 'w') as f:
            f.write("This is a malicious file.\n" * 1000)
        time.sleep(1)

# Consume CPU resources
def consume_cpu():
    while True:
        pass  # Busy loop

# Attempt to make a network connection
def make_network_connection():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("example.com", 80))
        sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        response = sock.recv(4096)
        print(response.decode())
        sock.close()
    except Exception as e:
        print(f"Network connection failed: {e}")

if __name__ == "__main__":
    create_files()
    make_network_connection()
    consume_cpu()

