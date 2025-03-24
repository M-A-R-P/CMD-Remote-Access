import socket
import ssl
import logging
import os
from threading import Thread
from dotenv import load_dotenv
from time import time
from uuid import uuid4
from traceback import format_exc

# Load environment variables
load_dotenv()

# Server configuration
HOST = os.getenv('SERVER_HOST', '0.0.0.0')
PORT = int(os.getenv('SERVER_PORT', 5000))
CERT_FILE = os.getenv('CERT_FILE', 'server.crt')
KEY_FILE = os.getenv('KEY_FILE', 'server.key')
VALID_CREDS = {
    'username': os.getenv('USERNAME', 'admin'),
    'password': os.getenv('PASSWORD', 'securepass123')
}

# Rate limiting (commands per minute per client)
RATE_LIMIT = 60  # Max 60 commands per minute
client_command_times = {}

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def sanitize_command(command):
    """Restrict commands to a safe subset."""
    allowed_commands = {'dir', 'cd', 'echo', 'type', 'exit'}  # Customize as needed
    cmd_parts = command.split()
    if cmd_parts and cmd_parts[0].lower() in allowed_commands:
        return command
    return None


def authenticate_client(conn):
    """Authenticate the client with username and password."""
    conn.send("Username: ".encode())
    username = conn.recv(1024).decode().strip()
    conn.send("Password: ".encode())
    password = conn.recv(1024).decode().strip()

    if username == VALID_CREDS['username'] and password == VALID_CREDS['password']:
        conn.send("Authentication successful".encode())
        return True
    conn.send("Authentication failed".encode())
    return False


def check_rate_limit(session_id):
    """Enforce rate limiting for commands."""
    current_time = time()
    if session_id not in client_command_times:
        client_command_times[session_id] = []

    # Remove commands older than 60 seconds
    client_command_times[session_id] = [t for t in client_command_times[session_id] if current_time - t < 60]

    if len(client_command_times[session_id]) >= RATE_LIMIT:
        return False
    client_command_times[session_id].append(current_time)
    return True


def handle_client(conn, addr):
    """Handle commands from an authenticated client."""
    session_id = str(uuid4())
    logging.info(f"New connection from {addr} with session ID {session_id}")

    # Set timeout to avoid hanging
    conn.settimeout(30)

    if not authenticate_client(conn):
        conn.close()
        return

    while True:
        try:
            command = input(f"Enter command for {addr} (Session: {session_id}) (or 'exit' to disconnect): ")
            sanitized_cmd = sanitize_command(command)
            if sanitized_cmd is None:
                print("Command not allowed.")
                continue

            if not check_rate_limit(session_id):
                conn.send("Rate limit exceeded. Try again later.".encode())
                logging.warning(f"Rate limit exceeded for {addr}, session {session_id}")
                continue

            if sanitized_cmd.lower() == 'exit':
                conn.send(sanitized_cmd.encode())
                break

            conn.send(sanitized_cmd.encode())
            response = conn.recv(4096).decode()
            print(f"Response from {addr}:\n{response}")
            logging.info(f"Command '{sanitized_cmd}' executed on {addr}, session {session_id}")

        except socket.timeout:
            logging.error(f"Timeout with {addr}, session {session_id}")
            break
        except (ConnectionError, ssl.SSLError) as e:
            logging.error(f"Connection error with {addr}, session {session_id}: {e}\n{format_exc()}")
            break
        except Exception as e:
            logging.error(f"Unexpected error with {addr}, session {session_id}: {e}\n{format_exc()}")
            break

    conn.close()
    logging.info(f"Connection with {addr}, session {session_id} closed")


def server_program():
    """Main server function with TLS and multi-client support."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='C:/CMD Remote Access/server.crt', keyfile='C:/CMD Remote Access/server.key')

    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging.info(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server_socket.accept()
            secure_conn = context.wrap_socket(conn, server_side=True)
            client_thread = Thread(target=handle_client, args=(secure_conn, addr))
            client_thread.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down")
    finally:
        server_socket.close()


if __name__ == '__main__':
    server_program()