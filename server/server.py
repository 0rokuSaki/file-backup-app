from client_handler import ClientHandler
from database import *
import socket
import threading


class Server:
    DATABASE = 'server.db'
    VERSION = 3
    MAX_QUEUED_CONNECTIONS = 5  # Default maximum number of queued connections.
    TIMEOUT_SECONDS = 180

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.database = Database(Server.DATABASE)

    def listen(self):
        self.sock.listen(Server.MAX_QUEUED_CONNECTIONS)
        print(f'[Server] Listening on port: {self.port}.')
        while True:
            try:
                conn, addr = self.sock.accept()
                conn.settimeout(Server.TIMEOUT_SECONDS)
                threading.Thread(target=self._handle_client, args=(conn, addr)).start()
            except Exception as e:
                print(f"[Server] Main loop exception: {e}")

    def _handle_client(self, conn: socket, addr) -> None:
        print(f'[Server] Client connected: {addr}')
        ClientHandler(conn, addr, self.database).handle_client()


if __name__ == "__main__":
    port = 1234  # Default port number.
    try:
        with open('port.info', 'r') as port_info:
            temp_port = int(port_info.readline())
            if 0 <= temp_port <= 65535:  # Validate port number.
                port = temp_port
    except Exception as ex:
        print(f'Error reading port from port.info.\nDetails: {ex}')

    Server('localhost', port).listen()  # Start server.

