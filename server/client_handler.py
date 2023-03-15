from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from database import *
from datetime import datetime
from protocol import *
import os.path
import socket
import struct
import uuid
import zlib


class ClientHandler:
    PACKET_SIZE = 1024
    VERSION = b'\x03'

    def __init__(self, conn: socket, addr: tuple, db: Database):
        self.conn = conn
        self.addr = addr
        self.db = db
        self.session_key = get_random_bytes(Size.AES_KEY.value)
        self.client_id = b'\x00' * Size.CLIENT_ID
        self.client_name = ''

    def handle_client(self):
        try:
            session_active = True
            while session_active:
                client_id, client_ver, req_code, payload_size = self._read(REQ_HEADER)  # Receive request header

                print(f'\nRequest received from: {self.addr}\n'
                      f'Client ID = {uuid.UUID(bytes=client_id)}\n'
                      f"Client version = {int.from_bytes(client_ver, byteorder='little')}\n"
                      f'Request code = {req_code}\n'
                      f'Payload size = {payload_size}\n')

                rc = ResCode.GENERAL_FAILURE

                # Do not verify client ID on login or registration
                if ReqCode.REGISTER == req_code:
                    rc = self._handle_registration()
                elif ReqCode.LOGIN == req_code:
                    rc = self._handle_login(client_id)

                # Verify client ID for all other requests
                elif self.client_id != client_id:
                    pass

                elif ReqCode.KEY_EXCHANGE == req_code:
                    rc = self._handle_key_exchange()
                elif ReqCode.BACKUP_FILE == req_code:
                    rc = self._handle_file_backup()
                elif ReqCode.CRC_VALID == req_code:
                    rc = self._handle_crc_valid()
                    if ResCode.ACKNOWLEDGE == rc:
                        session_active = False
                elif ReqCode.CRC_INVALID_RETRYING == req_code:
                    rc = self._handle_crc_invalid_retry()
                elif ReqCode.CRC_INVALID_ABORTING == req_code:
                    rc = self._handle_abort()
                    session_active = False

                if ResCode.GENERAL_FAILURE == rc:
                    self._write(RES_HEADER, rc)
                    print(f"Server has encountered an error.")

        except Exception as e:
            print(f'Server has encountered a fatal error: {e}')

        print(f"Session with {self.addr} has been terminated.")

    def _read(self, fmt: str) -> tuple:
        data = self.conn.recv(REQUEST_SIZES[fmt])
        if not data:
            raise Exception(f'Client {self.addr} disconnected')
        return struct.unpack(fmt, data)

    def _write(self, fmt: str, code: int, *args) -> None:
        if RES_HEADER == fmt:
            self.conn.sendall(struct.pack(RES_HEADER, ClientHandler.VERSION, code, 0))
            return
        args = [RES_HEADER + fmt, ClientHandler.VERSION, code, RESPONSE_SIZES[fmt]] + list(args)
        self.conn.sendall(struct.pack(*args))

    def _handle_registration(self) -> int:
        print(f"Handling registration request for {self.addr}")
        self.client_name = self._read(REQ_CLIENT_NAME_PAYLOAD)[0].replace(b'\x00', b'').decode('ascii')

        # Check if client already exists
        if self.db.client_name_exits(self.client_name):
            print(f"Could not register client '{self.client_name}' - client already exists.")
            self._write(RES_HEADER, ResCode.REGISTER_FAILURE)
            return ResCode.REGISTER_FAILURE

        # Assign a new UUID for client (make sure it's unique in database)
        while True:
            self.client_id = uuid.uuid4().bytes
            if not self.db.client_id_exists(self.client_id):
                break

        # Create a client record in database
        client = Client(self.client_id, self.client_name, b'\x00' * Size.PUBLIC_KEY, datetime.now(), self.session_key)
        if not self.db.store_client(client):
            print(f"Failed to store client '{self.client_name}' in database.")
            return ResCode.GENERAL_FAILURE

        # Create a directory for files
        path_name = ".\\" + self.client_name
        try:
            if not os.path.exists(path_name):
                os.mkdir(path_name)
        except OSError as os_e:
            print(f"Failed to create a directory for client '{self.client_name}'.\n(Error: {os_e})")
            return ResCode.GENERAL_FAILURE

        # Send success message
        self._write(RES_CLIENT_ID_PAYLOAD, ResCode.REGISTER_SUCCESS, self.client_id)
        print(f"Successfully registered client '{self.client_name}'.")
        return ResCode.REGISTER_SUCCESS

    def _handle_login(self, client_id: bytes) -> int:
        print(f"Handling login request for {self.addr}")
        self.client_name = self._read(REQ_CLIENT_NAME_PAYLOAD)[0].replace(b'\x00', b'').decode('ascii')

        # Check if client exists
        if not self.db.client_id_exists(client_id):
            print(f"Client '{self.client_name}' does not exit in database.")
            self._write(RES_CLIENT_ID_PAYLOAD, ResCode.LOGIN_FAILURE, client_id)
            return ResCode.LOGIN_FAILURE
        self.client_id = client_id

        # Set client's last seen
        if not self.db.set_client_last_seen(client_id, datetime.now()):
            print(f"Could not set last seen for client '{self.client_name}'")
            return ResCode.GENERAL_FAILURE

        # Set client's session key
        if not self.db.set_client_aes_key(client_id, self.session_key):
            print(f"Could not set session key for client '{self.client_name}'")
            return ResCode.GENERAL_FAILURE

        # Fetch public key from database
        public_key = self.db.get_client_public_key(client_id)
        if not public_key:
            print(f"Could not retrieve public key for client '{self.client_name}'.")

        # Encrypt session key and send it to client
        encrypted_session_key = PKCS1_OAEP.new(RSA.importKey(public_key)).encrypt(self.session_key)
        print(f"Login successful, sending encrypted session key to client '{self.client_name}'")
        self._write(RES_ENCRYPTED_AES_PAYLOAD, ResCode.LOGIN_SUCCESS, client_id, encrypted_session_key)
        return ResCode.LOGIN_SUCCESS

    def _handle_key_exchange(self) -> int:
        print(f"Handling key exchange request for {self.addr}")
        client_name, public_key = self._read(REQ_PUBLIC_KEY_PAYLOAD)
        client_name = client_name.replace(b'\x00', b'').decode('ascii')

        if self.client_name != client_name:
            print(f"Client name '{client_name}' is incorrect (should be '{self.client_name}').")
            return ResCode.GENERAL_FAILURE

        # Set client's last seen
        if not self.db.set_client_last_seen(self.client_id, datetime.now()):
            print(f"Could not set last seen for client '{client_name}'.")
            return ResCode.GENERAL_FAILURE

        # Set client's public key
        if not self.db.set_client_public_key(self.client_id, public_key):
            print(f"Could not set public key for client '{client_name}'")
            return ResCode.GENERAL_FAILURE

        # Set client's session key
        if not self.db.set_client_aes_key(self.client_id, self.session_key):
            print(f"Could not set session key for client '{client_name}'")
            return ResCode.GENERAL_FAILURE

        # Encrypt session key and send it to client
        encrypted_session_key = PKCS1_OAEP.new(RSA.importKey(public_key)).encrypt(self.session_key)
        self._write(RES_ENCRYPTED_AES_PAYLOAD, ResCode.PUBLIC_KEY_RECEIVED, self.client_id, encrypted_session_key)
        print(f"Key exchange successful, sending encrypted session key to client '{client_name}'")
        return ResCode.PUBLIC_KEY_RECEIVED

    def _handle_file_backup(self) -> int:
        print(f"Handling file backup request for {self.addr}")
        content_size, file_name_raw = self._read(REQ_FILE_PAYLOAD)
        file_name = file_name_raw.replace(b'\x00', b'').decode('ascii')

        # Set client's last seen
        if not self.db.set_client_last_seen(self.client_id, datetime.now()):
            print(f"Could not set last seen for client '{self.client_name}'")
            return ResCode.GENERAL_FAILURE

        # Receive file in packets, decrypt & calculate checksum
        file_path = ".\\" + self.client_name + "\\" + file_name
        checksum = 0
        try:
            with open(file_path, 'wb') as file:
                cipher = AES.new(self.session_key, AES.MODE_CBC, iv=b'\x00' * 16)  # IV size is always 16
                bytes_remaining = content_size
                while bytes_remaining:
                    data = self.conn.recv(min(ClientHandler.PACKET_SIZE, bytes_remaining))
                    decrypted_data = cipher.decrypt(data)
                    if bytes_remaining <= ClientHandler.PACKET_SIZE:
                        decrypted_data = unpad(decrypted_data, AES.block_size)
                    file.write(decrypted_data)
                    checksum = zlib.crc32(decrypted_data, checksum)
                    bytes_remaining -= len(data)
        except OSError as os_e:
            print(f"Error during file backup: {os_e}")
            if os.path.exists(file_path):
                os.remove(file_path)
            return ResCode.GENERAL_FAILURE

        # If file with same name exists in database, set it's verified status to 'False'
        if self.db.file_exists(self.client_id, file_name):
            if not self.db.set_file_verified(self.client_id, file_name, False):
                print(f"Could not set verified for file '{file_name}'")
                return ResCode.GENERAL_FAILURE

        # Otherwise, create a new record for it in the database
        elif not self.db.store_file(File(self.client_id, file_name, file_path, False)):
            print(f"Failed to store file '{file_name}' in database.")
            return ResCode.GENERAL_FAILURE

        # Send checksum to client
        self._write(RES_CRC_PAYLOAD, ResCode.FILE_RECEIVED, self.client_id, content_size, file_name_raw, checksum)
        print(f"File received successfully, checksum = {checksum}")
        return ResCode.FILE_RECEIVED

    def _handle_crc_valid(self) -> int:
        print(f"Handling CRC valid request for {self.addr}")
        file_name = self._read(REQ_FILE_NAME_PAYLOAD)[0].replace(b'\x00', b'').decode('ascii')

        # Set client's last seen
        if not self.db.set_client_last_seen(self.client_id, datetime.now()):
            print(f"Could not set last seen for client '{self.client_name}'")
            return ResCode.GENERAL_FAILURE

        # Set file's verified
        if not self.db.set_file_verified(self.client_id, file_name, True):
            print(f"Could not set verified for file '{file_name}'")
            return ResCode.GENERAL_FAILURE

        self._write(RES_CLIENT_ID_PAYLOAD, ResCode.ACKNOWLEDGE, self.client_id)
        print(f"Successfully verified file '{file_name}'.")
        return ResCode.ACKNOWLEDGE

    def _handle_crc_invalid_retry(self) -> int:
        print(f"Handling CRC invalid request for {self.addr}")
        self._read(REQ_FILE_NAME_PAYLOAD)

        # Set client's last seen
        if not self.db.set_client_last_seen(self.client_id, datetime.now()):
            print(f"Could not set last seen for client '{self.client_name}'")
            return ResCode.GENERAL_FAILURE
        return 0

    def _handle_abort(self) -> int:
        print(f"Handling abort request for {self.addr}")
        self._read(REQ_FILE_NAME_PAYLOAD)

        # Set client's last seen
        if not self.db.set_client_last_seen(self.client_id, datetime.now()):
            print(f"Could not set last seen for client '{self.client_name}'")
            return ResCode.GENERAL_FAILURE
        self._write(RES_CLIENT_ID_PAYLOAD, ResCode.ACKNOWLEDGE, self.client_id)
        return ResCode.ACKNOWLEDGE
