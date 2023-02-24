from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from database import *
from datetime import datetime
from protocol import *
import socket
import struct
import uuid
import zlib


class ClientHandler:
    PACKET_SIZE = 1024
    VERSION = 3

    def __init__(self, conn: socket, addr, db: Database):
        self.conn = conn
        self.addr = addr
        print(f'type of addr = {type(addr)}')  # TODO: remove this line later
        self.db = db
        self.session_key = get_random_bytes(Size.AES_KEY.value)
        self.iv = b'\x00' * 16
        self.version = bytes(ClientHandler.VERSION)

    def handle_client(self):
        try:
            active = True
            while active:
                client_id, client_ver, req_code, payload_size = self._read(REQ_HEADER)  # Receive request header
                print(f'Request received from client {self.addr}\n'
                      f'Client ID = {client_id}\n'
                      f'Client version = {client_ver}\n'
                      f'Request code = {ReqCode.name(req_code)}\n'
                      f'Payload size = {payload_size}\n')

                success = False
                if ReqCode.REGISTER == req_code:
                    success = self._handle_registration()
                elif ReqCode.KEY_EXCHANGE == req_code:
                    success = self._handle_key_exchange(client_id)
                elif ReqCode.LOGIN == req_code:
                    success = self._handle_login(client_id)
                elif ReqCode.BACKUP_FILE == req_code:
                    success = self._handle_file_backup(client_id)
                elif ReqCode.CRC_VALID == req_code:
                    success = self._handle_crc_valid()
                elif ReqCode.CRC_INVALID_RETRYING == req_code:
                    success = self._handle_crc_invalid_retry()
                elif ReqCode.CRC_INVALID_ABORTING == req_code:
                    success = self._handle_abort()

                if not success:
                    pass
        except Exception as e:
            print(f'Exception: {e}')

    def _read(self, fmt: str) -> tuple:
        data = self.conn.recv(REQUEST_SIZES[fmt])
        if not data:
            raise Exception(f'Client {self.addr} disconnected')
        return struct.unpack(fmt, data)

    def _write(self, fmt: str, code: int, *args) -> None:
        if RES_HEADER == fmt:
            self.conn.sendall(struct.pack(RES_HEADER, self.version, code, 0))
            return
        self.conn.sendall(struct.pack(RES_HEADER + fmt, self.version, code, RESPONSE_SIZES[fmt], args))

    def _handle_registration(self) -> ResCode.value:
        client_name = self._read(REQ_CLIENT_NAME_PAYLOAD)[0].replace(b'\x00', b'')

        # Check if client already exists
        if self.db.client_name_exits(client_name):
            print(f'Could not register client {client_name} - client already exists.')
            self._write(RES_HEADER, ResCode.REGISTER_FAILURE)
            return ResCode.REGISTER_FAILURE

        # Assign a new UUID for client (make sure it's unique in database)
        while self.db.client_uuid_exists(client_id := uuid.uuid4().bytes):
            pass

        # Create a client record in database
        client = Client(client_id, client_name, b'\x00' * Size.PUBLIC_KEY, str(datetime.now()))
        if not self.db.store_client(client):
            print(f'Failed to store client {client_name} in database.')
            return ResCode.GENERAL_FAILURE

        # Send success message
        print(f'Successfully registered client: {client_name}.')
        self._write(RES_CLIENT_ID_PAYLOAD, ResCode.REGISTER_SUCCESS, client_id)
        return ResCode.REGISTER_SUCCESS

    def _handle_key_exchange(self, client_id: bytes) -> ResCode.value:
        client_name, public_key = self._read(REQ_PUBLIC_KEY_PAYLOAD)
        client_name = client_name.replace(b'\x00', b'')

        # Check if client exists
        if not self.db.client_exists(client_id, client_name):
            print(f'Client {client_name} does not exit in database.')
            return ResCode.GENERAL_FAILURE  # TODO: determine what to do here

        # Set client's last seen
        if not self.db.set_last_seen(client_id, (datetime.now())):
            print(f'Could not set last seen for client {client_name}.')
            return ResCode.GENERAL_FAILURE

        # Set client's public key
        if not self.db.set_client_public_key(client_id, public_key):
            print(f'Could not set public key for client {client_name}')
            return ResCode.GENERAL_FAILURE

        # Encrypt session key and send it to client
        encrypted_session_key = PKCS1_OAEP.new(RSA.importKey(public_key)).encrypt(self.session_key)
        self._write(RES_ENCRYPTED_AES_PAYLOAD, ResCode.PUBLIC_KEY_RECEIVED, client_id, encrypted_session_key)
        return ResCode.PUBLIC_KEY_RECEIVED

    def _handle_login(self, client_id: bytes) -> ResCode.value:
        client_name = self._read(REQ_CLIENT_NAME_PAYLOAD)[0].replace(b'\x00', b'')

        # Check if client exists
        if not self.db.client_exists(client_id, client_name):
            print(f'Client {client_name} does not exit in database.')
            self._write(RES_CLIENT_ID_PAYLOAD, ResCode.LOGIN_FAILURE, client_id)
            return ResCode.LOGIN_FAILURE

        # Set client's last seen
        if not self.db.set_last_seen(client_id, (datetime.now())):
            print(f'Could not set last seen for client {client_name}.')
            return ResCode.GENERAL_FAILURE

        # Fetch public key from database
        public_key = self.db.get_client_public_key(client_id)
        if not public_key:
            print(f'Could not get public key for client {client_name}.')

        # Encrypt session key and send it to client
        encrypted_session_key = PKCS1_OAEP.new(RSA.importKey(public_key)).encrypt(self.session_key)
        self._write(RES_ENCRYPTED_AES_PAYLOAD, ResCode.LOGIN_SUCCESS, client_id, encrypted_session_key)
        return ResCode.LOGIN_SUCCESS

    def _handle_file_backup(self, client_id: bytes) -> ResCode.value:
        content_size, file_name = self._read(REQ_FILE_PAYLOAD)
        file_name = file_name.replace(b'\x00', b'')

        # Check if client exists
        if not self.db.client_uuid_exists(client_id):
            print(f'Client with UUID {client_id} does not exit in database.')
            return ResCode.GENERAL_FAILURE

        # Set client's last seen
        # TODO: Get client name here
        if not self.db.set_last_seen(client_id, (datetime.now())):
            print(f'Could not set last seen for client with UUID {client_id}.')
            return ResCode.GENERAL_FAILURE

        # Receive file in packets, decrypt & calculate checksum
        with open(file_name, 'wb') as file:
            cipher = AES.new(self.session_key, AES.MODE_CBC, self.iv)
            checksum = 0
            bytes_remaining = content_size
            while bytes_remaining:
                data = self.conn.recv(min(ClientHandler.PACKET_SIZE, bytes_remaining))
                decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
                file.write(decrypted_data)
                checksum = zlib.crc32(decrypted_data, checksum)
                bytes_remaining -= len(data)

        # Send checksum to client
        self._write(RES_CRC_PAYLOAD, ResCode.FILE_RECEIVED, client_id, content_size, file_name, checksum)
        return ResCode.FILE_RECEIVED

    def _handle_crc_valid(self) -> bool:
        pass

    def _handle_crc_invalid_retry(self) -> bool:
        pass

    def _handle_abort(self) -> bool:
        pass