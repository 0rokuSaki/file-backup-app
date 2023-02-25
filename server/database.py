from datetime import datetime
from protocol import *
import os.path
import sqlite3


class Client:
    def __init__(self, id: bytes, name: str, public_key: bytes, last_seen: datetime, aes_key: bytes) -> None:
        # Validate arguments
        if type(id) is not bytes:
            raise TypeError(f"Argument 'id' should be of type '{bytes}', not '{type(id)}'")
        if len(id) != Size.CLIENT_ID:
            raise ValueError(f"Argument 'id' should be of size '{Size.CLIENT_ID}', not {len(id)}")

        if type(name) is not str:
            raise TypeError(f"Argument 'name' should be of type '{str}', not '{type(name)}'")
        if len(name) >= Size.CLIENT_NAME:
            raise ValueError(f"Argument 'name' should be of size '{Size.CLIENT_NAME}', not {len(name)}")

        if type(public_key) is not bytes:
            raise TypeError(f"Argument 'public_key' should be of type '{bytes}', not '{type(public_key)}'")
        if len(public_key) != Size.PUBLIC_KEY:
            raise TypeError(f"Argument 'public_key' should be of size '{Size.PUBLIC_KEY}', not '{len(public_key)}'")

        if type(last_seen) is not datetime:
            raise TypeError(f"Argument 'last_seen' should be of type '{datetime}', not '{type(last_seen)}'")

        if type(aes_key) is not bytes:
            raise TypeError(f"Argument 'aes_key' should be of type '{bytes}', not '{type(aes_key)}'")
        if len(aes_key) != Size.AES_KEY:
            raise TypeError(f"Argument 'aes_key' should be of size '{Size.AES_KEY}', not '{len(aes_key)}'")

        self.id = id
        self.name = name
        self.public_key = public_key
        self.last_seen = str(last_seen)
        self.aes_key = aes_key


class File:
    def __init__(self, id: bytes, name: str, path: str, verified: bool) -> None:
        # Validate arguments
        if type(id) is not bytes:
            raise TypeError(f"Argument 'id' should be of type '{bytes}', not '{type(id)}'")
        if len(id) != Size.CLIENT_ID:
            raise ValueError(f"Argument 'id' should be of size '{Size.CLIENT_ID}', not {len(id)}")

        if type(name) is not str:
            raise TypeError(f"Argument 'name' should be of type '{str}', not '{type(name)}'")
        if len(name) >= Size.FILE_NAME:
            raise ValueError(f"Argument 'name' should be of size '{Size.FILE_NAME}', not {len(name)}")

        if type(path) is not str:
            raise TypeError(f"Argument 'path' should be of type '{str}', not '{type(path)}'")

        if type(verified) is not bool:
            raise TypeError(f"Argument 'verified' should be of type '{bool}', not '{type(verified)}'")

        self.id = id
        self.name = name
        self.path = path
        self.verified = verified


class Database:
    CLIENTS = 'clients'
    FILES = 'files'

    def __init__(self, name: str) -> None:
        self.name = name
        self.create_tables()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.name)  # doesn't raise an exception
        conn.text_factory = bytes
        return conn

    def execute_script(self, script: str) -> None:
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except:
            pass
        conn.close()

    def execute(self, query: str, args: list, commit=False):
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
        except Exception as e:
            print(f'Exception: {e}')
        conn.close()
        return results

    def create_tables(self) -> None:
        self.execute_script(f"""
            CREATE TABLE {Database.CLIENTS} (
                ID CHAR(16) NOT NULL PRIMARY KEY,
                Name CHAR(255) NOT NULL,
                PublicKey CHAR(160) NOT NULL,
                LastSeen DATE NOT NULL,
                AES CHAR(16) NOT NULL
            );
        """)

        self.execute_script(f"""
            CREATE TABLE {Database.FILES} (
                ID CHAR(16) NOT NULL PRIMARY KEY,
                Name CHAR(255) NOT NULL,
                Path CHAR(255) NOT NULL,
                Verified INTEGER
            );
        """)

    def client_name_exits(self, client_name: bytes) -> bool:
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ?", [client_name])
        if not results:
            return False
        return len(results) > 0

    def client_id_exists(self, client_id: bytes) -> bool:
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return False
        return len(results) > 0

    def store_client(self, client: Client) -> bool:
        return self.execute(f"INSERT INTO {Database.CLIENTS} VALUES (?, ?, ?, ?, ?)",
                            [client.id, client.name, client.public_key, client.last_seen, client.aes_key], commit=True)

    def set_client_public_key(self, client_id, public_key):
        return self.execute(f"UPDATE {Database.CLIENTS} SET PublicKey = ? WHERE ID = ?",
                            [public_key, client_id], commit=True)

    def set_client_last_seen(self, client_id: bytes, last_seen: datetime) -> bool:
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?",
                            [str(last_seen), client_id], commit=True)

    def set_client_aes_key(self, client_id: bytes, aes_key: bytes) -> bool:
        return self.execute(f"UPDATE {Database.CLIENTS} SET AES = ? WHERE ID = ?",
                            [aes_key, client_id], commit=True)

    def get_client_name(self, client_id: bytes) -> str:
        results = self.execute(f"SELECT Name FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return ''
        return results[0][0].decode('ascii')

    def get_client_public_key(self, client_id: bytes) -> bytes:
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return b''
        return results[0][0]

    def store_file(self, file: File) -> bool:
        return self.execute(f"INSERT INTO {Database.FILES} VALUES (?, ?, ?, ?)",
                            [file.id, file.name, file.path, file.verified], commit=True)

    def set_file_verified(self, client_id: bytes, file_name: str, verified: bool) -> bool:
        return self.execute(f"UPDATE {Database.FILES} SET Verified = ? WHERE ID = ? AND Name = ?",
                            [verified, client_id, file_name], commit=True)
