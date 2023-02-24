from protocol import *
import os.path
import sqlite3


class Client:
    def __init__(self, uuid, name, public_key, last_seen):
        self.uuid = uuid
        self.name = name
        self.public_key = public_key
        self.last_seen = last_seen

    def validate(self) -> bool:
        if not self.uuid or Size.UUID != len(self.uuid):
            return False
        if not self.name or Size.USER_NAME <= len(self.name):
            return False
        if not self.public_key or Size.PUBLIC_KEY != len(self.public_key):
            return False
        if not self.last_seen:
            return False
        return True


class File:
    def __init__(self, owner_uuid, name, path, verified):
        self.owner_uuid = owner_uuid
        self.name = name
        self.path = path
        self.verified = verified

    def validate(self) -> bool:
        if not self.owner_uuid or Size.UUID != len(self.owner_uuid):
            return False
        if not self.name or Size.FILE_NAME != len(self.name):
            return False
        if not os.path.isfile(self.path):
            return False
        if not type(self.verified) is bool:
            return False
        return True


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

    def execute(self, query: str, args: str, commit=False):
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
            print(f'[Database] Exception: {e}')
        conn.close()
        return results

    def create_tables(self) -> None:
        self.execute_script(f"""
            CREATE TABLE {Database.CLIENTS} (
                UUID CHAR(16) NOT NULL PRIMARY KEY,
                Name CHAR(255) NOT NULL,
                PublicKey CHAR(160) NOT NULL,
                LastSeen DATE
            );
        """)

        self.execute_script(f"""
            CREATE TABLE {Database.FILES} (
                OwnerUUID CHAR(16) NOT NULL PRIMARY KEY,
                Name CHAR(255) NOT NULL,
                Path CHAR(255) NOT NULL,
                Verified INTEGER
            );
        """)

    def client_name_exits(self, name) -> bool:
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ?", [name])
        if not results:
            return False
        return len(results) > 0

    def client_uuid_exists(self, uuid) -> bool:
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE UUID = ?", [uuid])
        if not results:
            return False
        return len(results) > 0

    def client_exists(self, uuid, name) -> bool:
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE UUID = ? AND Name = ?", [uuid, name])
        if not results:
            return False
        return len(results) > 0

    def store_client(self, client: Client) -> bool:
        if not type(client) is Client or not client.validate():
            return False
        return self.execute(f"INSERT INTO {Database.CLIENTS} VALUES (?, ?, ?, ?)",
                            [client.uuid, client.name, client.public_key, client.last_seen], commit=True)

    def set_last_seen(self, client_uuid, last_seen) -> bool:
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE UUID = ?",
                            [last_seen, client_uuid], commit=True)

    def set_client_public_key(self, client_uuid, public_key):
        return self.execute(f"UPDATE {Database.CLIENTS} SET PublicKey = ? WHERE UUID = ?",
                            [public_key, client_uuid], commit=True)

    def get_client_public_key(self, client_uuid):
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS} WHERE UUID = ?", [client_uuid])
        if not results:
            return None
        return results[0][0]

    def set_verified(self, owner_uuid, file_name, verified) -> bool:
        return self.execute(f"UPDATE {Database.FILES} SET Verified = ? WHERE OwnerUUID = ? AND Name = ?",
                            [verified, owner_uuid, file_name], commit=True)

