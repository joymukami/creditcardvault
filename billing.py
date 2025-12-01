import mysql.connector
import hashlib
import binascii
from secrets import token_bytes

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'card_vault_db',
}

def create_user(username, password, role_id):
    salt = token_bytes(16)
    hex_salt = binascii.hexlify(salt).decode()
    pwd_hash = hashlib.sha256((hex_salt + password).encode('utf-8')).hexdigest()

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, salt, password_hash, role_id) VALUES (%s, %s, %s, %s)",
        (username, salt, pwd_hash, role_id)
    )
    conn.commit()
    cursor.close()
    conn.close()
    print("User created.")

create_user("Accountant2", "Accountee", 2)
