import os

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',  # XAMPP default root password
    'database': 'card_vault_db',
}

# AES key for encrypting/decrypting card numbers
AES_KEY = os.getenv('AES_KEY', 'my_secret_key_123')
