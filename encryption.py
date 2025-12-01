from cryptography.fernet import Fernet
import secrets

# Generate a key once and store securely (environment variable or file)
# Example: key = Fernet.generate_key()
key = b'bszjLrf7Gfk3BieQ1pO3FcxrIaFBUdxP8LCeWE27ucQ='  # replace with your key
cipher = Fernet(key)

def encrypt_card(card_number):
    """Encrypt card number (PAN)"""
    return cipher.encrypt(card_number.encode())

def decrypt_card(encrypted_card):
    """Decrypt PAN"""
    return cipher.decrypt(encrypted_card).decode()

def generate_token():
    """Generate a random unique card token"""
    return secrets.token_hex(16)  # 32 hex characters
