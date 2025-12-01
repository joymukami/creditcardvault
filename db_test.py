import mysql.connector
from config import DB_CONFIG

try:
    conn = mysql.connector.connect(**DB_CONFIG)
    print("Connected to MariaDB successfully!")
    conn.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
