import sqlite3
from sqlite3 import Error


def connect_database():
    try:
        connection = sqlite3.connect('database/nonce_database.db')
        return connection
    except Error:
        print(Error)


def init_database():
    try:
        connection = connect_database()
        connection.cursor().execute("CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY);")
        connection.commit()
        print("INFO: Successfully created database and nonces table.")
    finally:
        connection.close()


def insert_nonce(nonce):
    try:
        connection = connect_database()
        connection.cursor().execute(
            'INSERT INTO nonces(nonce) VALUES(?)', [nonce])
        connection.commit()
        print("INFO: Nonce inserted in database.")
    finally:
        connection.close()


def exists_nonce(nonce):
    try:
        connection = connect_database()
        cursor = connection.cursor()
        cursor.execute(
            'SELECT COUNT(*) FROM nonces WHERE nonce = ?', [nonce])
        count = cursor.fetchone()[0]
        if count == 0:
            return False
        else:
            return True
    finally:
        connection.close()
