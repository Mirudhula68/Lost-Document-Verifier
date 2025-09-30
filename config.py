# config.py
import mysql.connector
from mysql.connector import Error

def get_db_connection():
    # update user, password as per your MySQL
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='root',
        database='lost_document_verifier'
    )
