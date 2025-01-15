import sqlite3
import os


db_path = "project.db"

if os.path.exists(db_path):
    os.remove(db_path)

connection = sqlite3.connect("project.db")
cursor = connection.cursor()

cursor.execute("PRAGMA foreign_keys = ON;")

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT NOT NULL,
        nationality_number TEXT NOT NULL UNIQUE,
        birth_date DATE NOT NULL,
        phone_number TEXT NOT NULL,
        password TEXT NOT NULL,
        is_staff BOOLEAN NOT NULL DEFAULT 0
    )
"""
)

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        content BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
"""
)

connection.commit()
connection.close()

print("Database and tables have been recreated successfully.")
