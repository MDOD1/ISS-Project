import sqlite3
from utils import hash_password


def insert_file(data):
    file_name = data["file_name"]
    user_id = data["user_id"]
    content = data["content"]

    with sqlite3.connect("project.db") as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO documents (user_id, file_name, content)
            VALUES (?, ?, ?)
            """,
            (user_id, file_name, content),
        )
        connection.commit()


def insert_user(data):
    user_name = data["user_name"]
    nationality_number = data["nationality_number"]
    birth_date = data["birth_date"]
    phone_number = data["phone_number"]
    hashed_password = hash_password(data["password"])
    is_staff = data["is_staff"]

    with sqlite3.connect("project.db") as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO users (user_name, nationality_number, birth_date, phone_number, password, is_staff)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_name,
                nationality_number,
                birth_date,
                phone_number,
                hashed_password,
                is_staff,
            ),
        )
        connection.commit()


def get_file(id):
    with sqlite3.connect("project.db") as connection:
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT * FROM documents WHERE id = ?
            """,
            (id,),
        )
        columns = [description[0] for description in cursor.description]
        file = cursor.fetchone()
        if file:
            return dict(zip(columns, file))


def get_files(field, value):
    with sqlite3.connect("project.db") as connection:
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT id, user_id, file_name FROM documents WHERE {field} = ?
            """,
            (value,),
        )
        rows = cursor.fetchall()

        columns = [description[0] for description in cursor.description]
        files = [dict(zip(columns, row)) for row in rows]

        return files


def get_user(field, value):
    with sqlite3.connect("project.db") as connection:
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT id, password, is_staff FROM users WHERE {field} = ?
            """,
            (value,),
        )
        return cursor.fetchone()
