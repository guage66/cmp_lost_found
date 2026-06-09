import pymysql


DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "password",
    "database": "lost_found",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}


def get_db_connection():
    return pymysql.connect(**DB_CONFIG)
