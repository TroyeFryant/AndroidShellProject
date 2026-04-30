"""
数据库连接池模块
"""

import pymysql
from contextlib import contextmanager

DB_CONFIG = {
    "host": "20.2.70.27",
    "port": 3306,
    "user": "root",
    "password": "qaz.060725",
    "database": "shell_protector",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}

@contextmanager
def get_db():
    conn = pymysql.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
