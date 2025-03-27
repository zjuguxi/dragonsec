import os
import sqlite3


def unsafe_sql_query(user_input):
    # SQL注入漏洞
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    return query


def unsafe_command(user_input):
    # 命令注入漏洞
    os.system(f"echo {user_input}")
    return True


def hardcoded_credentials():
    # 硬编码凭证
    password = "admin123"
    api_key = "sk-1234567890abcdefghijklmn"
    return password


def unsafe_path_traversal(filename):
    # 路径遍历漏洞
    with open(f"/var/data/{filename}", "r") as f:
        return f.read()
