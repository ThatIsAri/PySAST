import sqlite3
import os
import pickle


def sql_injection(user_input: str):
    """Пример SQL инъекции"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # УЯЗВИМЫЙ КОД: конкатенация строк
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)  # Должно обнаружиться как PYTHON-SQLI-001

    # Безопасная альтернатива (не должна обнаруживаться)
    safe_query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(safe_query, (user_input,))


def command_injection(filename: str):
    """Пример командной инъекции"""
    import subprocess

    # УЯЗВИМЫЙ КОД
    os.system(f"rm {filename}")  # Должно обнаружиться как PYTHON-CMD-001

    # Безопасная альтернатива
    subprocess.run(["ls", filename])  # Не должно обнаруживаться


def insecure_deserialization(data: bytes):
    """Пример небезопасной десериализации"""
    # УЯЗВИМЫЙ КОД
    obj = pickle.loads(data)  # Должно обнаружиться как PYTHON-DES-001

    # Безопасная альтернатива
    import json
    safe_obj = json.loads(data.decode())  # Не должно обнаруживаться


def path_traversal(filename: str):
    """Пример Path Traversal"""
    # УЯЗВИМЫЙ КОД
    with open(filename, 'r') as f:  # Должно обнаружиться как PYTHON-FI-001
        content = f.read()

    # Безопасная альтернатива
    import os
    safe_path = os.path.normpath(filename)
    if safe_path.startswith('/safe/directory/'):
        with open(safe_path, 'r') as f:
            content = f.read()


def xss_vulnerability(user_input: str):
    """Пример XSS уязвимости (для веб-фреймворков)"""
    from flask import render_template_string

    # УЯЗВИМЫЙ КОД
    template = f"<div>Welcome, {user_input}!</div>"
    return render_template_string(template)  # Должно обнаружиться как PYTHON-XSS-001


if __name__ == "__main__":
    # Тестовые вызовы
    sql_injection("test")
    command_injection("file.txt")
    insecure_deserialization(b"test")
    path_traversal("/etc/passwd")
    xss_vulnerability("<script>alert('XSS')</script>")