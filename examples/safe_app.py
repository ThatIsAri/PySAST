"""Пример безопасного кода, который не должен содержать уязвимостей"""

import json
import sqlite3
import subprocess


def safe_sql_query(user_input: str):
    """Безопасный SQL запрос"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Безопасные запросы
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
    cursor.execute("SELECT * FROM products WHERE category = ? AND price > ?",
                   ("electronics", 100))


def safe_file_operations():
    """Безопасные операции с файлами"""
    # Безопасное открытие файла
    with open("/var/log/app.log", "r") as f:
        content = f.read()

    # Безопасные системные команды
    subprocess.run(["ls", "-la"])
    subprocess.call(["echo", "hello"])


def safe_data_handling():
    """Безопасная обработка данных"""
    # Безопасная десериализация
    data = '{"name": "test", "value": 123}'
    obj = json.loads(data)

    # Безопасная сериализация
    output = json.dumps(obj)

    return output


if __name__ == "__main__":
    safe_sql_query("test")
    safe_file_operations()
    result = safe_data_handling()
    print("Безопасный код выполнен успешно")