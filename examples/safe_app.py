import json
import sqlite3
import subprocess
import os

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

def safe_path_handling(filename: str):
    """Безопасная обработка путей"""
    import os.path

    # Нормализация и проверка пути
    safe_path = os.path.normpath(filename)
    base_dir = "/safe/directory"

    # Проверка, что путь находится в разрешенной директории
    if os.path.commonprefix([base_dir, safe_path]) == base_dir:
        with open(safe_path, 'r') as f:
            return f.read()
    else:
        raise ValueError("Доступ к файлу запрещен")

if __name__ == "__main__":
    safe_sql_query("test")
    safe_file_operations()
    result = safe_data_handling()
    print("✅ Безопасный код выполнен успешно")