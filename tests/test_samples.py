#Пример 1: SQL инъекция
def sql_injection_example(user_input: str):
    import sqlite3

    #УЯЗВИМЫЙ КОД: конкатенация строк
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    #Детектируется как SQLI-001
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)  #Уязвимость

    #Безопасная альтернатива (не детектируется)
    safe_query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(safe_query, (user_input,))


#Пример 2: Командная инъекция
def command_injection_example(filename: str):
    import os
    import subprocess

    #УЯЗВИМЫЙ КОД: использование пользовательского ввода в команде
    #Детектируется как CMD-001
    os.system(f"rm {filename}")  #Уязвимость

    #Безопасная альтернатива
    subprocess.run(["rm", filename])  #Безопасно


#Пример 3: Небезопасная десериализация
def insecure_deserialization(data: bytes):
    import pickle

    # УЯЗВИМЫЙ КОД
    #Детектируется как DES-001
    obj = pickle.loads(data)  #Уязвимость

    #Безопасная альтернатива
    import json
    safe_obj = json.loads(data.decode())  #Безопасно


#Пример 4: Path Traversal
def path_traversal_example(filename: str):
    # УЯЗВИМЫЙ КОД
    # Детектируется как FI-001
    with open(filename, 'r') as f:  #Уязвимость
        content = f.read()

    #Безопасная альтернатива
    import os
    safe_path = os.path.normpath(filename)
    if not safe_path.startswith('/safe/directory/'):
        raise ValueError("Invalid path")


#Пример 5: XSS в Flask
def xss_example():
    from flask import Flask, render_template_string

    app = Flask(__name__)

    @app.route('/unsafe')
    def unsafe_route():
        user_input = "{{ malicious_code }}"  # Может быть из запроса
        #УЯЗВИМЫЙ КОД
        #Детектируется как XSS-001
        return render_template_string(f"<div>{user_input}</div>")  # Уязвимость!

    #Безопасная альтернатива
    from markupsafe import escape
    @app.route('/safe')
    def safe_route():
        user_input = "{{ malicious_code }}"
        return f"<div>{escape(user_input)}</div>"  # Безопасно