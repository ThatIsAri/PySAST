# Пример 1: Python SQL инъекция
def sql_injection_example(user_input: str):
    import sqlite3
    # УЯЗВИМЫЙ КОД: конкатенация строк
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Детектируется как PYTHON-SQLI-001
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)  # Уязвимость

    # Безопасная альтернатива (не детектируется)
    safe_query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(safe_query, (user_input,))


# Пример 2: Python Командная инъекция
def command_injection_example(filename: str):
    import os
    import subprocess
    # УЯЗВИМЫЙ КОД: использование пользовательского ввода в команде
    # Детектируется как PYTHON-CMD-001
    os.system(f"rm {filename}")  # Уязвимость

    # Безопасная альтернатива
    subprocess.run(["rm", filename])  # Безопасно


# Пример 3: Python Небезопасная десериализация
def insecure_deserialization(data: bytes):
    import pickle
    # УЯЗВИМЫЙ КОД
    # Детектируется как PYTHON-DES-001
    obj = pickle.loads(data)  # Уязвимость

    # Безопасная альтернатива
    import json
    safe_obj = json.loads(data.decode())  # Безопасно


# Пример 4: Java SQL инъекция (тест для Java анализатора)
java_code = """
public class TestJava {
    public void vulnerableMethod(String input) {
        String query = "SELECT * FROM users WHERE name = '" + input + "'";
        stmt.executeQuery(query); // Уязвимость
    }
}
"""

# Пример 5: PHP File Inclusion (тест для PHP анализатора)
php_code = """<?php
$page = $_GET['page'];
include($page . '.php'); // Уязвимость
?>
"""


# Тестирование анализа рисков
def test_risk_assessment():
    """Тест функции анализа рисков"""
    from pysast.core.risk_analyzer import RiskAnalyzer
    from pysast.core.base_analyzer import Vulnerability

    risk_analyzer = RiskAnalyzer()

    # Создаем тестовую уязвимость
    test_vuln = Vulnerability(
        file_path="/src/main.py",
        line_number=10,
        severity="HIGH",
        category="INJECTION",
        description="Test SQL Injection",
        pattern_id="PYTHON-SQLI-001",
        language="python",
        cwe_id="CWE-89",
        remediation="Use parameterized queries"
    )

    # Оцениваем риск
    assessment = risk_analyzer.assess_risk(test_vuln)

    print(f"Оценка риска: {assessment.risk_score:.2f}")
    print(f"Уровень риска: {assessment.risk_level}")
    print(f"Актив: {assessment.asset.name}")

    assert assessment.risk_score > 0
    print("✅ Тест анализа рисков пройден")


if __name__ == "__main__":
    test_risk_assessment()
    print("\nВсе тесты завершены успешно!")