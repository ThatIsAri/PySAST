import re
from typing import List, Dict, Any
from pysast.core.base_analyzer import BaseAnalyzer, Vulnerability


class PHPAnalyzer(BaseAnalyzer):
    """Анализатор PHP кода"""

    def __init__(self):
        super().__init__("php")
        self.patterns = self._load_php_patterns()

    def _load_php_patterns(self) -> Dict[str, Any]:
        """Шаблоны уязвимостей для PHP"""
        return {
            'PHP-SQLI-001': {
                'name': 'PHP SQL Injection',
                'description': 'Использование переменных в SQL запросах без экранирования',
                'severity': 'HIGH',
                'category': 'INJECTION',
                'cwe_id': 'CWE-89',
                'regex': r'mysqli_query\(.*\..*\..*\)|mysql_query\(.*\..*\..*\)|->query\(.*\..*\..*\)'
            },
            'PHP-FI-001': {
                'name': 'PHP File Inclusion',
                'description': 'Использование include/require с пользовательским вводом',
                'severity': 'CRITICAL',
                'category': 'FILE_INCLUSION',
                'cwe_id': 'CWE-98',
                'regex': r'(include|require)(_once)?\s*\(.*\$_'
            },
            'PHP-CMD-001': {
                'name': 'PHP Command Injection',
                'description': 'Использование system/exec/shell_exec с пользовательским вводом',
                'severity': 'CRITICAL',
                'category': 'INJECTION',
                'cwe_id': 'CWE-78',
                'regex': r'(system|exec|shell_exec|passthru|proc_open)\s*\(.*\$_'
            },
            'PHP-XSS-001': {
                'name': 'PHP XSS Vulnerability',
                'description': 'Вывод пользовательского ввода без экранирования',
                'severity': 'MEDIUM',
                'category': 'XSS',
                'cwe_id': 'CWE-79',
                'regex': r'echo\s*\$_|print\s*\$_|<\?=\s*\$_'
            },
            'PHP-RCE-001': {
                'name': 'PHP Remote Code Execution',
                'description': 'Использование eval() с пользовательским вводом',
                'severity': 'CRITICAL',
                'category': 'RCE',
                'cwe_id': 'CWE-94',
                'regex': r'eval\s*\(.*\$_'
            }
        }

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Анализ PHP файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

            vulnerabilities = []
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                for pattern_id, pattern_info in self.patterns.items():
                    if re.search(pattern_info['regex'], line, re.IGNORECASE):
                        vuln = Vulnerability(
                            file_path=file_path,
                            line_number=line_num,
                            severity=pattern_info['severity'],
                            category=pattern_info['category'],
                            description=pattern_info['description'],
                            pattern_id=pattern_id,
                            language='php',
                            cwe_id=pattern_info['cwe_id'],
                            remediation=self._get_remediation(pattern_id)
                        )
                        vulnerabilities.append(vuln)

            return vulnerabilities
        except Exception as e:
            print(f"Ошибка при анализе PHP файла {file_path}: {e}")
            return []

    def _get_remediation(self, pattern_id: str) -> str:
        """Рекомендации по исправлению"""
        remediations = {
            'PHP-SQLI-001': 'Используйте подготовленные выражения PDO или mysqli с bind_param',
            'PHP-FI-001': 'Используйте whitelist разрешенных файлов',
            'PHP-CMD-001': 'Используйте escapeshellarg() или escapeshellcmd() для аргументов',
            'PHP-XSS-001': 'Используйте htmlspecialchars() или htmlentities() перед выводом',
            'PHP-RCE-001': 'Избегайте использования eval(), используйте альтернативные методы'
        }
        return remediations.get(pattern_id, 'Используйте безопасные функции PHP')

    def get_patterns(self) -> Dict[str, Any]:
        return self.patterns