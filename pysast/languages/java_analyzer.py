import re
from typing import List, Dict, Any
from pysast.core.base_analyzer import BaseAnalyzer, Vulnerability


class JavaAnalyzer(BaseAnalyzer):
    """Анализатор Java кода"""

    def __init__(self):
        super().__init__("java")
        self.patterns = self._load_java_patterns()

    def _load_java_patterns(self) -> Dict[str, Any]:
        """Шаблоны уязвимостей для Java"""
        return {
            'JAVA-SQLI-001': {
                'name': 'Java SQL Injection',
                'description': 'Конкатенация строк в SQL запросах JDBC',
                'severity': 'HIGH',
                'category': 'INJECTION',
                'cwe_id': 'CWE-89',
                'regex': r'\.executeQuery\(.*\+.*\)|\.executeUpdate\(.*\+.*\)|\.prepareStatement\(.*\+.*\)'
            },
            'JAVA-DES-001': {
                'name': 'Insecure Java Deserialization',
                'description': 'Использование readObject() без валидации',
                'severity': 'CRITICAL',
                'category': 'INSECURE_DESERIALIZATION',
                'cwe_id': 'CWE-502',
                'regex': r'\.readObject\(|ObjectInputStream\(|readObject\('
            },
            'JAVA-PT-001': {
                'name': 'Java Path Traversal',
                'description': 'Использование пользовательского ввода в путях файлов',
                'severity': 'MEDIUM',
                'category': 'FILE_INCLUSION',
                'cwe_id': 'CWE-22',
                'regex': r'new File\(.*\+.*\)|\.getResource\(.*\+.*\)|\.getResourceAsStream\(.*\+.*\)'
            },
            'JAVA-XSS-001': {
                'name': 'Java XSS Vulnerability',
                'description': 'Вывод пользовательского ввода без экранирования',
                'severity': 'MEDIUM',
                'category': 'XSS',
                'cwe_id': 'CWE-79',
                'regex': r'response\.getWriter\(\)\.print\(.*\$|response\.getWriter\(\)\.write\(.*\$'
            },
            'JAVA-CMD-001': {
                'name': 'Java Command Injection',
                'description': 'Использование Runtime.exec() с пользовательским вводом',
                'severity': 'CRITICAL',
                'category': 'INJECTION',
                'cwe_id': 'CWE-78',
                'regex': r'Runtime\.getRuntime\(\)\.exec\(.*\$|ProcessBuilder\(.*\$'
            }
        }

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Анализ Java файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

            vulnerabilities = []
            lines = content.split('\n')

            for line_num, line in enumerate(lines, 1):
                for pattern_id, pattern_info in self.patterns.items():
                    if re.search(pattern_info['regex'], line):
                        vuln = Vulnerability(
                            file_path=file_path,
                            line_number=line_num,
                            severity=pattern_info['severity'],
                            category=pattern_info['category'],
                            description=pattern_info['description'],
                            pattern_id=pattern_id,
                            language='java',
                            cwe_id=pattern_info['cwe_id'],
                            remediation=self._get_remediation(pattern_id)
                        )
                        vulnerabilities.append(vuln)

            return vulnerabilities
        except Exception as e:
            print(f"Ошибка при анализе Java файла {file_path}: {e}")
            return []

    def _get_remediation(self, pattern_id: str) -> str:
        """Рекомендации по исправлению"""
        remediations = {
            'JAVA-SQLI-001': 'Используйте PreparedStatement с параметризованными запросами',
            'JAVA-DES-001': 'Реализуйте whitelist десериализуемых классов, используйте validateObject()',
            'JAVA-PT-001': 'Валидируйте и нормализуйте пути к файлам',
            'JAVA-XSS-001': 'Используйте ESAPI.encoder().encodeForHTML() для экранирования',
            'JAVA-CMD-001': 'Используйте ProcessBuilder с раздельными аргументами'
        }
        return remediations.get(pattern_id, 'Используйте безопасные практики программирования')

    def get_patterns(self) -> Dict[str, Any]:
        return self.patterns