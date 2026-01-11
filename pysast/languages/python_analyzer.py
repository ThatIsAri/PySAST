import ast
import re
from typing import List, Dict, Any
from pysast.core.base_analyzer import BaseAnalyzer, Vulnerability


class PythonAnalyzer(BaseAnalyzer):
    """Анализатор Python кода"""

    def __init__(self):
        super().__init__("python")
        self.patterns = self._load_python_patterns()

    def _load_python_patterns(self) -> Dict[str, Any]:
        """Шаблоны уязвимостей для Python"""
        return {
            'PYTHON-SQLI-001': {
                'name': 'Python SQL Injection',
                'description': 'Конкатенация строк в SQL запросах',
                'severity': 'HIGH',
                'category': 'INJECTION',
                'cwe_id': 'CWE-89',
                'pattern_func': self._check_sql_injection_ast,
                'regex': r'execute\(.*\+.*\)|executemany\(.*\+.*\)'
            },
            'PYTHON-CMD-001': {
                'name': 'Python Command Injection',
                'description': 'Использование недоверенных данных в системных командах',
                'severity': 'CRITICAL',
                'category': 'INJECTION',
                'cwe_id': 'CWE-78',
                'pattern_func': self._check_command_injection_ast,
                'regex': r'(os|subprocess)\.(system|popen|call|run|Popen)\(.*\$'
            },
            'PYTHON-DES-001': {
                'name': 'Python Insecure Deserialization',
                'description': 'Использование pickle для десериализации недоверенных данных',
                'severity': 'HIGH',
                'category': 'INSECURE_DESERIALIZATION',
                'cwe_id': 'CWE-502',
                'pattern_func': self._check_pickle_deserialization_ast,
                'regex': r'pickle\.(loads|load)\('
            },
            'PYTHON-FI-001': {
                'name': 'Python Path Traversal',
                'description': 'Использование пользовательского ввода в путях к файлам',
                'severity': 'MEDIUM',
                'category': 'FILE_INCLUSION',
                'cwe_id': 'CWE-22',
                'pattern_func': self._check_path_traversal_ast,
                'regex': r'open\(.*\$.*\)'
            },
            'PYTHON-XSS-001': {
                'name': 'Python XSS Vulnerability',
                'description': 'Неэкранированный вывод пользовательских данных в веб-шаблонах',
                'severity': 'MEDIUM',
                'category': 'XSS',
                'cwe_id': 'CWE-79',
                'pattern_func': self._check_xss_ast,
                'regex': r'render_template_string\(.*\$|render_template\(.*\$'
            }
        }

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Анализ Python файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

            vulnerabilities = []

            # Попытка AST анализа
            try:
                tree = ast.parse(content)
                vulnerabilities.extend(self._analyze_with_ast(file_path, tree))
            except SyntaxError:
                # Если AST парсинг не удался, используем регулярные выражения
                vulnerabilities.extend(self._analyze_with_regex(file_path, content))

            return vulnerabilities

        except Exception as e:
            print(f"Ошибка при анализе Python файла {file_path}: {e}")
            return []

    def _analyze_with_ast(self, file_path: str, tree: ast.AST) -> List[Vulnerability]:
        """Анализ с использованием AST"""
        vulnerabilities = []

        for node in ast.walk(tree):
            for pattern_id, pattern_info in self.patterns.items():
                if pattern_info['pattern_func'](node):
                    line_no = node.lineno if hasattr(node, 'lineno') else 1

                    vuln = Vulnerability(
                        file_path=file_path,
                        line_number=line_no,
                        severity=pattern_info['severity'],
                        category=pattern_info['category'],
                        description=pattern_info['description'],
                        pattern_id=pattern_id,
                        language='python',
                        cwe_id=pattern_info['cwe_id'],
                        remediation=self._get_remediation(pattern_id)
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_with_regex(self, file_path: str, content: str) -> List[Vulnerability]:
        """Анализ с помощью регулярных выражений"""
        vulnerabilities = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern_id, pattern_info in self.patterns.items():
                if 'regex' in pattern_info and re.search(pattern_info['regex'], line):
                    vuln = Vulnerability(
                        file_path=file_path,
                        line_number=line_num,
                        severity=pattern_info['severity'],
                        category=pattern_info['category'],
                        description=pattern_info['description'],
                        pattern_id=pattern_id,
                        language='python',
                        cwe_id=pattern_info['cwe_id'],
                        remediation=self._get_remediation(pattern_id)
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    # Методы проверки AST
    def _check_sql_injection_ast(self, node: ast.AST) -> bool:
        """Проверка SQL инъекции в AST"""
        if isinstance(node, ast.Call):
            # Проверяем вызовы execute, executemany
            if hasattr(node.func, 'attr'):
                if node.func.attr in ['execute', 'executemany']:
                    if node.args and isinstance(node.args[0], ast.BinOp):
                        if isinstance(node.args[0].op, ast.Add):
                            return True
            # Проверяем строки с форматированием
            if node.args and isinstance(node.args[0], ast.JoinedStr):
                return True
        return False

    def _check_command_injection_ast(self, node: ast.AST) -> bool:
        """Проверка командной инъекции в AST"""
        if isinstance(node, ast.Call):
            dangerous_funcs = ['system', 'popen', 'call', 'Popen', 'run']

            # Проверяем os.system(), subprocess.run() и т.д.
            if hasattr(node.func, 'attr') and node.func.attr in dangerous_funcs:
                if node.args and not isinstance(node.args[0], ast.Constant):
                    return True

            # Проверяем полные пути
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in dangerous_funcs:
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        return True
        return False

    def _check_pickle_deserialization_ast(self, node: ast.AST) -> bool:
        """Проверка небезопасной десериализации в AST"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ['loads', 'load']:
                    if hasattr(node.func, 'value'):
                        if isinstance(node.func.value, ast.Name):
                            if node.func.value.id == 'pickle':
                                return True
        return False

    def _check_path_traversal_ast(self, node: ast.AST) -> bool:
        """Проверка Path Traversal в AST"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'open':
                if node.args and not isinstance(node.args[0], ast.Constant):
                    return True
        return False

    def _check_xss_ast(self, node: ast.AST) -> bool:
        """Проверка XSS в AST"""
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'attr'):
                if node.func.attr in ['render_template_string', 'render_template']:
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        return True
        return False

    def _get_remediation(self, pattern_id: str) -> str:
        """Рекомендации по исправлению"""
        remediations = {
            'PYTHON-SQLI-001': 'Используйте параметризованные запросы или ORM',
            'PYTHON-CMD-001': 'Используйте shlex.quote() или передавайте аргументы отдельно',
            'PYTHON-DES-001': 'Используйте безопасные форматы (json, yaml) или подписывайте данные',
            'PYTHON-FI-001': 'Валидируйте и нормализуйте пути, используйте whitelist',
            'PYTHON-XSS-001': 'Экранируйте HTML сущности или используйте безопасные шаблоны'
        }
        return remediations.get(pattern_id, 'Используйте безопасные практики программирования')

    def get_patterns(self) -> Dict[str, Any]:
        return self.patterns