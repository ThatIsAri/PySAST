import ast
from dataclasses import dataclass
from typing import Dict, List, Callable, Any


@dataclass
class VulnerabilityPattern:
    """Класс для описания шаблона уязвимости"""
    id: str
    name: str
    description: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    cwe_id: str
    pattern_func: Callable[[ast.AST], bool]
    remediation: str


class PatternRegistry:
    """Реестр шаблонов уязвимостей"""

    def __init__(self):
        self.patterns: Dict[str, VulnerabilityPattern] = {}
        self._register_patterns()

    def _register_patterns(self):
        """Регистрация всех шаблонов"""
        # SQL Injection patterns
        self.patterns['SQLI-001'] = VulnerabilityPattern(
            id='SQLI-001',
            name='Potential SQL Injection',
            description='Обнаружено формирование SQL запроса через конкатенацию строк',
            category='INJECTION',
            severity='HIGH',
            cwe_id='CWE-89',
            pattern_func=self._check_sql_injection,
            remediation='Используйте параметризованные запросы или ORM'
        )

        # Command Injection patterns
        self.patterns['CMD-001'] = VulnerabilityPattern(
            id='CMD-001',
            name='Potential Command Injection',
            description='Использование недоверенных данных в вызовах системных команд',
            category='INJECTION',
            severity='CRITICAL',
            cwe_id='CWE-78',
            pattern_func=self._check_command_injection,
            remediation='Используйте shlex.quote() или подпроцессы с аргументами'
        )

        # Insecure Deserialization patterns
        self.patterns['DES-001'] = VulnerabilityPattern(
            id='DES-001',
            name='Insecure Deserialization',
            description='Использование pickle для десериализации недоверенных данных',
            category='INSECURE_DESERIALIZATION',
            severity='HIGH',
            cwe_id='CWE-502',
            pattern_func=self._check_pickle_deserialization,
            remediation='Используйте безопасные форматы (JSON, YAML) или подписывайте данные'
        )

        # XSS patterns
        self.patterns['XSS-001'] = VulnerabilityPattern(
            id='XSS-001',
            name='Potential Cross-Site Scripting',
            description='Неэкранированный вывод пользовательских данных в шаблонах',
            category='XSS',
            severity='MEDIUM',
            cwe_id='CWE-79',
            pattern_func=self._check_xss,
            remediation='Экранируйте HTML сущности или используйте безопасные шаблоны'
        )

        # File Inclusion patterns
        self.patterns['FI-001'] = VulnerabilityPattern(
            id='FI-001',
            name='Potential Path Traversal',
            description='Использование пользовательского ввода для формирования путей к файлам',
            category='FILE_INCLUSION',
            severity='MEDIUM',
            cwe_id='CWE-22',
            pattern_func=self._check_path_traversal,
            remediation='Валидируйте и нормализуйте пути, используйте whitelist'
        )

    def _check_sql_injection(self, node: ast.AST) -> bool:
        """Проверка на SQL инъекцию"""
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'attr') and node.func.attr in ['execute', 'executemany']:
                if node.args and isinstance(node.args[0], ast.BinOp):
                    if isinstance(node.args[0].op, ast.Add):
                        return True
        return False

    def _check_command_injection(self, node: ast.AST) -> bool:
        """Проверка на командную инъекцию"""
        if isinstance(node, ast.Call):
            dangerous_funcs = ['system', 'popen', 'call', 'Popen', 'run']

            if hasattr(node.func, 'attr') and node.func.attr in dangerous_funcs:
                if node.args and not isinstance(node.args[0], ast.Constant):
                    return True
        return False

    def _check_pickle_deserialization(self, node: ast.AST) -> bool:
        """Проверка на небезопасную десериализацию"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ['loads', 'load']:
                    if hasattr(node.func, 'value'):
                        if isinstance(node.func.value, ast.Name):
                            if node.func.value.id == 'pickle':
                                return True
        return False

    def _check_xss(self, node: ast.AST) -> bool:
        """Проверка на XSS"""
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'attr'):
                if node.func.attr in ['render_template_string', 'render_template']:
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        return True
        return False

    def _check_path_traversal(self, node: ast.AST) -> bool:
        """Проверка на Path Traversal"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'open':
                if node.args and not isinstance(node.args[0], ast.Constant):
                    return True
        return False

    def get_all_patterns(self) -> List[VulnerabilityPattern]:
        """Получить все зарегистрированные шаблоны"""
        return list(self.patterns.values())

    def get_pattern_by_id(self, pattern_id: str) -> VulnerabilityPattern:
        """Получить шаблон по ID"""
        return self.patterns.get(pattern_id)