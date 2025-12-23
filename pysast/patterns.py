""" Модуль определения шаблонов уязвимостей для Python кода """

import ast
from dataclasses import dataclass
from typing import Dict, List, Callable


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

        # XSS patterns (для веб-фреймворков)
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
            # Проверяем вызовы методов execute, executemany
            if hasattr(node.func, 'attr') and node.func.attr in ['execute', 'executemany']:
                if node.args:
                    arg = node.args[0]
                    # Проверяем конкатенацию строк
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        return True
                    # Проверяем форматирование строк
                    elif isinstance(arg, ast.Call):
                        if (isinstance(arg.func, ast.Attribute) and
                                arg.func.attr in ['format', 'format_map']):
                            return True
                    # Проверяем f-строки
                    elif isinstance(arg, ast.JoinedStr):
                        return True
        return False

    def _check_command_injection(self, node: ast.AST) -> bool:
        """Проверка на командную инъекцию"""
        if isinstance(node, ast.Call):
            # Проверяем вызовы os.system, subprocess.call и т.д.
            dangerous_funcs = [
                ('os', 'system'),
                ('os', 'popen'),
                ('subprocess', 'call'),
                ('subprocess', 'Popen'),
                ('subprocess', 'run')
            ]

            for module, func_name in dangerous_funcs:
                if self._is_function_call(node, module, func_name):
                    if node.args:
                        arg = node.args[0]
                        # Если аргумент - не строковый литерал
                        if not isinstance(arg, ast.Constant):
                            return True
        return False

    def _check_pickle_deserialization(self, node: ast.AST) -> bool:
        """Проверка на небезопасную десериализацию"""
        if isinstance(node, ast.Call):
            dangerous_calls = ['pickle.loads', 'pickle.load']
            for call in dangerous_calls:
                if self._is_function_call(node, *call.split('.')):
                    return True
        return False

    def _check_xss(self, node: ast.AST) -> bool:
        """Проверка на XSS (базовый уровень)"""
        if isinstance(node, ast.Call):
            # Для Flask/Jinja2: проверяем render_template с неэкранированными данными
            if self._is_function_call(node, None, 'render_template_string'):
                return True
        return False

    def _check_path_traversal(self, node: ast.AST) -> bool:
        """Проверка на Path Traversal"""
        if isinstance(node, ast.Call):
            # Проверяем открытие файлов с пользовательским вводом
            if isinstance(node.func, ast.Name) and node.func.id == 'open':
                if node.args and len(node.args) > 0:
                    arg = node.args[0]
                    # Если путь формируется из пользовательского ввода
                    if not isinstance(arg, ast.Constant):
                        return True
        return False

    def _is_function_call(self, node: ast.Call, module: str, func_name: str) -> bool:
        """Проверяет, является ли вызов функцией из указанного модуля"""
        if module is None:
            # Проверка по имени функции без модуля
            return (isinstance(node.func, ast.Name) and
                    node.func.id == func_name)
        else:
            # Проверка с модулем: module.func_name
            return (isinstance(node.func, ast.Attribute) and
                    node.func.attr == func_name and
                    isinstance(node.func.value, ast.Name) and
                    node.func.value.id == module)

    def get_all_patterns(self) -> List[VulnerabilityPattern]:
        """Получить все зарегистрированные шаблоны"""
        return list(self.patterns.values())