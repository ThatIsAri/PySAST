
import ast
import os
from dataclasses import dataclass
from typing import List, Dict  # ← Убедитесь, что Any импортирован

from patterns import PatternRegistry, VulnerabilityPattern


@dataclass
class Vulnerability:
    """Класс для представления найденной уязвимости"""
    pattern_id: str
    file_path: str
    line_number: int
    code_snippet: str
    severity: str
    description: str
    remediation: str
    cwe_id: str


class ASTAnalyzer:
    """Анализатор AST Python кода"""

    def __init__(self):
        self.pattern_registry = PatternRegistry()
        self.vulnerabilities: List[Vulnerability] = []

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """
        Анализирует файл Python на наличие уязвимостей

        Args:
            file_path: Путь к файлу для анализа

        Returns:
            Список найденных уязвимостей
        """
        self.vulnerabilities.clear()

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            # Парсинг исходного кода в AST
            tree = ast.parse(source_code, filename=file_path)

            # Обход AST и поиск уязвимостей
            self._visit_nodes(tree, file_path, source_code)

            return self.vulnerabilities.copy()

        except SyntaxError as e:
            print(f"Ошибка синтаксиса в файле {file_path}: {e}")
            return []
        except Exception as e:
            print(f"Ошибка при анализе файла {file_path}: {e}")
            return []

    def analyze_directory(self, directory_path: str) -> Dict[str, List[Vulnerability]]:
        """
        Рекурсивно анализирует все Python файлы в директории

        Args:
            directory_path: Путь к директории для анализа

        Returns:
            Словарь с результатами анализа по файлам
        """
        results = {}

        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    vulnerabilities = self.analyze_file(file_path)
                    if vulnerabilities:
                        results[file_path] = vulnerabilities

        return results

    def _visit_nodes(self, node: ast.AST, file_path: str, source_code: str):
        """Рекурсивный обход узлов AST"""

        # Проверяем текущий узел на соответствие шаблонам уязвимостей
        for pattern in self.pattern_registry.get_all_patterns():
            if pattern.pattern_func(node):
                self._add_vulnerability(node, pattern, file_path, source_code)

        # Рекурсивный обход дочерних узлов
        for child in ast.iter_child_nodes(node):
            self._visit_nodes(child, file_path, source_code)

    def _add_vulnerability(self, node: ast.AST, pattern: VulnerabilityPattern,
                           file_path: str, source_code: str):
        """Добавляет найденную уязвимость в список"""

        # Получаем номер строки
        line_number = getattr(node, 'lineno', 0)

        # Получаем фрагмент кода
        code_snippet = self._get_code_snippet(source_code, line_number)

        vulnerability = Vulnerability(
            pattern_id=pattern.id,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            severity=pattern.severity,
            description=pattern.description,
            remediation=pattern.remediation,
            cwe_id=pattern.cwe_id
        )

        self.vulnerabilities.append(vulnerability)

    def _get_code_snippet(self, source_code: str, line_number: int) -> str:
        """Извлекает фрагмент кода вокруг указанной строки"""
        lines = source_code.split('\n')

        if 0 <= line_number - 1 < len(lines):
            start = max(0, line_number - 3)
            end = min(len(lines), line_number + 2)
            snippet_lines = lines[start:end]

            # Добавляем номера строк
            snippet = '\n'.join([f"{i + 1}: {line}" for i, line in
                                 enumerate(snippet_lines, start=start)])
            return snippet

        return ""