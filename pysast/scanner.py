import os
import time
from datetime import datetime
from typing import Dict, List, Any
from pysast.languages.python_analyzer import PythonAnalyzer
from pysast.languages.java_analyzer import JavaAnalyzer
from pysast.languages.php_analyzer import PHPAnalyzer
from pysast.core.risk_analyzer import RiskAnalyzer


class PySASTScanner:
    """Основной сканер с поддержкой нескольких языков"""

    def __init__(self):
        self.analyzers = {
            '.py': PythonAnalyzer(),
            '.java': JavaAnalyzer(),
            '.php': PHPAnalyzer()
        }
        self.risk_analyzer = RiskAnalyzer()
        self.scan_results = []
        self.stats = {
            'total_files': 0,
            'total_vulnerabilities': 0,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'severity_counts': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            'language_counts': {
                'python': 0,
                'java': 0,
                'php': 0
            }
        }

    def scan(self, path: str) -> Dict[str, List[Any]]:
        """Сканирование файла или директории"""
        self.scan_results = []
        self._reset_stats()

        if os.path.isfile(path):
            results = self._scan_file(path)
        else:
            results = self._scan_directory(path)

        return results

    def _scan_file(self, file_path: str) -> Dict[str, List[Any]]:
        """Сканирование одного файла"""
        _, extension = os.path.splitext(file_path)

        if extension not in self.analyzers:
            return {file_path: []}

        try:
            analyzer = self.analyzers[extension]
            vulnerabilities = analyzer.analyze_file(file_path)

            # Обновляем статистику
            self.stats['total_files'] += 1
            self.stats['total_vulnerabilities'] += len(vulnerabilities)

            language_name = analyzer.language
            if language_name in self.stats['language_counts']:
                self.stats['language_counts'][language_name] += len(vulnerabilities)

            for vuln in vulnerabilities:
                if vuln.severity in self.stats['severity_counts']:
                    self.stats['severity_counts'][vuln.severity] += 1

                # Добавление оценки рисков
                risk_assessment = self.risk_analyzer.assess_risk(vuln)
                vuln.risk_score = risk_assessment.risk_score
                vuln.asset_name = risk_assessment.asset.name

            self.scan_results.extend(vulnerabilities)
            return {file_path: vulnerabilities}
        except Exception as e:
            print(f"Ошибка при сканировании файла {file_path}: {e}")
            return {file_path: []}

    def _scan_directory(self, directory: str) -> Dict[str, List[Any]]:
        """Рекурсивное сканирование директории"""
        results = {}

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_results = self._scan_file(file_path)
                results.update(file_results)

        return results

    def _reset_stats(self):
        """Сброс статистики"""
        self.stats = {
            'total_files': 0,
            'total_vulnerabilities': 0,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'severity_counts': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            'language_counts': {
                'python': 0,
                'java': 0,
                'php': 0
            }
        }

    def generate_risk_report(self) -> Dict[str, Any]:
        """Генерация отчета по рискам"""
        return self.risk_analyzer.generate_risk_report(self.scan_results)

    def get_vulnerability_stats(self) -> Dict[str, Any]:
        """Получение статистики сканирования"""
        return self.stats.copy()

    def get_supported_extensions(self) -> List[str]:
        """Получение списка поддерживаемых расширений"""
        return list(self.analyzers.keys())

    def get_supported_languages(self) -> List[str]:
        """Получение списка поддерживаемых языков"""
        return [analyzer.language for analyzer in self.analyzers.values()]

    def generate_report(self, output_format: str = 'console', output_file: str = None):
        """Генерация отчета (заглушка для совместимости)"""
        # Эта функция реализуется в report_generator.py
        from pysast.report_generator import ReportGenerator

        report_gen = ReportGenerator()

        if output_format == 'json':
            return report_gen.generate_json_report(self.scan_results, self.stats)
        elif output_format == 'html':
            return report_gen.generate_html_report(self.scan_results, self.stats)
        elif output_format == 'markdown':
            return report_gen.generate_markdown_report(self.scan_results, self.stats)
        else:
            return report_gen.generate_console_report(self.scan_results, self.stats)

    def get_vulnerabilities_by_severity(self, severity: str) -> List[Any]:
        """Получить уязвимости по уровню серьезности"""
        return [v for v in self.scan_results if v.severity == severity]

    def get_vulnerabilities_by_language(self, language: str) -> List[Any]:
        """Получить уязвимости по языку программирования"""
        return [v for v in self.scan_results if v.language == language]

    def get_top_risks(self, limit: int = 10) -> List[Any]:
        """Получить топ наиболее рисковых уязвимостей"""
        return sorted(self.scan_results, key=lambda x: x.risk_score, reverse=True)[:limit]