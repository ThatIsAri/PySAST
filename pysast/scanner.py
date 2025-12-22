import os
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

# Обратите внимание на точку перед импортами - это относительный импорт
try:
    from .ast_analyzer import ASTAnalyzer, Vulnerability
    from .report_generator import ReportGenerator, ScanSummary
except ImportError:
    # Если относительные импорты не работают
    from ast_analyzer import ASTAnalyzer, Vulnerability
    from report_generator import ReportGenerator, ScanSummary


class PySASTScanner:
    """Основной класс сканера безопасности"""

    def __init__(self):
        self.analyzer = ASTAnalyzer()
        self.report_generator = ReportGenerator()
        self.scan_results: Dict[str, List[Vulnerability]] = {}
        self.summary = None


class PySASTScanner:
    """Основной класс сканера безопасности"""

    def __init__(self):
        self.analyzer = ASTAnalyzer()
        self.report_generator = ReportGenerator()
        self.scan_results: Dict[str, List[Vulnerability]] = {}

    def scan(self, target_path: str) -> Dict[str, List[Vulnerability]]:
        """
        Выполняет сканирование указанного пути
        """
        print(f"🔍 Начало сканирования: {target_path}")
        start_time = time.time()

        if os.path.isfile(target_path) and target_path.endswith('.py'):
            # Сканирование одного файла
            vulnerabilities = self.analyzer.analyze_file(target_path)
            self.scan_results[target_path] = vulnerabilities
            total_files = 1

        elif os.path.isdir(target_path):
            # Рекурсивное сканирование директории
            self.scan_results = self.analyzer.analyze_directory(target_path)
            total_files = len(self.scan_results)

        else:
            raise ValueError(f"Неверный путь: {target_path}")

        scan_duration = time.time() - start_time

        # Подсчет уязвимостей по серьезности
        severity_counts = self._count_vulnerabilities_by_severity()
        total_vulnerabilities = sum(severity_counts.values())

        # Создание сводки
        self.summary = ScanSummary(
            total_files=total_files,
            total_vulnerabilities=total_vulnerabilities,
            scan_duration=scan_duration,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            severity_counts=severity_counts
        )

        # Вывод результатов
        self._print_scan_summary(self.summary)  # ← Этот метод должен вызываться!

        return self.scan_results  # ← Важно: возвращаем результаты

    def _count_vulnerabilities_by_severity(self) -> Dict[str, int]:
        """Подсчитывает количество уязвимостей по уровням серьезности"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }

        for vulns in self.scan_results.values():
            for vuln in vulns:
                if vuln.severity in severity_counts:
                    severity_counts[vuln.severity] += 1

        return severity_counts

    def _print_scan_summary(self, summary: ScanSummary):
        """Выводит сводку сканирования в консоль"""
        print("\n" + "=" * 50)
        print("📊 СВОДКА СКАНИРОВАНИЯ")
        print("=" * 50)
        print(f"Файлов проанализировано: {summary.total_files}")
        print(f"Уязвимостей найдено: {summary.total_vulnerabilities}")
        print(f"Время выполнения: {summary.scan_duration:.2f} секунд")
        print(f"Дата сканирования: {summary.scan_date}")
        print("\nРаспределение по серьезности:")

        for severity, count in summary.severity_counts.items():
            if count > 0:
                print(f"  {severity}: {count}")

        print("=" * 50)

    def generate_report(self, output_format: str = 'html',
                        output_file: Optional[str] = None):
        """
        Генерирует отчет в указанном формате

        Args:
            output_format: Формат отчета (json, html, markdown, console)
            output_file: Путь для сохранения отчета (опционально)
        """
        if not self.scan_results:
            print("❌ Нет результатов сканирования. Сначала выполните scan().")
            return

        if not self.summary:
            print("❌ Отсутствует сводка сканирования.")
            return

        # Генерация отчета
        if output_format == 'json':
            report = self.report_generator.generate_json_report(
                self.scan_results, self.summary)
            ext = '.json'

        elif output_format == 'html':
            report = self.report_generator.generate_html_report(
                self.scan_results, self.summary)
            ext = '.html'

        elif output_format == 'markdown':
            report = self.report_generator.generate_markdown_report(
                self.scan_results, self.summary)
            ext = '.md'

        elif output_format == 'console':
            # Выводим отчет прямо в консоль
            self.report_generator.generate_console_report(
                self.scan_results, self.summary)
            return  # Не сохраняем в файл

        else:
            raise ValueError(f"Неподдерживаемый формат: {output_format}")

        # Сохранение или вывод отчета
        if output_file:
            self.report_generator.save_report(report, output_file)
        else:
            # Автоматическое имя файла
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"pysast_report_{timestamp}{ext}"
            self.report_generator.save_report(report, output_file)

    def get_vulnerability_stats(self) -> Dict[str, Any]:
        """Возвращает статистику найденных уязвимостей"""
        if not hasattr(self, 'summary'):
            return {}

        return {
            'total_files': self.summary.total_files,
            'total_vulnerabilities': self.summary.total_vulnerabilities,
            'severity_counts': self.summary.severity_counts,
            'scan_date': self.summary.scan_date
        }