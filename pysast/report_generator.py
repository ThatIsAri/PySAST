import json
from dataclasses import dataclass
from typing import List, Dict  # ← Убедитесь, что Any импортирован

from ast_analyzer import Vulnerability


@dataclass
class ScanSummary:
    """Сводка результатов сканирования"""
    total_files: int
    total_vulnerabilities: int
    scan_duration: float
    scan_date: str
    severity_counts: Dict[str, int]


class ReportGenerator:
    """Генератор отчетов в различных форматах"""

    def __init__(self):
        self.summary = None

    def generate_json_report(self, results: Dict[str, List[Vulnerability]],
                             summary: ScanSummary) -> str:
        """
        Генерирует отчет в формате JSON

        Args:
            results: Результаты анализа
            summary: Сводка сканирования

        Returns:
            JSON строка с отчетом
        """
        report = {
            "summary": {
                "total_files": summary.total_files,
                "total_vulnerabilities": summary.total_vulnerabilities,
                "scan_duration": summary.scan_duration,
                "scan_date": summary.scan_date,
                "severity_counts": summary.severity_counts
            },
            "vulnerabilities": {}
        }

        for file_path, vulns in results.items():
            report["vulnerabilities"][file_path] = [
                {
                    "pattern_id": v.pattern_id,
                    "line_number": v.line_number,
                    "severity": v.severity,
                    "description": v.description,
                    "remediation": v.remediation,
                    "cwe_id": v.cwe_id,
                    "code_snippet": v.code_snippet
                }
                for v in vulns
            ]

        return json.dumps(report, indent=2, ensure_ascii=False)

    def generate_console_report(self, results: Dict[str, List[Vulnerability]],
                                summary: ScanSummary):
        """Выводит краткий отчет в консоль"""
        print("\n" + "=" * 60)
        print("📊 ОТЧЕТ АНАЛИЗА БЕЗОПАСНОСТИ PySAST")
        print("=" * 60)

        print(f"\n📈 Сводка:")
        print(f"  Файлов проанализировано: {summary.total_files}")
        print(f"  Уязвимостей найдено: {summary.total_vulnerabilities}")
        print(f"  Время выполнения: {summary.scan_duration:.2f} с")
        print(f"  Дата сканирования: {summary.scan_date}")

        print(f"\n📊 Распределение по серьезности:")
        for severity, count in summary.severity_counts.items():
            if count > 0:
                print(f"  {severity}: {count}")

        print("\n" + "=" * 60)
        print("🔍 Детали уязвимостей:")
        print("=" * 60)

        total_shown = 0
        for file_path, vulns in results.items():
            if vulns:
                print(f"\n📄 {file_path}:")
                for vuln in vulns:
                    print(f"\n  [Line {vuln.line_number}] {vuln.severity}: {vuln.description}")
                    print(f"     ID: {vuln.pattern_id}, CWE: {vuln.cwe_id}")
                    print(f"     Рекомендация: {vuln.remediation}")

                    # Показываем только первые 3 строки кода
                    lines = vuln.code_snippet.split('\n')[:3]
                    if len(lines) > 0:
                        print(f"     Код: {lines[0]}")
                        if len(lines) > 1:
                            for line in lines[1:]:
                                print(f"           {line}")

                    total_shown += 1
                    if total_shown >= 10:  # Ограничиваем вывод
                        print(f"\n⚠️  Показано {total_shown} из {len(vulns)} уязвимостей. Полный отчет в файле.")
                        return

        if total_shown == 0:
            print("\n✅ Уязвимостей не обнаружено!")

