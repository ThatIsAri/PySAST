import json
import os
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class ScanSummary:
    """Сводка по сканированию"""
    total_files: int
    total_vulnerabilities: int
    scan_duration: float
    scan_date: str
    severity_counts: Dict[str, int]
    language_counts: Dict[str, int]


class ReportGenerator:
    """Генератор отчетов"""

    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')

    def generate_console_report(self, results: Dict[str, List[Any]],
                                summary: Dict[str, Any] = None) -> str:
        """Генерация консольного отчета"""
        report_lines = []

        report_lines.append("=" * 80)
        report_lines.append("PySAST - ОТЧЕТ СКАНИРОВАНИЯ БЕЗОПАСНОСТИ")
        report_lines.append("=" * 80)

        if summary:
            report_lines.append(f"\n📊 СВОДКА:")
            report_lines.append(f"  Файлов проанализировано: {summary.get('total_files', 0)}")
            report_lines.append(f"  Уязвимостей обнаружено: {summary.get('total_vulnerabilities', 0)}")
            report_lines.append(f"  Дата сканирования: {summary.get('scan_date', 'N/A')}")

            severity_counts = summary.get('severity_counts', {})
            if severity_counts:
                report_lines.append(f"\n  Уровни серьезности:")
                for severity, count in severity_counts.items():
                    if count > 0:
                        severity_icon = self._get_severity_icon(severity)
                        report_lines.append(f"    {severity_icon} {severity}: {count}")

        # Детализация по файлам
        if results:
            report_lines.append("\n" + "=" * 80)
            report_lines.append("ДЕТАЛИЗАЦИЯ УЯЗВИМОСТЕЙ:")
            report_lines.append("=" * 80)

            for file_path, vulnerabilities in results.items():
                if vulnerabilities:
                    report_lines.append(f"\n📄 Файл: {file_path}")

                    for i, vuln in enumerate(vulnerabilities, 1):
                        severity_icon = self._get_severity_icon(vuln.severity)
                        report_lines.append(f"\n  {i}. {severity_icon} {vuln.description}")
                        report_lines.append(f"     Строка: {vuln.line_number}")
                        report_lines.append(f"     Уровень: {vuln.severity}")
                        report_lines.append(f"     Категория: {vuln.category}")
                        report_lines.append(f"     CWE ID: {vuln.cwe_id}")
                        report_lines.append(f"     Язык: {vuln.language}")
                        if hasattr(vuln, 'risk_score') and vuln.risk_score > 0:
                            report_lines.append(f"     Оценка риска: {vuln.risk_score:.2f}")
                        report_lines.append(f"     Рекомендация: {vuln.remediation}")

        else:
            report_lines.append("\n✅ Уязвимостей не обнаружено!")

        report_lines.append("\n" + "=" * 80)
        report_lines.append("Сканирование завершено")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)

    def generate_risk_report(self, risk_data: Dict[str, Any]) -> str:
        """Генерация отчета по рискам"""
        report_lines = []

        report_lines.append("=" * 80)
        report_lines.append("АНАЛИЗ РИСКОВ БЕЗОПАСНОСТИ")
        report_lines.append("=" * 80)

        report_lines.append(f"\n📊 ОБЩАЯ СТАТИСТИКА:")
        report_lines.append(f"  Всего рисков: {risk_data.get('total_risks', 0)}")
        report_lines.append(f"  Общая оценка риска: {risk_data.get('total_risk_score', 0):.2f}")
        report_lines.append(f"  Средняя оценка риска: {risk_data.get('average_risk_score', 0):.2f}")

        risk_levels = risk_data.get('risk_levels', {})
        if risk_levels:
            report_lines.append(f"\n  Распределение по уровням риска:")
            for level, count in risk_levels.items():
                if count > 0:
                    report_lines.append(f"    {self._get_risk_level_icon(level)} {level}: {count}")

        # Риски по активам
        risk_by_asset = risk_data.get('risk_by_asset', {})
        if risk_by_asset:
            report_lines.append(f"\n  Риски по активам:")
            for asset, count in risk_by_asset.items():
                report_lines.append(f"    📦 {asset}: {count} рисков")

        # Топ-5 рисков
        top_risks = risk_data.get('top_risks', [])
        if top_risks:
            report_lines.append("\n" + "=" * 80)
            report_lines.append("ТОП-5 НАИБОЛЕЕ РИСКОВЫХ УЯЗВИМОСТЕЙ:")
            report_lines.append("=" * 80)

            for i, risk in enumerate(top_risks, 1):
                report_lines.append(f"\n  {i}. {risk['vulnerability']}")
                report_lines.append(f"     Файл: {risk['file']}:{risk['line']}")
                report_lines.append(f"     Актив: {risk['asset']}")
                report_lines.append(f"     Вероятность: {risk['probability']}")
                report_lines.append(f"     Воздействие: {risk['impact']}")
                report_lines.append(f"     Оценка риска: {risk['risk_score']} ({risk['risk_level']})")

        report_lines.append("\n" + "=" * 80)
        report_lines.append("Анализ рисков завершен")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)

    def generate_json_report(self, results: Dict[str, List[Any]],
                             summary: Dict[str, Any]) -> str:
        """Генерация JSON отчета"""
        report_data = {
            'scan_summary': summary,
            'vulnerabilities': [],
            'timestamp': datetime.now().isoformat()
        }

        for file_path, vulnerabilities in results.items():
            for vuln in vulnerabilities:
                vuln_dict = {
                    'file': file_path,
                    'line': vuln.line_number,
                    'severity': vuln.severity,
                    'category': vuln.category,
                    'description': vuln.description,
                    'pattern_id': vuln.pattern_id,
                    'language': vuln.language,
                    'cwe_id': vuln.cwe_id,
                    'remediation': vuln.remediation
                }

                if hasattr(vuln, 'risk_score'):
                    vuln_dict['risk_score'] = vuln.risk_score

                report_data['vulnerabilities'].append(vuln_dict)

        return json.dumps(report_data, indent=2, ensure_ascii=False)

    def generate_html_report(self, results: Dict[str, List[Any]],
                             summary: Dict[str, Any]) -> str:
        """Генерация HTML отчета"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>PySAST - Отчет сканирования безопасности</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
                .critical { border-left: 5px solid #dc3545; }
                .high { border-left: 5px solid #fd7e14; }
                .medium { border-left: 5px solid #ffc107; }
                .low { border-left: 5px solid #28a745; }
                .severity { font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; }
                .severity-critical { background: #dc3545; }
                .severity-high { background: #fd7e14; }
                .severity-medium { background: #ffc107; color: #333; }
                .severity-low { background: #28a745; }
            </style>
        </head>
        <body>
            <h1>PySAST - Отчет сканирования безопасности</h1>
            <div class="summary">
                <h2>Сводка</h2>
                <p><strong>Файлов проанализировано:</strong> {total_files}</p>
                <p><strong>Уязвимостей обнаружено:</strong> {total_vulnerabilities}</p>
                <p><strong>Дата сканирования:</strong> {scan_date}</p>
            </div>
        """.format(**summary)

        if results:
            html += "<h2>Детализация уязвимостей</h2>"

            for file_path, vulnerabilities in results.items():
                if vulnerabilities:
                    html += f"<h3>Файл: {file_path}</h3>"

                    for vuln in vulnerabilities:
                        severity_class = f"severity-{vuln.severity.lower()}"
                        html += f"""
                        <div class="vulnerability {vuln.severity.lower()}">
                            <div class="severity {severity_class}">{vuln.severity}</div>
                            <h4>{vuln.description}</h4>
                            <p><strong>Строка:</strong> {vuln.line_number}</p>
                            <p><strong>Категория:</strong> {vuln.category}</p>
                            <p><strong>CWE ID:</strong> {vuln.cwe_id}</p>
                            <p><strong>Язык:</strong> {vuln.language}</p>
                            <p><strong>Рекомендация:</strong> {vuln.remediation}</p>
                        </div>
                        """

        html += """
        </body>
        </html>
        """

        return html

    def generate_markdown_report(self, results: Dict[str, List[Any]],
                                 summary: Dict[str, Any]) -> str:
        """Генерация Markdown отчета"""
        md = "# PySAST - Отчет сканирования безопасности\n\n"

        md += "## Сводка\n\n"
        md += f"- **Файлов проанализировано:** {summary.get('total_files', 0)}\n"
        md += f"- **Уязвимостей обнаружено:** {summary.get('total_vulnerabilities', 0)}\n"
        md += f"- **Дата сканирования:** {summary.get('scan_date', 'N/A')}\n"

        severity_counts = summary.get('severity_counts', {})
        if severity_counts:
            md += "\n## Уровни серьезности\n\n"
            for severity, count in severity_counts.items():
                if count > 0:
                    md += f"- **{severity}:** {count}\n"

        if results:
            md += "\n## Детализация уязвимостей\n\n"

            for file_path, vulnerabilities in results.items():
                if vulnerabilities:
                    md += f"### Файл: `{file_path}`\n\n"

                    for i, vuln in enumerate(vulnerabilities, 1):
                        md += f"#### {i}. {vuln.description}\n\n"
                        md += f"- **Строка:** {vuln.line_number}\n"
                        md += f"- **Уровень:** {vuln.severity}\n"
                        md += f"- **Категория:** {vuln.category}\n"
                        md += f"- **CWE ID:** {vuln.cwe_id}\n"
                        md += f"- **Язык:** {vuln.language}\n"
                        if hasattr(vuln, 'risk_score') and vuln.risk_score > 0:
                            md += f"- **Оценка риска:** {vuln.risk_score:.2f}\n"
                        md += f"- **Рекомендация:** {vuln.remediation}\n\n"

        return md

    def _get_severity_icon(self, severity: str) -> str:
        """Получить иконку для уровня серьезности"""
        icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        return icons.get(severity, '⚪')

    def _get_risk_level_icon(self, risk_level: str) -> str:
        """Получить иконку для уровня риска"""
        icons = {
            'CRITICAL': '🔥',
            'HIGH': '⚠️',
            'MEDIUM': '🔶',
            'LOW': 'ℹ️'
        }
        return icons.get(risk_level, '⚪')