import json
import os
import sys
from typing import Dict, Any
from datetime import datetime


class GitLabIntegration:
    """Класс для интеграции с GitLab CI/CD"""

    def __init__(self, scanner):
        self.scanner = scanner
        self.gitlab_variables = self._load_gitlab_variables()

    def _load_gitlab_variables(self) -> Dict[str, str]:
        """Загружает переменные окружения GitLab CI"""
        variables = {}

        # Основные переменные GitLab CI
        gitlab_vars = [
            'CI_PROJECT_DIR',
            'CI_PROJECT_ID',
            'CI_COMMIT_SHA',
            'CI_COMMIT_REF_NAME',
            'CI_JOB_ID',
            'CI_PIPELINE_ID',
            'CI_MERGE_REQUEST_IID'
        ]

        for var in gitlab_vars:
            variables[var] = os.getenv(var, '')

        return variables

    def run_gitlab_scan(self, project_path: str = None) -> Dict[str, Any]:
        """Запускает сканирование в среде GitLab CI"""
        if project_path is None:
            project_path = self.gitlab_variables.get('CI_PROJECT_DIR', '.')

        print(f"Запуск сканирования в GitLab CI")
        print(f"Проект: {project_path}")

        # Выполняем сканирование
        results = self.scanner.scan(project_path)

        # Генерируем отчеты
        self._generate_gitlab_reports(results)

        # Проверяем наличие критических уязвимостей
        stats = self.scanner.get_vulnerability_stats()
        critical_count = stats.get('severity_counts', {}).get('CRITICAL', 0)

        # Если есть критические уязвимости, завершаем с ошибкой
        if critical_count > 0:
            print(f"Найдено критических уязвимостей: {critical_count}")
            print("Статус пайплайна: FAILED")
            sys.exit(1)

        return results

    def _generate_gitlab_reports(self, results: Dict[str, Any]):
        """Генерирует отчеты для GitLab CI"""
        artifacts_dir = "pysast-artifacts"
        os.makedirs(artifacts_dir, exist_ok=True)

        # 1. GitLab Security Dashboard отчет
        security_report = []
        for file_path, vulns in results.items():
            for vuln in vulns:
                severity_map = {
                    'CRITICAL': 'critical',
                    'HIGH': 'high',
                    'MEDIUM': 'medium',
                    'LOW': 'low'
                }

                security_report.append({
                    "category": vuln.category.lower().replace('_', '-'),
                    "description": f"{vuln.description}. Рекомендация: {vuln.remediation}",
                    "severity": severity_map.get(vuln.severity, 'unknown'),
                    "location": {
                        "file": file_path,
                        "line": vuln.line_number
                    }
                })

        # Сохраняем отчет
        report_path = os.path.join(artifacts_dir, 'gl-security-report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(security_report, f, indent=2, ensure_ascii=False)

        print(f"GitLab Security отчет создан: {report_path}")

    def create_merge_request_comment(self, results: Dict[str, Any]) -> str:
        """Создает комментарий для Merge Request"""
        stats = self.scanner.get_vulnerability_stats()

        comment = f"""## Результаты сканирования безопасности PySAST

**Статус:** {"**FAILED**" if stats.get('severity_counts', {}).get('CRITICAL', 0) > 0 else "✅ **PASSED**"}

### Статистика:
- Проанализировано файлов: {stats.get('total_files', 0)}
- Найдено уязвимостей: {stats.get('total_vulnerabilities', 0)}
- Дата сканирования: {stats.get('scan_date', 'N/A')}

### Распределение по серьезности:
"""

        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }

        for severity, count in stats.get('severity_counts', {}).items():
            if count > 0:
                emoji = severity_emoji.get(severity, '')
                comment += f"- {emoji} **{severity}:** {count}\n"

        # Добавляем детали по критическим уязвимостям
        critical_vulns = []
        for file_path, vulns in results.items():
            for vuln in vulns:
                if vuln.severity == 'CRITICAL':
                    critical_vulns.append(vuln)

        if critical_vulns:
            comment += "\n### ❗ Критические уязвимости:\n"
            for i, vuln in enumerate(critical_vulns[:3], 1):
                comment += f"{i}. **{vuln.description}**\n"
                comment += f"   - Файл: `{vuln.file_path}:{vuln.line_number}`\n"
                comment += f"   - Рекомендация: {vuln.remediation}\n"

        comment += "\n---\n*Этот комментарий создан автоматически PySAST*"

        return comment