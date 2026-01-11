#!/usr/bin/env python
"""PySAST - Статический анализатор безопасности Python, Java и PHP кода"""

import argparse
import sys
import os
import time
from datetime import datetime

# Добавляем корневую директорию в путь Python
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Импорт из пакета pysast
try:
    from pysast.scanner import PySASTScanner
    from pysast.gitlab_integration import GitLabIntegration
    from pysast.patterns import PatternRegistry
    from pysast.report_generator import ReportGenerator, ScanSummary

    print("✅ Модули успешно импортированы")
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    print(f"\nТекущий sys.path: {sys.path[:3]}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='PySAST - Статический анализатор безопасности Python, Java и PHP кода',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s scan ./project/           # Сканирование директории
  %(prog)s scan ./app.py            # Сканирование одного файла
  %(prog)s scan --format html       # Генерация HTML отчета
  %(prog)s scan --output report.html # Сохранение отчета в файл
  %(prog)s gitlab-scan              # Запуск в режиме GitLab CI
  %(prog)s list-patterns            # Показать все шаблоны уязвимостей
  %(prog)s risk-assessment ./src/   # Анализ рисков безопасности
  %(prog)s supported-languages      # Показать поддерживаемые языки
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')

    # Команда scan
    scan_parser = subparsers.add_parser('scan', help='Сканирование кода на уязвимости')
    scan_parser.add_argument('path', help='Путь к файлу или директории для сканирования')
    scan_parser.add_argument('--format', '-f',
                             choices=['json', 'html', 'markdown', 'console', 'all'],
                             default='console',
                             help='Формат отчета (по умолчанию: console)')
    scan_parser.add_argument('--output', '-o',
                             help='Путь для сохранения отчета (по умолчанию: auto-generated)')
    scan_parser.add_argument('--quiet', '-q',
                             action='store_true',
                             help='Тихий режим (минимальный вывод)')
    scan_parser.add_argument('--no-exit',
                             action='store_true',
                             help='Не завершать работу при обнаружении уязвимостей')
    scan_parser.add_argument('--exclude', '-e',
                             nargs='+',
                             help='Список файлов/паттернов для исключения')
    scan_parser.add_argument('--severity',
                             choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ALL'],
                             default='ALL',
                             help='Фильтр по минимальной серьезности уязвимостей')

    # Команда gitlab-scan
    gitlab_parser = subparsers.add_parser('gitlab-scan',
                                          help='Запуск сканирования в режиме GitLab CI/CD')
    gitlab_parser.add_argument('--path',
                               default=None,
                               help='Путь к проекту (по умолчанию: текущая директория)')
    gitlab_parser.add_argument('--no-fail',
                               action='store_true',
                               help='Не завершать с ошибкой при обнаружении уязвимостей')
    gitlab_parser.add_argument('--quiet', '-q',
                               action='store_true',
                               help='Тихий режим (минимальный вывод)')

    # Команда list-patterns
    patterns_parser = subparsers.add_parser('list-patterns',
                                            help='Показать все доступные шаблоны уязвимостей')

    # Команда risk-assessment
    risk_parser = subparsers.add_parser('risk-assessment',
                                        help='Анализ рисков безопасности')
    risk_parser.add_argument('path',
                             help='Путь к файлу или директории для анализа')
    risk_parser.add_argument('--format', '-f',
                             choices=['console', 'json', 'html'],
                             default='console',
                             help='Формат отчета по рискам')
    risk_parser.add_argument('--top', '-t',
                             type=int,
                             default=10,
                             help='Количество отображаемых топ-рисков')

    # Команда supported-languages
    lang_parser = subparsers.add_parser('supported-languages',
                                        help='Показать поддерживаемые языки программирования')

    args = parser.parse_args()

    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'gitlab-scan':
        run_gitlab_scan(args)
    elif args.command == 'list-patterns':
        list_patterns()
    elif args.command == 'risk-assessment':
        run_risk_assessment(args)
    elif args.command == 'supported-languages':
        list_supported_languages()
    elif not args.command:
        parser.print_help()
        sys.exit(0)
    else:
        print(f"Неизвестная команда: {args.command}")
        parser.print_help()
        sys.exit(1)


def run_scan(args):
    """Запуск обычного сканирования"""
    scanner = PySASTScanner()

    if not os.path.exists(args.path):
        print(f"❌ Путь не существует: {args.path}")
        sys.exit(1)

    if not args.quiet:
        print("=" * 60)
        print("PySAST - Статический анализатор безопасности")
        print("=" * 60)
        print(f"Цель: {args.path}")
        print(f"Тип: {'Файл' if os.path.isfile(args.path) else 'Директория'}")
        print(f"Формат отчета: {args.format}")
        print(f"Поддерживаемые языки: {', '.join(scanner.get_supported_languages())}")
        if args.severity != 'ALL':
            print(f"Фильтр по серьезности: {args.severity} и выше")
        print("=" * 60)
        print()

    try:
        start_time = time.time()
        results = scanner.scan(args.path)
        scan_time = time.time() - start_time

        if not results:
            if not args.quiet:
                print("✅ Сканирование завершено. Уязвимостей не обнаружено.")
            return

        # Фильтрация по серьезности
        if args.severity != 'ALL':
            filtered_results = {}
            severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            min_severity_idx = severity_levels.index(args.severity)

            for file_path, vulns in results.items():
                filtered_vulns = [
                    v for v in vulns
                    if severity_levels.index(v.severity) <= min_severity_idx
                ]
                if filtered_vulns:
                    filtered_results[file_path] = filtered_vulns
            results = filtered_results

        # Получаем статистику
        stats = scanner.get_vulnerability_stats()
        stats['scan_duration'] = scan_time

        # Генерация отчета
        report_gen = ReportGenerator()

        if args.format == 'console':
            report = report_gen.generate_console_report(results, stats)
            print(report)

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)

        elif args.format == 'json':
            report = report_gen.generate_json_report(results, stats)

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)
            else:
                print(report)

        elif args.format == 'html':
            report = report_gen.generate_html_report(results, stats)

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)
            else:
                print("HTML отчет сгенерирован (используйте --output для сохранения)")

        elif args.format == 'markdown':
            report = report_gen.generate_markdown_report(results, stats)

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)
            else:
                print(report)

        # Проверка на критические уязвимости
        critical_count = stats.get('severity_counts', {}).get('CRITICAL', 0)
        high_count = stats.get('severity_counts', {}).get('HIGH', 0)

        exit_code = 0
        if critical_count > 0:
            if not args.no_exit:
                exit_code = 2
            if not args.quiet:
                print(f"\n⚠️  ВНИМАНИЕ: Найдено {critical_count} критических уязвимостей!")
        elif high_count > 0 and not args.no_exit:
            exit_code = 1
            if not args.quiet:
                print(f"\n⚠️  ВНИМАНИЕ: Найдено {high_count} высокоуровневых уязвимостей!")

        # Завершение
        if exit_code > 0 and not args.quiet and not args.no_exit:
            print(f"\nДля отключения автоматического завершения используйте опцию --no-exit")

        sys.exit(exit_code if not args.no_exit else 0)

    except KeyboardInterrupt:
        print("\n\n⏹ Сканирование прервано пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Ошибка при сканировании: {e}")
        import traceback
        if not args.quiet:
            traceback.print_exc()
        sys.exit(1)


def run_gitlab_scan(args):
    """Запуск сканирования в режиме GitLab CI"""
    ci_env = os.getenv('CI', 'false')

    if not getattr(args, 'quiet', False) and ci_env != 'true':
        print("⚠️  Предупреждение: Не обнаружена среда GitLab CI")
        print("  Запуск в режиме эмуляции GitLab CI/CD")

    if args.path:
        project_path = args.path
    else:
        project_path = os.getenv('CI_PROJECT_DIR', '.')

    if not os.path.exists(project_path):
        print(f"❌ Путь не существует: {project_path}")
        sys.exit(1)

    scanner = PySASTScanner()
    gitlab_integration = GitLabIntegration(scanner)

    if not getattr(args, 'quiet', False):
        print("=" * 60)
        print("PySAST - Интеграция с GitLab CI/CD")
        print("=" * 60)
        print(f"Проект: {project_path}")
        print(f"Ветка: {os.getenv('CI_COMMIT_REF_NAME', 'unknown')}")
        print(f"Коммит: {os.getenv('CI_COMMIT_SHA', 'unknown')[:8]}")
        print("=" * 60)

    try:
        results = gitlab_integration.run_gitlab_scan(project_path)

        stats = scanner.get_vulnerability_stats()
        critical_count = stats.get('severity_counts', {}).get('CRITICAL', 0)

        if critical_count > 0 and not getattr(args, 'no_fail', False):
            print(f"\nНайдено критических уязвимостей: {critical_count}")
            print("Статус пайплайна: FAILED")
            sys.exit(1)
        else:
            if not getattr(args, 'quiet', False):
                print("\n✅ Критических уязвимостей не обнаружено")
                print("Статус пайплайна: PASSED")

        # Коммент для merge request
        if os.getenv('CI_MERGE_REQUEST_IID') and not getattr(args, 'quiet', False):
            comment = gitlab_integration.create_merge_request_comment(results)
            print("\n📝 Комментарий для Merge Request:")
            print("-" * 40)
            print(comment[:500] + "..." if len(comment) > 500 else comment)
            print("-" * 40)

    except KeyboardInterrupt:
        print("\n\n⏹ Сканирование прервано пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Ошибка при выполнении GitLab сканирования: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def list_patterns():
    """Показать все доступные шаблоны уязвимостей"""
    try:
        registry = PatternRegistry()
        patterns = registry.get_all_patterns()

        print("=" * 60)
        print("ДОСТУПНЫЕ ШАБЛОНЫ УЯЗВИМОСТЕЙ")
        print("=" * 60)

        categories = {}
        for pattern in patterns:
            category = pattern.category
            if category not in categories:
                categories[category] = []
            categories[category].append(pattern)

        for category, pattern_list in categories.items():
            print(f"\n📁 Категория: {category}")
            print("-" * 40)

            for pattern in pattern_list:
                print(f"\n  🔍 {pattern.name}")
                print(f"     ID: {pattern.id}")
                print(f"     Серьезность: {pattern.severity}")
                print(f"     CWE: {pattern.cwe_id}")
                print(f"     Описание: {pattern.description[:80]}...")
                print(f"     Рекомендация: {pattern.remediation[:80]}...")

        print("\n" + "=" * 60)
        print(f"Всего шаблонов: {len(patterns)}")
        print("=" * 60)

    except Exception as e:
        print(f"❌ Ошибка при загрузке шаблонов: {e}")
        sys.exit(1)


def run_risk_assessment(args):
    """Запуск анализа рисков"""
    scanner = PySASTScanner()

    if not os.path.exists(args.path):
        print(f"❌ Путь не существует: {args.path}")
        sys.exit(1)

    print("=" * 60)
    print("PySAST - Анализ рисков безопасности")
    print("=" * 60)
    print(f"Цель: {args.path}")
    print(f"Тип: {'Файл' if os.path.isfile(args.path) else 'Директория'}")
    print("=" * 60)
    print()

    try:
        start_time = time.time()
        results = scanner.scan(args.path)
        scan_time = time.time() - start_time

        if not results:
            print("✅ Уязвимостей не обнаружено. Риски отсутствуют.")
            return

        # Генерация отчета по рискам
        risk_report = scanner.generate_risk_report()
        risk_report['scan_duration'] = scan_time

        report_gen = ReportGenerator()

        if args.format == 'console':
            report = report_gen.generate_risk_report(risk_report)
            print(report)

        elif args.format == 'json':
            report = json.dumps(risk_report, indent=2, ensure_ascii=False)
            print(report)

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)

        elif args.format == 'html':
            # Простой HTML отчет для рисков
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Анализ рисков безопасности</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .risk {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                    .critical {{ background: #ffe6e6; }}
                    .high {{ background: #fff0e6; }}
                    .medium {{ background: #fffae6; }}
                    .low {{ background: #e6ffe6; }}
                </style>
            </head>
            <body>
                <h1>Анализ рисков безопасности</h1>
                <p><strong>Всего рисков:</strong> {risk_report.get('total_risks', 0)}</p>
                <p><strong>Общая оценка риска:</strong> {risk_report.get('total_risk_score', 0):.2f}</p>
            """

            for risk in risk_report.get('top_risks', [])[:args.top]:
                risk_class = risk['risk_level'].lower()
                html += f"""
                <div class="risk {risk_class}">
                    <h3>{risk['vulnerability']}</h3>
                    <p><strong>Файл:</strong> {risk['file']}:{risk['line']}</p>
                    <p><strong>Актив:</strong> {risk['asset']}</p>
                    <p><strong>Оценка риска:</strong> {risk['risk_score']} ({risk['risk_level']})</p>
                </div>
                """

            html += "</body></html>"

            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(html)
                print(f"✅ HTML отчет сохранен: {args.output}")
            else:
                print(html)

        print(f"\n⏱️  Время анализа: {scan_time:.2f} секунд")

    except KeyboardInterrupt:
        print("\n\n⏹ Анализ рисков прерван пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Ошибка при анализе рисков: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def list_supported_languages():
    """Показать поддерживаемые языки программирования"""
    scanner = PySASTScanner()

    print("=" * 60)
    print("ПОДДЕРЖИВАЕМЫЕ ЯЗЫКИ ПРОГРАММИРОВАНИЯ")
    print("=" * 60)

    languages = scanner.get_supported_languages()
    extensions = scanner.get_supported_extensions()

    for lang, ext in zip(languages, extensions):
        print(f"\n🌐 {lang.upper()}")
        print(f"   Расширение файлов: {ext}")

        # Создаем анализатор для получения информации о шаблонах
        if ext == '.py':
            from pysast.languages.python_analyzer import PythonAnalyzer
            analyzer = PythonAnalyzer()
        elif ext == '.java':
            from pysast.languages.java_analyzer import JavaAnalyzer
            analyzer = JavaAnalyzer()
        elif ext == '.php':
            from pysast.languages.php_analyzer import PHPAnalyzer
            analyzer = PHPAnalyzer()
        else:
            continue

        patterns = analyzer.get_patterns()
        print(f"   Шаблонов уязвимостей: {len(patterns)}")

        # Показываем категории уязвимостей
        categories = set()
        for pattern in patterns.values():
            categories.add(pattern.get('category', 'UNKNOWN'))

        if categories:
            print(f"   Категории: {', '.join(sorted(categories))}")

    print("\n" + "=" * 60)
    print(f"Всего языков: {len(languages)}")
    print("=" * 60)


if __name__ == '__main__':
    main()