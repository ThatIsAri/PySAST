#!/usr/bin/env python3
"""
Командный интерфейс для PySAST сканера
"""

import argparse
import sys
import os
import time
from typing import Optional
from datetime import datetime

# РАСШИРЕННЫЙ ПОИСК МОДУЛЕЙ
# Добавляем несколько возможных путей для импорта

# Путь 1: текущая директория (где лежит run_scanner.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Путь 2: папка pysast в текущей директории
pysast_dir = os.path.join(current_dir, 'pysast')
if os.path.exists(pysast_dir):
    sys.path.insert(0, pysast_dir)

# Путь 3: папка src (если структура другая)
src_dir = os.path.join(current_dir, 'src')
if os.path.exists(src_dir):
    sys.path.insert(0, src_dir)
    # Ищем pysast внутри src
    pysast_in_src = os.path.join(src_dir, 'pysast')
    if os.path.exists(pysast_in_src):
        sys.path.insert(0, pysast_in_src)

print(f"🔍 Поиск модулей в: {sys.path}")

# Теперь пробуем импортировать
try:
    from pysast.scanner import PySASTScanner
    from pysast.gitlab_integration import GitLabIntegration

    print("✅ Модули успешно импортированы из pysast")
except ImportError as e:
    print(f"⚠️  Не удалось импортировать из pysast: {e}")

    # Пробуем прямую загрузку модулей из текущей директории
    try:
        # Если файлы лежат прямо в корне
        import scanner
        import gitlab_integration
        from scanner import PySASTScanner
        from gitlab_integration import GitLabIntegration

        print("✅ Модули импортированы напрямую")
    except ImportError as e2:
        print(f"❌ Ошибка импорта: {e2}")
        print("\n📋 Проверьте структуру проекта:")
        print("1. Файл run_scanner.py должен быть в корне проекта")
        print("2. Папка 'pysast' должна быть в той же директории")
        print("3. В папке 'pysast' должны быть файлы: scanner.py, gitlab_integration.py и др.")
        print("\nТекущая структура:")
        for root, dirs, files in os.walk(current_dir):
            level = root.replace(current_dir, '').count(os.sep)
            indent = ' ' * 2 * level
            print(f'{indent}{os.path.basename(root)}/')
            subindent = ' ' * 2 * (level + 1)
            for file in files[:5]:  # Показываем первые 5 файлов
                if file.endswith('.py'):
                    print(f'{subindent}{file}')
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='PySAST - Статический анализатор безопасности Python кода',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s scan ./project/              # Сканирование директории
  %(prog)s scan ./app.py               # Сканирование одного файла
  %(prog)s scan --format html          # Генерация HTML отчета
  %(prog)s scan --output report.html   # Сохранение отчета в файл
  %(prog)s gitlab-scan                 # Запуск в режиме GitLab CI
  %(prog)s list-patterns               # Показать все шаблоны уязвимостей
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')

    # Команда scan
    scan_parser = subparsers.add_parser('scan', help='Сканирование кода на уязвимости')
    scan_parser.add_argument('path',
                             help='Путь к файлу или директории для сканирования')
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
                               help='Путь к проекту (по умолчанию: CI_PROJECT_DIR или текущая директория)')
    gitlab_parser.add_argument('--no-fail',
                               action='store_true',
                               help='Не завершать с ошибкой при обнаружении уязвимостей')
    gitlab_parser.add_argument('--quiet', '-q',
                               action='store_true',
                               help='Тихий режим (минимальный вывод)')

    # Команда list-patterns
    patterns_parser = subparsers.add_parser('list-patterns',
                                            help='Показать все доступные шаблоны уязвимостей')

    args = parser.parse_args()

    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'gitlab-scan':
        run_gitlab_scan(args)
    elif args.command == 'list-patterns':
        list_patterns()
    elif not args.command:
        # Если команда не указана, показываем справку
        parser.print_help()
        sys.exit(0)
    else:
        print(f"❌ Неизвестная команда: {args.command}")
        parser.print_help()
        sys.exit(1)


def run_scan(args):
    """Запуск обычного сканирования"""
    # Создаем экземпляр сканера
    scanner = PySASTScanner()

    # Проверяем существование пути
    if not os.path.exists(args.path):
        print(f"❌ Путь не существует: {args.path}")
        sys.exit(1)

    # Выводим информацию о сканировании
    if not args.quiet:
        print("=" * 60)
        print("🔍 PySAST - Статический анализатор безопасности Python")
        print("=" * 60)
        print(f"Цель: {args.path}")
        print(f"Тип: {'Файл' if os.path.isfile(args.path) else 'Директория'}")
        print(f"Формат отчета: {args.format}")
        if args.severity != 'ALL':
            print(f"Фильтр по серьезности: {args.severity} и выше")
        print("=" * 60)
        print()

    try:
        # Выполняем сканирование
        start_time = time.time()
        results = scanner.scan(args.path)
        scan_time = time.time() - start_time

        # Если результатов нет, выходим
        if not results:
            if not args.quiet:
                print("✅ Сканирование завершено. Уязвимостей не обнаружено.")
            return

        # Применяем фильтр по серьезности, если задан
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

        # ОБЯЗАТЕЛЬНО: Для формата console выводим детальный отчет
        if args.format == 'console' and not args.quiet:
            try:
                from pysast.report_generator import ReportGenerator, ScanSummary

                # Пересчитываем статистику на основе отфильтрованных результатов
                severity_counts = {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                }
                total_vulnerabilities = 0
                total_files = len(results)

                for file_path, vulns in results.items():
                    for vuln in vulns:
                        if vuln.severity in severity_counts:
                            severity_counts[vuln.severity] += 1
                            total_vulnerabilities += 1

                # Создаем сводку для отчета
                summary = ScanSummary(
                    total_files=total_files,
                    total_vulnerabilities=total_vulnerabilities,
                    scan_duration=scan_time,
                    scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    severity_counts=severity_counts
                )

                # Генерируем и выводим консольный отчет
                report_gen = ReportGenerator()
                report_gen.generate_console_report(results, summary)

            except ImportError as e:
                print(f"⚠️  Модуль report_generator не найден: {e}")
                print("Вывод упрощенного отчета...")

                print("\n" + "=" * 60)
                print("📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
                print("=" * 60)

                total_vulns = sum(len(v) for v in results.values())
                print(f"Найдено уязвимостей: {total_vulns}")
                print(f"Файлов проанализировано: {len(results)}")

                for file_path, vulns in results.items():
                    if vulns:
                        print(f"\n📄 {file_path}:")
                        for i, vuln in enumerate(vulns[:5], 1):
                            print(f"  {i}. [{vuln.severity}] {vuln.description}")
                            print(f"     Строка: {vuln.line_number}, ID: {vuln.pattern_id}")

                print("=" * 60)

        # Для других форматов генерируем отчеты
        elif args.format != 'console' or (args.format == 'console' and args.output):
            if args.format == 'all':
                formats = ['json', 'html', 'markdown']
                for fmt in formats:
                    generate_specific_report(scanner, results, fmt, args.output, args.quiet)
            else:
                generate_specific_report(scanner, results, args.format, args.output, args.quiet)

        # Проверяем наличие критических уязвимостей
        critical_count = stats.get('severity_counts', {}).get('CRITICAL', 0)
        high_count = stats.get('severity_counts', {}).get('HIGH', 0)

        # Определяем код возврата
        exit_code = 0
        if critical_count > 0:
            if not args.no_exit:
                exit_code = 2  # Код для критических уязвимостей
                if not args.quiet:
                    print(f"\n🚨 ВНИМАНИЕ: Найдено {critical_count} критических уязвимостей!")
        elif high_count > 0 and not args.no_exit:
            exit_code = 1  # Код для высокоуровневых уязвимостей
            if not args.quiet:
                print(f"\n⚠️  ВНИМАНИЕ: Найдено {high_count} высокоуровневых уязвимостей!")

        # Завершаем с соответствующим кодом
        if exit_code > 0 and not args.quiet:
            print(f"\nДля отключения автоматического завершения используйте опцию --no-exit")

        sys.exit(exit_code if not args.no_exit else 0)

    except KeyboardInterrupt:
        print("\n\n⏹️  Сканирование прервано пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Ошибка при сканировании: {e}")
        import traceback
        if not args.quiet:
            traceback.print_exc()
        sys.exit(1)


def generate_specific_report(scanner, results, format: str, output_file: Optional[str], quiet: bool):
    """Генерирует отчет в указанном формате"""
    if not quiet:
        print(f"\n📄 Генерация {format.upper()} отчета...")

    try:
        # Для консольного формата используем существующий метод сканера
        if format == 'console':
            if not quiet:
                scanner.generate_report(output_format=format)
            return

        # Определяем имя файла для отчета
        if output_file:
            # Если указан конкретный файл для одного формата
            if format != 'all':
                report_file = output_file
            else:
                # Для формата 'all' добавляем суффикс
                base, ext = os.path.splitext(output_file)
                report_file = f"{base}_{format}{ext}"
        else:
            # Автоматическое имя файла
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"pysast_report_{timestamp}.{format if format != 'markdown' else 'md'}"

        # Генерируем отчет через сканер
        scanner.generate_report(output_format=format, output_file=report_file)

        if not quiet:
            print(f"✅ Отчет сохранен: {os.path.abspath(report_file)}")

    except Exception as e:
        print(f"❌ Ошибка при генерации {format} отчета: {e}")
        if not quiet:
            import traceback
            traceback.print_exc()


def run_gitlab_scan(args):
    """Запуск сканирования в режиме GitLab CI"""
    # Проверяем, запущены ли мы в среде GitLab CI
    ci_env = os.getenv('CI', 'false')

    # Исправление: используем getattr для безопасного получения атрибута
    if not getattr(args, 'quiet', False) and ci_env != 'true':
        print("⚠️  Предупреждение: Не обнаружена среда GitLab CI")
        print("   Запуск в режиме эмуляции GitLab CI/CD")

    # Определяем путь к проекту
    if args.path:
        project_path = args.path
    else:
        project_path = os.getenv('CI_PROJECT_DIR', '.')

    # Проверяем существование пути
    if not os.path.exists(project_path):
        print(f"❌ Путь не существует: {project_path}")
        sys.exit(1)

    # Создаем экземпляры классов
    scanner = PySASTScanner()
    gitlab_integration = GitLabIntegration(scanner)

    # Выводим информацию только если не включен тихий режим
    if not getattr(args, 'quiet', False):
        print("=" * 60)
        print("🚀 PySAST - Интеграция с GitLab CI/CD")
        print("=" * 60)
        print(f"Проект: {project_path}")
        print(f"Ветка: {os.getenv('CI_COMMIT_REF_NAME', 'unknown')}")
        print(f"Коммит: {os.getenv('CI_COMMIT_SHA', 'unknown')[:8]}")
        print("=" * 60)

    try:
        # Выполняем сканирование
        results = gitlab_integration.run_gitlab_scan(project_path)

        # Проверяем наличие критических уязвимостей
        stats = scanner.get_vulnerability_stats()
        critical_count = stats.get('severity_counts', {}).get('CRITICAL', 0)

        if critical_count > 0 and not getattr(args, 'no_fail', False):
            print(f"\n❌ Найдено критических уязвимостей: {critical_count}")
            print("Статус пайплайна: FAILED")
            sys.exit(1)
        else:
            if not getattr(args, 'quiet', False):
                print("\n✅ Критических уязвимостей не обнаружено")
                print("Статус пайплайна: PASSED")

            # Создаем комментарий для Merge Request
            if os.getenv('CI_MERGE_REQUEST_IID') and not getattr(args, 'quiet', False):
                comment = gitlab_integration.create_merge_request_comment(results)
                print("\n💬 Комментарий для Merge Request:")
                print("-" * 40)
                print(comment[:500] + "..." if len(comment) > 500 else comment)
                print("-" * 40)

        # Показываем путь к артефактам
        artifacts_dir = "pysast-artifacts"
        if os.path.exists(artifacts_dir) and not getattr(args, 'quiet', False):
            print(f"\n📁 Артефакты сохранены в директории: {artifacts_dir}")
            for file in os.listdir(artifacts_dir):
                file_path = os.path.join(artifacts_dir, file)
                size = os.path.getsize(file_path)
                print(f"  - {file} ({size} байт)")

    except KeyboardInterrupt:
        print("\n\n⏹️  Сканирование прервано пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Ошибка при выполнении GitLab сканирования: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def list_patterns():
    """Показать все доступные шаблоны уязвимостей"""
    try:
        from pysast.patterns import PatternRegistry

        registry = PatternRegistry()
        patterns = registry.get_all_patterns()

        print("=" * 60)
        print("📋 ДОСТУПНЫЕ ШАБЛОНЫ УЯЗВИМОСТЕЙ")
        print("=" * 60)

        # Группируем по категориям
        categories = {}
        for pattern in patterns:
            category = pattern.category
            if category not in categories:
                categories[category] = []
            categories[category].append(pattern)

        # Выводим по категориям
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

    except ImportError as e:
        print(f"❌ Ошибка при загрузке шаблонов: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()