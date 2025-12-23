import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pysast'))

print("Тестируем сканер напрямую")

try:
    from pysast.scanner import PySASTScanner

    scanner = PySASTScanner()
    print("Сканер создан")

    file_path = "examples/vulnerable_app.py"
    if not os.path.exists(file_path):
        print(f"Файл не существует: {file_path}")
        print(f"   Текущая директория: {os.getcwd()}")
        print(f"   Содержимое examples/:")
        if os.path.exists("examples"):
            for f in os.listdir("examples"):
                print(f"   - {f}")
        else:
            print("   Папка examples не существует")
    else:
        print(f"Файл найден: {file_path}")

        try:
            results = scanner.scan(file_path)
            print(f"Сканирование завершено")
            print(f"   Результаты: {results}")

            # Показываем статистику
            stats = scanner.get_vulnerability_stats()
            print(f"   Статистика: {stats}")

            # Генерируем отчет
            scanner.generate_report(output_format='console')

        except Exception as e:
            print(f"Ошибка при сканировании: {e}")
            import traceback

            traceback.print_exc()

except Exception as e:
    print(f"Ошибка: {e}")
    import traceback

    traceback.print_exc()