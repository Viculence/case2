import os
import datetime


def main():
    result_files = sorted([
        f for f in os.listdir('.')
        if f.endswith('.txt') and f.startswith('result')
    ])

    if not result_files:
        print("ОШИБКА: не найдено ни одного result*.txt файла в папке проекта.")
        return

    print(f"Найдены файлы для сравнения: {', '.join(result_files)}\n")

    IGNORE_STARTS = [
        'ОТЧЕТ', 'ФИНАНСОВЫЕ', 'СЕКРЕТНЫЕ', 'СИСТЕМНАЯ', "valid", "invalid",
        'РАСШИФРОВАННЫЕ', 'УГРОЗЫ', 'НОРМАЛИЗОВАННЫЕ', 'Найдено:',
        'валидные', 'невалидные', 'нормализованные', 'ips', 'files',
        'emails', 'sql_injections', 'xss_attempts', 'base64', 'hex',
        'suspicious_user_agents', 'failed_logins', 'Общее количество',
        '---', '===', 'Files analyzed', 'Generated', 'rot13',
    ]


    def is_artifact(line):
        line = line.strip()
        if not line:
            return False
        if all(c in '-=_ ' for c in line):
            return False
        for prefix in IGNORE_STARTS:
            if line.startswith(prefix):
                return False
        return True


    file_contents = {}
    for filename in result_files:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                lines = set(line.strip() for line in f.readlines() if line.strip())
                file_contents[filename] = lines
            print(f"  [{len(file_contents[filename])}] строк прочитано из {filename}")
        except FileNotFoundError:
            print(f"ОШИБКА: Файл {filename} не найден. Пропускаю.")
        except Exception as e:
            print(f"КРИТИЧЕСКАЯ ОШИБКА при чтении {filename}: {e}")

    if len(file_contents) < 2:
        print("ОШИБКА: нужно минимум 2 файла для сравнения.")
        return

    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТЫ СРАВНЕНИЯ ФАЙЛОВ:")
    print("=" * 60)

    files = list(file_contents.keys())

    # ОБЩИЕ СТРОКИ (есть во ВСЕХ файлах)
    common_all = set.intersection(*file_contents.values())
    print(f"\n[{len(common_all)}] ОБЩИЕ СТРОКИ (есть во всех файлах):")
    for line in sorted(common_all):
        print(f"  {line}")

    # ПОПАРНОЕ СРАВНЕНИЕ
    for i in range(len(files)):
        for j in range(i + 1, len(files)):
            f1, f2 = files[i], files[j]
            common = file_contents[f1] & file_contents[f2]
            only_f1 = file_contents[f1] - file_contents[f2]
            only_f2 = file_contents[f2] - file_contents[f1]

            print(f"\n--- Сравнение: {f1} vs {f2} ---")
            print(f"  [{len(common)}] общих строк")
            print(f"  [{len(only_f1)}] только в {f1}:")
            for line in sorted(only_f1):
                print(f"    {line}")
            print(f"  [{len(only_f2)}] только в {f2}:")
            for line in sorted(only_f2):
                print(f"    {line}")

    # УНИКАЛЬНЫЕ СТРОКИ (есть только в одном файле)
    print(f"\n{'=' * 60}")
    print("УНИКАЛЬНЫЕ СТРОКИ (есть только в одном файле):")
    print("=" * 60)
    for filename, content in file_contents.items():
        others = set.union(*[v for k, v in file_contents.items() if k != filename])
        unique = content - others
        print(f"\n  [{len(unique)}] только в {filename}:")
        for line in sorted(unique):
            print(f"    {line}")

    # ВСЕ СТРОКИ ИЗ ВСЕХ ФАЙЛОВ
    all_lines = set.union(*file_contents.values())
    print(f"\n{'=' * 60}")
    print(f"Всего уникальных строк по всем файлам: {len(all_lines)}")

    # СОХРАНЕНИЕ РЕЗУЛЬТАТА СРАВНЕНИЯ
    output_file = "comparison_result.txt"
    try:
        with open(output_file, 'w', encoding='utf-8') as f_out:
            f_out.write("--- ОТЧЁТ СРАВНЕНИЯ ФАЙЛОВ ---\n")
            f_out.write(f"Файлы: {', '.join(result_files)}\n")
            f_out.write(f"Дата: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f_out.write(f"ОБЩИЕ СТРОКИ (есть во всех файлах): {len(common_all)}\n")
            for line in sorted(common_all):
                f_out.write(f"  {line}\n")

            f_out.write(f"\nУНИКАЛЬНЫЕ СТРОКИ ПО ФАЙЛАМ:\n")
            for filename, content in file_contents.items():
                others = set.union(*[v for k, v in file_contents.items() if k != filename])
                unique = content - others
                f_out.write(f"\n  Только в {filename} ({len(unique)}):\n")
                for line in sorted(unique):
                    f_out.write(f"    {line}\n")

            f_out.write(f"\nВСЕГО УНИКАЛЬНЫХ СТРОК: {len(all_lines)}\n")

        print(f"\nФайл {output_file} успешно записан.")
    except Exception as e:
        print(f"КРИТИЧЕСКАЯ ОШИБКА при записи в {output_file}: {e}")


if __name__ == "__main__":
    main()