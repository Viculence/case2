# Operation Data Shield
# Developers: Yasminskaya V., Burykhina E., Tankova K.

import binascii
import re
import base64
import codecs
import datetime


text = '''confidential_data.xlsx, super_secure_4187!, report.pdf, 
10.0.0.1 - “GET /products?id=1’ OR ‘1’=’1” 10.0.0.50 - “POST /cart/add”, 
bob.martin@example.com, pk_test_x4y7zBz5gHq2dTt3x8J9iK6lL1mN7A8, 
01.01.2011, Base64: U29ycnlfb3VyX2JpbmFyeV9hY2Nlc3NfdXNl, 17-Jul-2009, 
jane_doe@personalmail.com, 4000 1234 5678 9876, 172.16.254.1, 203.0.113.5, 
203.0.113.5 - “GET /error/404” 192.168.1.100 - “GET /user?name=admin”, 
1483 5672 8734 4391, contact@mywebsite.org, 5901008664, 8-958-631-47-27, 
+44 20 7946 0857, ROT13: Gbtrgure Vzntvfg, admin@company.xyz, 7707083893, 
Hex: 5468697320697320612074657374206d657373616765, 129.267.1.4, 172.16.254.1, 
letmein2694$, 10.0.0.25 - “GET /logout” 182.168.1.50 - “GET /register”, 
172.16.0.1 - “GET /search?q=alert(‘xss’)” 214.0.149.10 - “GET /admin/login”, 
9876 5432 1098 7654, server_logs.txt, 28/04/2023, +1 800 555 35 20, 
invoice_2017.docx, ROT13: Zlfgrel bs Pyhzf, 9876 5432 1098 7654
'''

# Role 1. Financial investigator
# Task: to find and verify bank card numbers
''' Finds the card numbers and verifies them using
    the Luna algorithm.
    :param text: Parts of the text containing information about
    credit cards numbers.
    :return: {'valid':[], 'invalid':[]}
    '''
def find_and_validate_credit_cards(text):
    # проверка, что получен текст из строк
    if not isinstance(text, str):
        print('Ошибка. Функция получила не текст')
        return {'valid': [], 'invalid': []}

    card_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
    potential_cards = re.findall(card_pattern, text)
    valid_cards = []
    invalid_cards = []
    for card in potential_cards:
        clear_number = re.sub(r'\D', '', card)
        if len(clear_number) != 16:
            invalid_cards.append(card)
            continue
        digits = [int(d) for d in clear_number]
        check_digit = digits.pop()
        digits.reverse()
        processed_digits = []
        for index, digit in enumerate(digits):
            if index % 2 == 0:
                doubled = digit * 2
                if doubled > 9: doubled -= 9
                processed_digits.append(doubled)
            else:
                processed_digits.append(digit)
        if (sum(processed_digits) + check_digit) % 10 == 0:
            valid_cards.append(card)
        else:
            invalid_cards.append(card)
    return {'valid': valid_cards, 'invalid': invalid_cards}


# Role 2. The Key Hunter
# Task: find secret keys and passwords
''' Searches for API-keys, passwords and access tokens.
    :param text: Parts of the text containing information about
    keys, passwords and other secret data.
    :return: List of found secrets
    '''
def find_secrets(text):

    # проверка, что получен текст из строк
    if not isinstance(text, str):
        print('Ошибка. Функция получила не текст')
        return []
    found_secrets = []
    api_key_pattern = r'\b(?:sk_live_|pk_test_)[a-zA-Z0-9]+\b'

    # находим API-ключи
    found_secrets.extend(re.findall(api_key_pattern, text))

    # находим пароли
    words = text.split()
    for word in words:
        clean_word = word.strip('",.')
        if (len(clean_word) > 12 and '@' not in clean_word and
                not clean_word.startswith(('sk_live_', 'pk_test_'))):
            has_digit = any(char.isdigit() for char in clean_word)
            has_special = any(not char.isalnum() for char in clean_word)
            has_english_letter = any('a'<= char.lower() <= 'z' for char in clean_word)
            if has_digit and has_special and has_english_letter and not clean_word.endswith(('.docx', '.pdf', '.txt', '.xlsx')):
                found_secrets.append(clean_word)
    return list(set(found_secrets))


# Role 3. System information traker
# Task: find IP-addresses, files and email
def find_system_info(text):
    ''' Searches for system information.
    :param text: Parts of the text containing information about
    IP addresses, email addresses and file paths.
    :return: {'ips': [], 'files': [], 'emails': []}
    '''
    try:
        ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_regex, text)

        file_regex = r"\b[\w\.-] + (?:\.txt|\.pdf|\.jpg|\.png|\.docx|\.xlsx)\b"
        files = re.findall(file_regex, text)

        email_regex = r"[a-zA-Z0-9._%+-] + @[a-zA-Z0-9.-] + \.[a-zA-Z]{2,}"
        emails = re.findall(email_regex, text)

    except ValueError as e:
        print(f"ValueError occurred: {e}")
        ips, files, emails = [], [], []
    except FileNotFoundError as e:
        print(f"FileNotFoundError occurred: {e}")
        ips, files, emails = [], [], []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        ips, files, emails = [], [], []

    return{'ips': ips, 'files': files, 'emails': emails}


# Role 4. Cryptanalyst
# Task: find and decrypt hidden messages
def decode_messages(text):
    ''' Finds and decrypts messages.
    :param text: Parts of the text containing encoded messages
    in Base64, Hex or ROT13 format.
    :return: {'base64': [], 'hex': [], 'rot13': []}
    '''
    base64_list = []
    hex_list = []
    rot13_list = []
    # base64
    for word in text.split():
        try:
            decoded_bytes = base64.b64decode(word, validate=True)
            decoded = decoded_bytes.decode('utf-8')
            if decoded.isprintable() and decoded.strip():
                base64_list.append(decoded)
        except (ValueError, UnicodeDecodeError):
            continue
    # hex
    for word in text.split():
        try:
            if word.startswith("0x"):
                hex_string = word[2:]
            elif word.startswith("\\x"):
                hex_string = word.replace("\\x", "")
            elif all(c in "0123456789abcdefABCDEF" for c in word) \
                and len(word) % 2 == 0 \
                and len(word) >= 8:
                    hex_string = word
            else:
                continue

            decoded = bytes.fromhex(hex_string).decode('utf-8')
            if decoded.strip() and decoded.isprintable():
                hex_list.append(decoded)
        except (ValueError, UnicodeDecodeError):
            continue
    # rot13
    for line in text.splitlines():
        if "ROT13:" in line:
            rot_text = text.split("ROT13:")[1].split('\n')[0].strip()
            if rot_text:
                decoded = codecs.decode(rot_text, 'rot_13')
                rot13_list.append(decoded)
    return {'base64': base64_list,'hex': hex_list, 'rot13': rot13_list}


# Role 5. Log analyst
# Task: validate logs for attacks
def analyze_logs(text):
    ''' Analyzes the logs of the web server.
    :param text: Parts of the text containing the logs of
    web servers may also include requests for attacks.
    :return: {'sql_injections': [], 'xss_attempts': [],
    'suspicious_user_agents': [], 'failed_logins': []}
    '''
    sql_injections = []
    xss_attempts = []
    suspicious_user_agents = []
    failed_logins = []

    lines = text.splitlines()
    for line in lines:
        lower_line = line.lower()
        # sql_injections
        if ("' or 1=1" in lower_line or
                "union select" in lower_line or
                "select *" in lower_line or
                "drop table" in lower_line or
                "--" in lower_line):
            sql_injections.append(line)
        # xss_attempts
        if ("<script>" in lower_line or
                "</script>" in lower_line or
                "javascript:" in lower_line or
                "onerror=" in lower_line or
                "alert(" in lower_line):
            xss_attempts.append(line)
        # suspicious_user_agents
        if ("sqlmap" in lower_line or
                "nikto" in lower_line or
                "nmap" in lower_line or
                "curl" in lower_line or
                "wget" in lower_line or
                "python-requests" in lower_line):
            suspicious_user_agents.append(line)

        # failed_logins
        if ("failed login" in lower_line or
                "authentication failed" in lower_line or
                "401 unauthorized" in lower_line):
            failed_logins.append(line)

    return {'sql_injections': sql_injections,'xss_attempts': xss_attempts,
            'suspicious_user_agents': suspicious_user_agents,
            'failed_logins': failed_logins
            }


# Role 6. Data quality engineer
# Task: normalize and validate data
def normalize_and_validate(text):
    ''' Brings the data to a single format and verifies it.
    :param text: Text containing various data formats,
    including both valid and invalid ones.
    :return: {'phones': {'valid': [], 'invalid': []},
    'dates': {'normalized': [], 'invalid': []},
    'inn': {'valid': [], 'invalid': []},
    'cards': {'valid': [], 'invalid': []}
    }
    '''
    phones = {'valid': [], 'invalid': []}
    dates = {'normalized': [], 'invalid': []}
    inn = {'valid': [], 'invalid': []}
    cards = {'valid': [], 'invalid': []}

    try:
        phone_regex = (r"\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?"
                       r"[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}"
                       )
        phone_numbers = re.findall(phone_regex, text)
        for phone in phone_numbers:
            if validate_phone(phone):
                phones['valid'].append(phone)
            else:
                phones['invalid'].append(phone)

        date_regex = r"\d{2}[/-]\d{2}[/-]\d{4}"
        dates_found = re.findall(date_regex, text)
        for date in dates_found:
            normalized_date = normalize_date(date)
            if normalized_date != date:
                dates['normalized'].append(normalized_date)
            else:
                dates['invalid'].append(date)

        inn_regex = r"\b\d{10, 12}\b"
        inn_numbers = re.findall(inn_regex, text)
        for number in inn_numbers:
            if validate_inn(number):
                inn['valid'].append(number)
            else:
                inn['invalid'].append(number)

        card_regex = r"\b(?:\d{4}[- ]?){3}\d{4}\b"
        cards_found = re.findall(card_regex, text)
        for card in cards_found:
            if validate_card(card):
                cards['valid'].append(card)
            else:
                cards['invalid'].append(card)

    except ValueError as e:
        print(f"ValueError occurred: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return {'phones': phones, 'dates': dates, 'inn': inn, 'cards': cards}


def validate_phone(phone):
    phone_regex = (r"^\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?"
                   r"[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}$"
                   )
    return re.match(phone_regex, phone) is not None


def validate_inn(inn):
    return len(inn) in [10, 12] and inn.isdigit()


def validate_card(card_number):
    card_number = card_number.replace(" ", "").replace("-", "")
    total = 0
    reverse_digits = card_number[::-1]
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def normalize_date(date):
    try:
        date_obj = datetime.datetime.strptime(date, "%d/%m/%Y")
        return date_obj.strftime("%Y-%m-%d")
    except ValueError:
        return date


def generate_comprehensive_report(text):
    return {
        'financial_data': find_and_validate_credit_cards(text),
        'secrets': find_secrets(text),
        'system_info': find_system_info(text),
        'encoded_messages': decode_messages(text),
        'security_threats': analyze_logs(text),
        'normalized_data': normalize_and_validate(text)
    }


def print_and_save_report(report):

    output_filename = 'result5.txt'

    sections = [
        ("ФИНАНСОВЫЕ ДАННЫЕ", report['financial_data']),
        ("СЕКРЕТНЫЕ КЛЮЧИ", report['secrets']),
        ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
        ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
        ("УГРОЗЫ БЕЗОПАСНОСТИ", report['security_threats']),
        ("НОРМАЛИЗОВАННЫЕ ДАННЫЕ", report['normalized_data'])
    ]

    try:
        with open(output_filename, 'w', encoding='utf-8') as f:

            unique_artifacts = set()

            def log(text=""):
                print(text)
                f.write(str(text) + '\n')

            def print_dict(d):
                for key, val in d.items():

                    if key == "valid":
                        title = "валидные"
                    elif key == "invalid":
                        title = "невалидные"
                    elif key == "normalized":
                        title = "нормализованные"
                    else:
                        title = key

                    if isinstance(val, dict):
                        log(title)
                        print_dict(val)

                    elif isinstance(val, list):
                        if val:
                            log(title + ":")
                            for item in val:
                                log(str(item))
                                unique_artifacts.add(str(item))
                        else:
                            log(title + ": (пусто)")

                    else:
                        log(f"{title}: {val}")

            log('ОТЧЕТ ОПЕРАЦИИ DATA SHIELD\n')

            total_count = 0

            for title, data in sections:
                log(title)

                count = 0
                if isinstance(data, list):
                    count = len(data)
                elif isinstance(data, dict):
                    count = sum(len(v) for v in data.values() if isinstance(v, list))

                total_count += count

                log(f'Найдено: {count}\n')

                if isinstance(data, list):
                    for item in data:
                        log(str(item))
                        unique_artifacts.add(str(item))

                elif isinstance(data, dict):

                    print_dict(data)
                log(f'Общее количество уникальных артефактов: {len(unique_artifacts)}')

                log()  # пустая строка между разделами

        print(f'Файл создан: {output_filename}')

    except Exception as e:
        print(f'Ошибка при сохранении: {e}')


# ЗАПУСК
if __name__ == '__main__':
    input_file = 'input5.txt'

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text = f.read()

        report = generate_comprehensive_report(text)
        print_and_save_report(report)

    except FileNotFoundError:
        print(f'Файл {input_file} не найден')