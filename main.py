# Operation Data Shield
# Developers: Yasminskaya V., Burykhina E., Tankova K.
import binascii
import re
import base64
import codecs


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
            if has_digit and has_special and has_english_letter:
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
    ip_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_regex, text)

    file_regex = r"\b[\w\.-] + (?:\.txt|\.pdf|\.jpg|\.png|\.docx|\.xlsx)\b"
    files = re.findall(file_regex, text)

    email_regex = r"[a-zA-Z0-9._%+-] + @[a-zA-Z0-9.-] + \.[a-zA-Z]{2,}"
    emails = re.findall(email_regex, text)

    return{'ips': ips, 'files': files, 'emails': emails}


# Role 4. Cryptanalyst
# Task: find and decrypt hidden messages
def decode_messages(text):
    ''' Finds and decrypts messages.
    :param text: Parts of the text containing encoded messages
    in Base64, Hex or ROT13 format.
    :return: {'base64': [], 'hex': [], 'rot13': []}
    '''
    import base64
    import codecs
    base64_list = []
    hex_list = []
    rot13_list = []
    # base64
    for word in text.split():
        try:
            decoded = base64.b64decode(word).decode('utf-8')
            if decoded.isprintable():
                base64_list.append(decoded)
        except:
            pass
    # hex
    for word in text.split():
        try:
            if word.startswith("0x"):
                hex_string = word[2:]
            elif word.startswith("\\x"):
                hex_string = word.replace("\\x", "")
            else:
                continue

            decoded = bytes.fromhex(hex_string).decode('utf-8')
            hex_list.append(decoded)
        except:
            pass
    # rot13
    if "ROT13:" in text:
        rot_text = text.split("ROT13:")[1].strip()
        decoded = codecs.decode(rot_text, 'rot_13')
        rot13_list.append(decoded)
    return {'base64': base64_list,'hex': hex_list, 'rot13': rot13_list}
    # Карина


# Role 5. Log analyst
# Task: validate logs for attacks
def analyze_logs(log_text):
    ''' Analyzes the logs of the web server.
    :param log_text: Parts of the text containing the logs of
    web servers may also include requests for attacks.
    :return: {'sql_injections': [], 'xss_attempts': [],
    'suspicious_user_agents': [], 'failed_logins': []}
    '''
    sql_injections = []
    xss_attempts = []
    suspicious_user_agents = []
    failed_logins = []
    lines = log_text.splitlines()
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

    return {'sql_injections': sql_injections,'xss_attempts': xss_attempts,'suspicious_user_agents': suspicious_user_agents,'failed_logins': failed_logins}
    # Карина


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
    # Вика
    pass


