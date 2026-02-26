# Operation Data Shield
# Developers: Yasminskaya V., Burykhina E., Tankova K.

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
def find_and_validate_credit_cards(text):
    ''' Finds the card numbers and verifies them using
    the Luna algorithm.
    :param text: Parts of the text containing information about
    credit cards numbers.
    :return: {'valid':[], 'invalid':[]}
    '''
    # Мила
    pass


# Role 2. The Key Hunter
# Task: find secret keys and passwords
def find_secrets(text):
    ''' Searches for API-keys, passwords and access tokens.
    :param text: Parts of the text containing information about
    keys, passwords and other secret data.
    :return: List of found secrets
    '''
    # Мила
    pass


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
    # Карина
    pass


# Role 5. Log analyst
# Task: validate logs for attacks
def analyze_logs(log_text):
    ''' Analyzes the logs of the web server.
    :param log_text: Parts of the text containing the logs of
    web servers may also include requests for attacks.
    :return: {'sql_injections': [], 'xss_attempts': [],
    'suspicious_user_agents': [], 'failed_logins': []}
    '''
    # Карина
    pass


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


