import datetime
import random
import time
import re  # Поиск уязвимой части веб-запроса
import urllib.parse  # Парсинг URL-адреса
from time import sleep
from selenium import webdriver
from colors import Colors
from networkConnection import NetworkConnection
from report import Report
import report

# Загрузка User-Agents
def loadUserAgents(uafile="data\\User Agent\\user_agents.txt"):
    uas = []
    with open(uafile, 'rb') as uaf:
        for ua in uaf.readlines():
            if ua:
                uas.append(ua.strip()[1:-1 - 1])
    random.shuffle(uas)
    return uas


class Scanner:
    def __init__(self):
        self.color = Colors()
        self.temp_file_name_with_result_of_scanning = 'Report_' + time.strftime("%H_%M_%S") + '.pdf'
        self.temp_file_name_with_urls = "URLs.txt"
        self.connection = NetworkConnection()
        self.database_name = ["MySQL", "Microsoft SQL Server", "OracleSQL", "PostgreSQL"]
        self.vulnerabilities_report = {
                    'url': '',
                    'method': '',
                    'xss': '',
                    'sql_time': '',
                    'sql_boolean': '',
                    'list': ''}
        self.report = Report()

    '''
    Инициализация драйвера для работы с Selenium
    '''
    def init_driver(self):
        options = webdriver.ChromeOptions()
        options.binary_location = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
        # Загрузка пользовательского агента (рандомного)
        uas = loadUserAgents()
        ua = random.choice(uas)
        self.agent = ua
        if self.agent:
            options.add_argument('user-agent={}'.format(self.agent))
        options.add_argument("start-maximized")
        options.add_argument('headless')
        self.driver = webdriver.Chrome(options=options)

    '''
    Сканироване URL-адреса
    Параметры:
        url - адрес для сканирования на уязвимости    
    '''
    def scanning(self, url):
        try:
            self.init_driver()
            print(self.color.OKGREEN + "  [" + time.strftime("%H:%M:%S") + "] Начало работы сканера")
            if self.connection.isConnect():
                self.driver.get(url)
                useragent = self.agent
                cookies = self.driver.get_cookies()
                method = ''
                matches = {}
                if "?" in url:
                    method = 'GET'
                    # Parse GET data (in url)
                    params = url.split('?')[1]
                    regex_value = re.compile('([a-zA-Z0-9\-_]*?=[a-zA-Z#]*\d*)')
                    matches = regex_value.findall(params)
                else:
                    method = 'POST'
                    matches.append('*')
                self.vulnerabilities_report['method'] += str(method)
                self.vulnerabilities_report['url'] += str(url)
                for fuzz in matches:
                    print(self.color.WHITE + "  [" + time.strftime(
                        "%H:%M:%S") + "] [" + method + "]" + " Проверка параметра " + fuzz)
                    database, database_error = self.get_database(url, method, fuzz)
                    if len(database) != 0:
                        print(self.color.WHITE + "  [" + time.strftime(
                            "%H:%M:%S") + "] Параметр: " + fuzz + " (" + method + ")")
                        self.scan_sql_blind_time(method, url, fuzz, database)
                        self.scan_sql_blind_boolean(method, url, fuzz, database, database_error)
                        self.scan_xss(method, url, fuzz)
                    else:
                        if method == 'GET':
                            self.scan_sql_blind_time(method, url, fuzz, "All")
                            self.scan_xss(method, url, fuzz)
                        if len(self.vulnerabilities_report['list']) == 0:
                            print(self.color.WHITE + "  [" + time.strftime("%H:%M:%S") + "] Параметр " + fuzz + "не "
                                                                                                                "уязвим!")
                report.create_report(self.temp_file_name_with_result_of_scanning, self.vulnerabilities_report)
                print(self.color.WHITE + "  [" + time.strftime(
                    "%H:%M:%S") + "] Результаты сохранены в следующий файл: " + self.temp_file_name_with_result_of_scanning)
                self.driver.quit()
        except KeyboardInterrupt:
            print(self.color.FAIL + "  [" + time.strftime("%H:%M:%S") + "] Ошибка! ")
        except:
            print(self.color.EXIT + "  [" + time.strftime("%H:%M:%S") + "] Ошибка")

    '''
    Вывод информации об обнаруженой уязвимости
    Параметры:
        type - тип уязвимости
        fuzz - уязвимый параметр 
        database - тип БД 
        title - название вида уязвимости 
        payload - инъекция
    '''
    def print_info_about_vulnerabilities(self, type, fuzz, database, title, payload):
        print(self.color.WHITE + "          Тип: " + type)
        print(self.color.WHITE + "          Название: " + database + " " + title)
        print(self.color.WHITE + "          Инъекция: " + fuzz + ' ' + payload)

    '''
    Сканирование на Time-based SQLi уязвимость
    Параметры:
    method - метод отправки данных
    url - адрес сканирования
    fuzz - параметр для сканирования
    database - тип БД
    '''
    def scan_sql_blind_time(self, method, url, fuzz, database):
        try:
            file_with_payloads = "data\\Time Blind Payloads\\" + database + ".txt"
            with open(file_with_payloads) as injection_file:
                for injection in injection_file:
                    a = injection.rstrip()
                    # POST
                    if method == 'POST':
                        inject = url + injection
                        time_start = datetime.datetime.now()
                        self.driver.get(inject)
                    # GET
                    else:
                        inject = url.replace(fuzz, fuzz + " " + a)
                        time_start = datetime.datetime.now()
                        self.driver.get(inject)
                    time_end = datetime.datetime.now()
                    diff = time_end - time_start
                    diff = (divmod(diff.days * 86400 + diff.seconds, 60))[1]
                    if diff > 2:
                        self.print_info_about_vulnerabilities("time-based blind", fuzz, database,
                                                              "AND time-based blind",
                                                              injection)
                        self.vulnerabilities_report['sql_time'] += str(fuzz) + str('|') + str(injection)
                        self.vulnerabilities_report['list'] += 'B_SQLi|TYPE Time-Based|' + inject + '|DELIMITER|'
                        break
        except:
            print(self.color.FAIL + "  [" + time.strftime(
                "%H:%M:%S") + "] [X] Ошибка при сканировании на Time Blind SQL-инъекцию!")

    '''
    Сканирование на Boolean-based SQLi уязвимость
    Параметры:
    method - метод отправки данных
    url - адрес сканирования
    fuzz - параметр для сканирования
    database - тип БД
    string_with_error_database - ошибка
    '''
    def scan_sql_blind_boolean(self, method, url, fuzz, database, string_with_error_database):
        try:
            halflength_of_str_error = int(len(string_with_error_database) / 2)
            first_part_of_str_error = string_with_error_database[: halflength_of_str_error]
            second_part_of_str_error = string_with_error_database[halflength_of_str_error:]
            file_with_payloads = "data\\Boolean Blind Payloads\\" + database + ".txt"
            with open(file_with_payloads) as injection_file:
                for injection in injection_file:
                    injection = injection.rstrip()
                    # POST
                    if method == 'POST':
                        inject = url + injection
                    # GET
                    else:
                        inject = url.replace(fuzz, fuzz + injection)
                    self.driver.get(inject)
                    body_element = self.driver.find_element_by_xpath("//body")
                    text_from_body_with_inject = body_element.get_attribute("textContent")
                    if text_from_body_with_inject.find(
                            first_part_of_str_error) == -1 and text_from_body_with_inject.find(
                            second_part_of_str_error) == -1:
                        self.print_info_about_vulnerabilities("boolean-based blind", fuzz, database,
                                                              "AND boolean-based blind",
                                                              injection)
                        self.vulnerabilities_report['sql_boolean'] += str(fuzz) + str('|') + str(injection)
                        self.vulnerabilities_report['list'] += 'B_SQLi|TYPE Boolean-Based|' + inject + '|DELIMITER|'
                        break

        except:
            print(self.color.FAIL + "  [" + time.strftime(
                "%H:%M:%S") + "] [X] Ошибка при сканировании на Boolean Blind SQL-инъекцию!")

    '''
    Сканирование на XSS уязвимость
    Параметры:
    method - метод отправки данных
    url - адрес сканирования
    fuzz - параметр для сканирования
    '''
    def scan_xss(self, method, url, fuzz):
        try:
            type_of_alerts = ["1"]
            file_with_payloads = "data\\XSS Payloads\\xss_payloads.txt"
            with open(file_with_payloads) as injections_file:
                for payload in injections_file:
                    try:
                        # POST
                        if method == 'POST' and fuzz == '*':
                            inject = url.replace('*', payload)
                        # GET
                        if method == 'GET':
                            inject = url.replace(fuzz, fuzz + " " + payload)
                        inject = inject.rstrip()
                        self.driver.get(inject)
                        time.sleep(1)
                        result = self.driver.switch_to.alert
                        alert = result.text
                        if alert in type_of_alerts:
                            self.print_info_about_vulnerabilities("XSS", fuzz, "", "Cross-Site Scripting", payload)
                            self.vulnerabilities_report['xss'] += str(fuzz) + str('|') + str(payload)
                            self.vulnerabilities_report['list'] += 'XSS|TYPE|' + inject + '|DELIMITER|'
                            self.driver.quit()
                            self.init_driver()
                            break
                    except Exception as e:
                        if "confirm" in str(e):
                            self.print_info_about_vulnerabilities("XSS", fuzz, "",
                                                                  "Cross-Site Scripting (False positive ?)", payload)
                            inject = url + ":" + fuzz + ":" + payload
                            self.vulnerabilities_report['xss'] += str(fuzz) + str('|') + str(inject)
                            self.vulnerabilities_report['list'] += 'XSS|TYPE|' + inject + '|DELIMITER|'
                            self.driver.quit()
                            self.init_driver()
            injections_file.close()
        except:
            print(self.color.FAIL + "  [" + time.strftime(
                "%H:%M:%S") + "] [X] Ошибка при сканировании на XSS!")

    '''
    Обнаружение возможного типа БД
    Параметры:
    line - url-адрес
    method - метод отправки данных 
    fuzz - параметр для сканирования
    '''
    def get_database(self, line, method, fuzz):
        payload = "'"
        try:
            if method == 'POST':
                url = line.replace('*', payload)
            if method == 'GET':
                url = line.replace(fuzz, fuzz + payload)
            # Получение данных
            self.driver.get(url)
            if self.login():
                self.driver.get(url)
            body_element = self.driver.find_element_by_xpath("//body")
            text_from_body = body_element.get_attribute("textContent")
            current_database_name = ''
            for db_name in self.database_name:
                file_with_error_strings = "data\\Error strings\\" + db_name + ".txt"
                with open(file_with_error_strings) as error_strings:
                    for check_string in error_strings:
                        check_string = check_string.rstrip()
                        if text_from_body.find(check_string) != -1:
                            current_database_name = db_name
                            break
                    if current_database_name != '':
                        break
            if len(current_database_name) != 0:
                print(self.color.FAIL + "  [" + time.strftime(
                    "%H:%M:%S") + "] [*] Возможно, " + method + " параметр " + fuzz + " уязвим к инъекциям!")
                print(self.color.YELLOW + "  [" + time.strftime(
                    "%H:%M:%S") + "] [*] Предположительно, база данных " + str(current_database_name))
                print(self.color.WHITE + "  [" + time.strftime("%H:%M:%S") + "] [*] Сообщение: " + str(
                    text_from_body).replace('\n', ' ').replace('\r', '').replace('\t', '').replace('  ', ''))
                with open(self.temp_file_name_with_result_of_scanning, 'a') as file:
                    file.write(line)
            else:
                print(
                    self.color.WHITE + "  [" + time.strftime("%H:%M:%S") + "] [X] Не удалось выяснить тип базы данных")
            return current_database_name, str(text_from_body)
        except KeyboardInterrupt:
            print(self.color.FAIL + "  [" + time.strftime("%H:%M:%S") + "] [X] " + line)
        except Exception as e:
            print(e)
            return '', ''

    '''
    Авторизация    
    '''
    def login(self):
        try:
            username_element = self.driver.find_element_by_name('username')
            redirect = False
            if username_element:
                password_element = self.driver.find_element_by_name('password')
                login_submit = self.driver.find_element_by_name('Login')
                username_element.click()
                username_element.send_keys('admin')
                password_element.click()
                password_element.send_keys('password')
                login_submit.click()
                redirect = True
            return redirect
        except:
            ""

        # Получение данных

    '''
    Получение данных при работе с googledorks
    '''
    def get_data_for_google_dorks(self):
        # Kоличество страниц для просмотра
        count_of_pages_for_searching = input("  Число страниц для просмотра: ")
        if not count_of_pages_for_searching.isdigit():
            print(self.color.WARNING + "  [" + time.strftime(
                "%H:%M:%S") + "] Ошибка ввода! Вводите число. Используется число по умолчанию - 5")
            count_of_pages_for_searching = 5
        # Пауза между запросами
        timeout = input("  [" + time.strftime("%H:%M:%S") + "] Введите длительность паузы между запросами: ")
        if not timeout.isdigit():
            print(self.color.WARNING + "  [" + time.strftime(
                "%H:%M:%S") + "] Ошибка ввода! Вводите число. Используется число по умолчанию - 5")
            timeout = 3
        pages = int(count_of_pages_for_searching)
        sleep_time = int(timeout)
        return pages, sleep_time

    '''
    Поиск URL-адресов через googledork
    Параметры:
    dork - googledork
    '''
    def search_urls_with_google_dorks(self, dork):
        # =================================
        # Проходим по страницам
        # =================================
        try:
            self.init_driver()
            dork = urllib.parse.quote_plus(dork)
            pages, sleep_time = self.get_data_for_google_dorks()
            print("  [" + time.strftime("%H:%M:%S") + "] [*]:: Поиск.")
            print(self.color.OKGREEN + "  [" + time.strftime("%H:%M:%S") + "] [+]  Результат:")
            start_page = 0
            count_pages = 10
            for start in range(start_page, pages):
                # Google поиск
                current_page = int(start) * int(count_pages)
                url_address = "https://www.google.dk/search?q=" + dork + "&num=" + count_pages + "&start=" + str(
                    current_page)
                self.driver.get(url_address)
                print("  [" + time.strftime("%H:%M:%S") + "] [*]  Номер страницы: " + str(int(start) + 1))
                cite_urls = self.driver.find_elements_by_xpath('//div[@class = "r"]/a')
                urls = []
                for link in cite_urls:
                    urls.append(link.get_attribute("href"))
                for url in urls:
                    if dork in url:
                        print(
                            self.color.OKGREEN
                            + "  ["
                            + time.strftime("%H:%M:%S")
                            + "]  [+]  " + url
                        )
                        with open(self.temp_file_name_with_result_of_scanning, 'a') as file:
                            file.write(url + "\n")
                sleep(sleep_time)
            print("  [" + time.strftime("%H:%M:%S") + "] Парсинг веб-страниц выполнен!")
            with open(self.temp_file_name_with_result_of_scanning) as f:
                results_number = sum(1 for _ in f)
            print("  [" + time.strftime(
                "%H:%M:%S") + "] Результаты сохранены в следующий файл: " + self.temp_file_name_with_result_of_scanning)
            print("  [" + time.strftime("%H:%M:%S") + "] Всего сохраненных URL-адресов:  " + str(results_number))
            # Обработка ошибок
        except KeyboardInterrupt:
            print(self.color.FAIL + "  [" + time.strftime("%H:%M:%S") + "] Ввод с клавиатуры! ")
        except:
            print(self.color.EXIT + "  [" + time.strftime("%H:%M:%S") + "] Ошибка! ")

