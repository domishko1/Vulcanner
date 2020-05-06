from fpdf import FPDF
import fpdf

fpdf.SYSTEM_TTFONTS = 'C:/Users/1/PycharmProjects/scanner_sqlinj/'


def how_to_fix(pdf, filename):
    filename_ = 'data\\Report\\' + filename
    text = ''
    with open(filename_) as file_with_text:
        for line in file_with_text:
            text += line
    pdf.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
    pdf.set_font('DejaVu', '', 12)
    col_width = pdf.w - 20
    row_height = pdf.font_size + 1
    pdf.multi_cell(col_width, row_height, txt=text)
    pdf.ln(row_height)


def print_data(pdf, url, method, string_with_injection, type):
    index = string_with_injection.find("|")
    param = string_with_injection[:index]
    injection = string_with_injection[index + 1:]
    data = [['Тип уязвимости: ', type],
            ['URL-адрес: ', url],
            ['Метод: ', method],
            ['Параметр: ', param],
            ['Инъекция: ', injection]]
    pdf.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
    pdf.set_font('DejaVu', '', 12)
    col_width = pdf.w - 20
    row_height = pdf.font_size + 1
    for row in data:
        text = ''
        for item in row:
            text += item + '  '
        pdf.multi_cell(col_width, row_height, txt=text)
    pdf.ln(row_height)


'''
    Создание отчета
'''


def create_report(pdf_path, vulnerabilities_report):
    pdf = Report()
    pdf.add_page()
    url = vulnerabilities_report['url']
    method = vulnerabilities_report['method']
    time_sql_inj = vulnerabilities_report['sql_time']
    boolean_sql_inj = vulnerabilities_report['sql_boolean']
    xss_inj = vulnerabilities_report['xss']
    if len(time_sql_inj) != 0:
        print_data(pdf, url, method, time_sql_inj, 'Time-based blind SQL-инъекция')
    if len(boolean_sql_inj) != 0:
        print_data(pdf, url, method, boolean_sql_inj, 'Boolean-based blind SQL-инъекция')
    if len(xss_inj) != 0:
        print_data(pdf, url, method, xss_inj, 'Cross-Site Scripting')
    if len(time_sql_inj) != 0 or len(boolean_sql_inj) != 0:
        how_to_fix(pdf, 'SQL.txt')
    if len(xss_inj) != 0:
        how_to_fix(pdf, 'XSS.txt')
    pdf.output(pdf_path)


class Report(FPDF):

    def header(self):
        # Устанавливаем лого
        self.image('vulcanner.jpg', 10, 10, 50)  # y/x/%
        self.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
        self.set_font('DejaVu', '', 14)
        col_width = self.w / 1.5
        row_height = self.font_size
        self.cell(40)
        self.multi_cell(col_width, row_height, 'Результаты работы сканера уязвимостей веб-приложений - Vulcanner',
                        align='C')
        self.ln(row_height * 5)

    def footer(self):
        self.set_y(-10)
        # Добавляем номер страницы
        self.set_font('DejaVu', '', 14)
        page = str(self.page_no())
        self.cell(0, 10, page, 0, 0, 'C')
