import re
import sys
import time

from scanner import Scanner
from tools.colors import Colors

color = Colors()


def _help():
    print(color.HEADER + "  -h             Показать все функции сканера")
    print(color.HEADER + "  -u URL         Сканирование URL-адреса")
    print(color.HEADER + "  -g GOOGLEDORK  Найти список URL-адресов по Googledork ")
    sys.exit()


def exit_scanner():
    print(color.OKGREEN + "  [" + time.strftime("%H:%M:%S") + "] Выход")
    sys.exit()


def banner():
    print("___    _____     __ __      _____    ___    __     __     __  ______ ____    " + color.WHITE)
    print("\  \  /  /  |   |  |  |    /  ___\ /  _  \|    \  |  |\  |  ||   ___| __  \  " + color.WHITE)
    print(" \  \/  /|  |   |  |  |   |  /    /  /_\  \     \ |  | \ |  ||  |_|_ |__| |  " + color.OKBLUE)
    print("  \    / \  \   /  |  |   |  |   /   ___   \  |  \|  |  \|  ||   ___|    /   " + color.OKBLUE)
    print("   \  /   \  \_/  /|  \___|  \__/  /     \  \ |\  \  |   \  ||  |_|_  |\  \  " + color.WARNING)
    print("    \/     \ ___ / \______/\ __/_ /       \__\| \ __ |\ ___ ||______|_| \__\ " + color.WARNING)


if __name__ == '__main__':
    scanner = Scanner()
    scanner.create_pdf('report' + time.strftime("%H_%M_%S") + '.pdf')
    try:
        banner()
        if len(sys.argv) == 2:
            options = sys.argv[1]
        if len(sys.argv) == 3:
            options = sys.argv[1]
            target = sys.argv[2]
        if options == '-u':
            if re.search(r"\A(http|www\.|\w[\w.-]+\.\w{2,})", target) is not None:
                scanner.scanning(target)
            else:
                print(color.WARNING + "  [" + time.strftime("%H:%M:%S") + "] [X] Некорректно введен URL-адрес.")
                print(color.OKBLUE + "  [" + time.strftime(
                    "%H:%M:%S") + "] [*] Пример: http://www.site.com/vuln.php?id=1")
        elif options == '-g' and len(target) != 0:
            scanner.search_urls_with_google_dorks(target)
        elif options == '-h':
            _help()
        scanner.driver.quit()
        exit_scanner()
    except:
        print(color.OKBLUE + "  [" + time.strftime(
                    "%H:%M:%S") + "] [X] Ошибка ввода!")
        exit_scanner()
