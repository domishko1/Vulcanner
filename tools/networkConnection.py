import http
import time

from tools.colors import Colors


class NetworkConnection:
    def __init__(self):
        self.color = Colors()

    # Осуществляется проверка соединения сети
    def isConnect(self):
        print(self.color.OKGREEN + "  [" + time.strftime(
                    "%H:%M:%S") + "] [*]  Проверка сетевого подключения")
        conn = http.client.HTTPConnection("www.python.org", 80)
        try:
            conn.request("HEAD", "/")
            print(self.color.OKGREEN + "  [" + time.strftime(
                    "%H:%M:%S") + "] [+]  Соединение в порядке")
            _isConnect = True
        except:
            print(self.color.FAIL + "  [-]  Нет соединения сети")
            _isConnect = False
        return _isConnect
