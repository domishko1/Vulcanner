from colorama import Fore
from colorama import init
class Colors:
    def __init__(self):
        init()
    HEADER = Fore.MAGENTA
    OKBLUE = Fore.BLUE
    OKGREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    WHITE = Fore.WHITE
    WARNING = Fore.RED
    EXIT = Fore.LIGHTYELLOW_EX
    FAIL = Fore.LIGHTRED_EX