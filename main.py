import logging
import os
import sys
import threading
import time

import colorama
from colorama import Fore

from tools import Scanner, Helper


def get_thread(scanner):
    # Get thread and check for types
    if scan_type == "-tcp":
        return threading.Thread(target=scanner.tcp_syn, daemon=True)
    # Delete last printed line on console
    sys.stdout.write('\x1b[1A\x1b[2K')
    if scan_type == "-udp":
        print(Fore.RED + "[*] This feature will be available soon!")
    else:
        print(Fore.RED + "[!] Scan type not supported")
    exit(1)


def initialize():
    start_time = time.strftime("%H:%M:%S")
    print(Fore.LIGHTGREEN_EX + "[*] Scan started at " + start_time)
    # Scanning all ports from 1 to 65535
    for i in range(1, 65535):
        scanner = Scanner(target, i)
        try:
            get_thread(scanner).start()
        except KeyboardInterrupt:
            print(Fore.RED + "[-] Exiting..")
            exit(1)
    # Scan finished
    time.sleep(1)
    end_time = time.strftime("%H:%M:%S")
    print(Fore.CYAN + "[!] Scan of %s is terminated! [%s]" % (target, end_time))
    print(Fore.LIGHTBLUE_EX + "[*] Printing results...")
    Helper().print_results(target)


if __name__ == "__main__":
    colorama.init(autoreset=True)
    scapy_logger = logging.getLogger("scapy.runtime")
    scapy_logger.setLevel(logging.ERROR)
    # Check for args
    match len(sys.argv):
        case 3:
            target = sys.argv[1]
            scan_type = sys.argv[2].lower()
            if Scanner.is_valid(target):
                initialize()
            else:
                print(Fore.RED + "[!] Invalid IP. Please try again!")
        case _:
            print(Fore.RED + "[*] Usage: \"python {} <ip_address> <-tcp || -udp>\"".format(os.path.basename(__file__)))
