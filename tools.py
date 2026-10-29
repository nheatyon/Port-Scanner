import re
import socket as skt

from colorama import Fore
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1
from scapy.volatile import RandShort
from tabulate import tabulate


class Helper:
    opened_ports = {}

    @staticmethod
    def color(text, fore):
        return fore + str(text) + Fore.LIGHTBLUE_EX

    def print_results(self, target):
        table = []
        for port in self.opened_ports:
            protocol = self.opened_ports[port].upper()
            port_details = self.color(str(port) + " (%s)" % protocol, Fore.LIGHTYELLOW_EX)
            status = self.color("Open", Fore.LIGHTGREEN_EX)
            banner = self.color(Scanner(target, port).get_banner(protocol), Fore.LIGHTRED_EX)
            banner = "".join(banner.rsplit("'", 1)).replace("b'", "")
            # Applying formatted details
            table.append([port_details, status, banner])
        headers = ["Port", "Status", "Banner"]
        print(Fore.LIGHTBLUE_EX +
              tabulate(table, headers, tablefmt="fancy_grid", stralign="center", numalign="center"))


class Scanner:
    def __init__(self, target, port):
        self.target = target
        self.port = port

    # TCP SYN Scan
    def tcp_syn(self):
        ether_ip = Ether() / IP(dst=self.target)
        tcp = TCP(sport=RandShort(), dport=self.port, flags="S")
        pkt = srp1(ether_ip / tcp, timeout=5, verbose=0)
        if pkt is not None:
            if pkt.haslayer(TCP) and pkt[TCP].flags == 18:  # SYN/ACK
                print(Fore.YELLOW + "[*] Port %s seems to be open" % self.port)
                Helper.opened_ports[self.port] = "TCP"
        return Helper.opened_ports

    # Get service's banner info
    def get_banner(self, mode):
        if mode == "TCP":
            sock = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
        elif mode == "UDP":
            sock = skt.socket(skt.AF_INET, skt.SOCK_DGRAM)
        else:
            return None
        sock.connect((self.target, int(self.port)))
        banner = sock.recv(1024)
        sock.close()
        if b"" == banner:
            return "None"
        return banner

    @staticmethod
    def is_valid(ip):
        reg = \
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        if re.match(reg, ip):
            return True
        else:
            return False
