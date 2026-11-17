#!/usr/bin/env python3
"""
    python main.py collect [--full] [--sources cert telegram]
    python main.py calibrate      # авто-поріг за еталонним джерелом
    python main.py rescore        # перерахунок score без повторного збору
    python main.py cluster        # дедуплікація між джерелами
    python main.py export         # docs.jsonl + events.jsonl
    python main.py weights        # матриця Сааті, ваги критеріїв, CR
"""
import argparse
import hashlib
import json
import logging
import re
import sqlite3
import time
import unicodedata
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from math import prod
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dtparser
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Конфігурація
DB_PATH = "cyber.db"
RAW_DIR = Path("raw")
SINCE = datetime(2022, 2, 24, tzinfo=timezone.utc)
SINCE_ISO = SINCE.isoformat(timespec="seconds")
MAX_PAGES = 2000
SLEEP = 1.0
CALIB_PERCENTILE = 0.10     # процентиль оцінок еталонного джерела (CERT-UA)
CALIB_MIN_DOCS = 20         # мінімум еталонних документів для калібрування
KYIV = ZoneInfo("Europe/Kyiv")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 (academic-research)"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("parser.log", encoding="utf-8"), logging.StreamHandler()],
)
log = logging.getLogger("cyber")


def to_utc_iso(value, dayfirst=False):
    if value is None or value == "":
        return None
    try:
        s = str(value).strip()
        if s.isdigit() and len(s) >= 10:
            n = int(s)
            dt = datetime.fromtimestamp(n / 1000 if len(s) >= 13 else n, tz=timezone.utc)
        else:
            dt = dtparser.parse(s, dayfirst=dayfirst)
    except (ValueError, OverflowError, OSError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=KYIV)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def normalize(text):
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text).replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


URL_RE = re.compile(r"https?://\S+|hxxps?://\S+")


def fingerprint(text):
    # Хеш нормалізованого тексту (нижній регістр, без посилань і пунктуації)
    t = URL_RE.sub(" ", text.lower())
    t = re.sub(r"[^\w]+", " ", t).strip()
    return hashlib.md5(t.encode("utf-8")).hexdigest()


def url_id(url):
    return hashlib.md5(url.encode("utf-8")).hexdigest()[:16]


def detect_lang(text):
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "unknown"
    cyr = sum("\u0400" <= c <= "\u04ff" for c in letters) / len(letters)
    if cyr > 0.5:
        return "uk/ru"
    return "en" if cyr < 0.1 else "mixed"


def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    retry = Retry(total=5, backoff_factor=1.5, status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["GET"], respect_retry_after_header=True)
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def save_raw(category, doc_id, content, ext):
    if content is None:
        return None
    d = RAW_DIR / category
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{doc_id}.{ext}"
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    return str(p)


APOS_RE = re.compile(r"[’ʼ`´‘′]")
DASH_RE = re.compile(r"[‐‑–—−]")


def compile_term(t):
    return re.compile(rf"\b{t[:-1]}\b" if t.endswith("$") else rf"\b{t}", re.I)


# Словники
CYBER_THREATS = [
    "кібератак", "кіберінцидент", "кіберзагроз", "кібершпигун", r"кібер\w*(?:операц|злочин)",
    "кібервійн", "кіберсаботаж", "кібердиверс",
    r"кібернетичн\w+\s+(?:атак|інцидент|загроз)", r"комп'ютерн\w+\s+(?:атак|інцидент|вірус)",
    r"хакерськ\w+\s+(?:атак|напад)", "хакер", "злам",
    "malware", r"шкідлив\w+\s+(?:програм|код|файл|пз\b|по\b|розсилк|ресурс)",
    r"шпигунськ\w+\s+(?:пз|програм)", "spyware", "експлойт", "exploit$", "вразливіст",
    "бекдор", "backdoor", "ботнет", "botnet", r"троян(?!д)", "wiper", "stealer", "стілер",
    "кейлогер", "keylogger", "rootkit", "rat$", "c2$", "webshell", r"веб-?шел",
    r"командн\w+\s+(?:сервер|центр)", r"сервер\w*\s+управлін",
    "industroyer", "blackenergy", "notpetya", "caddywiper", "hermeticwiper", "whispergate",
    r"acid\s?rain", "fiberlake", "pipedream", "incontroller", "pterodo", "lameshell",
    "remcos", "asyncrat", "dcrat", "darkcrystal", "quasar", r"cobalt\s?strike", "metasploit",
    "mimikatz", "meterpreter", "vidar", "redline", "lummastealer", "xworm", "njrat",
    "formbook", r"agent\s?tesla", "snakekeylogger",
]
ATTACK_TYPES = [
    "фішинг", "phishing", "смішинг", "smishing", "вішинг", "vishing", "quishing",
    "спуфінг", "spoofing", "ddos", "dos$", "ransomware", r"програм\w*-?вимагач",
    "шифрувальник", r"вірус\w*-?(?:вимагач|шифрувальник)",
    "брутфорс", r"brute.?force", r"password.?spray", r"credential.?stuffing",
    r"sql.?injection", "xss$", r"remote\s+code\s+execution", "rce$", r"zero.?day", r"0-?day",
    "дефейс", "defacement", r"підмін\w+\s+(?:сайт|веб|вмісту)",
    r"ланцюг\w*\s+постачан", r"supply.?chain", r"man.in.the.middle", "mitm$",
    r"перехоплен\w+\s+(?:трафік|даних|сесі)", r"(?:dns|bgp).?hijack", "typosquat",
    r"соціальн\w+\s+інженері", r"social\s+engineering",
]
ATTACK_ACTIONS = [
    "проникнен", "вторгнен", "несанкціонован", "компрометац", r"отримал\w*\s+доступ",
    "закріпленн", "персистентн", "ексфільтрац", "exfiltrat",
    r"викрад\w+\s+(?:дан|інформац|облікових|баз)", "шифруванн",
    r"знищенн\w+\s+(?:дан|інформац)", "затиранн", r"ескалаці\w+\s+привілей",
    r"privilege\s+escalation", "латеральн", r"lateral\s+movement", "зловмисник",
    r"віддален\w+\s+(?:доступ|керуванн|виконанн)",
    r"зараженн\w+\s+(?:систем|комп|пристро|мереж|хост)", "інфікуван",
    r"розгорнут\w+\s+(?:бекдор|шкідлив)",
]
THREAT_ACTORS = [
    r"apt\s?-?\d*$", r"uac-\d", r"unc\d{3,4}", r"хакерськ\w+\s+(?:угруповань|груп)",
    "кіберугрупован", "кіберзлочин", "хактивіст", "hacktivis",
    r"спонсован\w+\s+держав", r"державн\w+\s+хакер",
    r"(?:російськ|китайськ|північнокорейськ|іранськ|білоруськ|проросійськ)\w*\s+"
    r"(?:хакер|хактивіст|кіберугрупован|угрупован)",
    "sandworm", "gamaredon", "turla", r"fancy\s+bear", r"cozy\s+bear", "armageddon",
    r"primitive\s+bear", "shuckworm", "callisto", "coldriver", r"star\s+blizzard",
    r"(?:midnight|forest|seashell|cadet)\s+blizzard", "nobelium", r"energetic\s+bear",
    "ghostwriter", "lorec53", r"saint\s+bear", "vermin",
    "killnet", "noname057", "xaknet", "cyberarmy", r"cyber\s+army", "solntsepek",
    r"server\s+killers", r"z-?pentest", "beregini",
    "lockbit", "conti$", "alphv", "blackcat", "revil", "clop$", "akira$", r"black\s?basta",
    "rhysida", "lazarus",
]
IMPACTS = [
    r"витік\w*\s+(?:даних|інформац|персональн|баз|документ)", r"злив\w*\s+(?:даних|баз|інформац)",
    "знеструмлен", "блекаут", "збій", "недоступн", "паралізува",
    r"зупинк\w+\s+(?:робот|систем|виробництв)", "відключен", r"порушен\w+\s+робот",
    r"втрат\w+\s+(?:даних|доступ)", r"розкритт\w+\s+(?:даних|інформац)",
    r"оприлюдн\w+\s+(?:дан|документ)",
    r"відмов\w+\s+(?:в\s+)?обслуговуван",
    r"перебо\w*\s+(?:в|з|у)\s+(?:робот|електропостач|водопостач|теплопостач|зв'язк|постачан)",
    r"блокуванн\w+\s+(?:робот|систем|доступ)", r"вихід\s+з\s+ладу", r"виведен\w+\s+з\s+ладу",
    r"пошкодженн\w+\s+(?:обладнан|систем|даних|файл)", "компрометован", r"зрив\s+робот",
    r"припинен\w+\s+(?:робот|надання|постачан)", r"масов\w+\s+відключен",
]
INFO_OPS = [
    "іпсо", "ботоферм", "дезінформац", "disinformation", "фейк", "пропаганд", "наратив",
    "маніпуляц", "вкид", "тролфабрик", r"фабрик\w+\s+тролів", "діпфейк", "deepfake",
    r"doppelg\w+", r"storm-?1516", r"portal\s+kombat", r"pravda\s+network",
    r"coordinated\s+inauthentic", r"скоординован\w+\s+(?:неавтентичн|кампані)",
    r"hack.?and.?(?:leak|publish)",
    r"психологічн\w+\s+(?:операц|вплив)", "fimi", r"інформаційно-психологічн",
    r"інформаційн\w+\s+(?:операц|вплив|війн|атак|кампані)",
]
TECHNOLOGY = [
    "scada", "асутп", r"асу\s?тп", "ics$", "plc$", "плк$", "hmi$", "dcs$", "rtu$", "modbus", "dnp3",
    r"iec[\s-]?(?:104|61850|60870)", r"технологічн\w+\s+(?:мереж|процес|систем)",
    "телемеханік", r"релейн\w+\s+захист", r"диспетчеризац", "siemens", "schneider",
    "rockwell", "simatic", "wago",
    "vpn$", "rdp$", "ssh$", "smb$", "dns$", "bgp$", "firewall", "маршрутизатор", "router$", "роутер",
    "mikrotik", "мікротік", "cisco", "fortinet", "fortigate", "fortios", r"pan-?os", r"palo\s?alto",
    "sonicwall", "citrix", "netscaler", "ivanti", "vmware", "esxi", "huawei", "hikvision", "dahua",
    r"ip-?камер", r"sim-?бокс", "iot$", "прошивк", "firmware",
    r"active\s+directory", r"domain\s+controller", "exchange$", "zimbra", "roundcube",
    "log4j", "log4shell", "proxyshell", "proxylogon", "confluence", "gitlab", "jenkins",
    "wordpress", "joomla", r"(?:m\.?e\.?doc|медок)", "powershell", "anydesk", "teamviewer",
    "хмарн", "cloud$", "windows", "linux", r"баз\w+\s+даних", "сервер",
]
LEAK_TERMS = [
    r"витік\w*\s+(?:даних|інформац|персональн|баз|документ)", r"злив\w*\s+(?:даних|баз|інформац)",
    "дамп", r"data.?leak", r"data.?breach", r"викрад\w+\s+(?:дан|баз|документ)",
    r"оприлюдн\w+\s+(?:дан|документ)", r"продаж\w*\s+(?:баз\w*\s+даних|доступ)",
    "даркнет", "darknet", r"dark\s?web", "breachforums", r"hack.?and.?leak",
]
PHYSICAL_TERMS = [
    "знеструмлен", "блекаут", r"відключен\w+\s+(?:електро|світл|опален|вод|газ)",
    r"зупинк\w+\s+(?:виробництв|підстанц|турбін)", "аварі", r"пошкодженн\w+\s+обладнан",
    r"пошкодженн\w+\s+(?:трансформатор|турбін)", r"вихід\s+з\s+ладу", r"аварійн\w+\s+відключен",
    "вимикач", r"насосн\w+\s+станці",
    "scada", "асутп", r"асу\s?тп", "plc$", "плк$", "modbus", r"iec[\s-]?104", "pipedream",
]
KINETIC_NOISE = [
    "мобілізац", "тцк", "ухилянт", "вбивств", "дтп", "хабар", "корупці", "нарко", "кол-центр",
    "крадіжк", "ґвалтуван", "держзрад", "колаборант", "контрабанд", "тендер", "олігарх",
    "шахед", "ракетн", "обстріл", "снаряд", "артилері", "штурм", "загинул", "поранен",
    "бпла", r"лінія\s+фронту", "фронт$",
    "кіберпес", "кіберкіт", "шахрайгудбай", "форум", "вебінар", "тренінг", "онлайн-курс",
    "курсу", "сніданок", "день науки", "подкаст", "хакатон", "конференці", "воркшоп", "семінар",
    "запрошуємо", "вакансі", "стипенді", "конкурс", "фестивал", "виставк", "нагород",
    "кібергігієн", "інтерв'ю", r"навчальн\w+\s+(?:курс|програм)",
    "кіберстійкіст", r"місяц\w*\s+кібербезпеки", r"нагадує\s+про\s+небезпеки", "forum$",
]
# Сектори
SECTORS = {
    "energy": [
        "обленерго", "укренерго", "енергосектор", "енергетик", "енергетичн", "енергокомпан",
        "енергоатом", "центренерго", "гідроенерго", "енергопостачальн", "електропостач",
        "електромереж", "енергосистем", "енергогенеруюч", "дтек", "нафтогаз", "укргазвидобут",
        "укртрансгаз", "нафтопереробн", "нафтопровід", "газопровід", "газотранспорт",
        "теплопостач", "тепломереж", "теплоелектро", "котельн", "підстанці",
        r"(?:сонячн|вітров)\w+\s+електростанц", r"оператор\w*\s+(?:системи\s+)?(?:розподілу|передачі)",
        "аес$", "тец$", "тес$", "гес$", "азс$",
    ],
    "telecom": [
        "телеком", "провайдер", "київстар", "vodafone", "lifecell", "укртелеком", "datagroup",
        "triolan", "тріолан", "ланет", r"оператор\w*\s+(?:зв'язку|мобільн|телеком)",
        r"електронн\w+\s+комунікац", r"базов\w+\s+станці", r"магістральн\w+\s+(?:мереж|канал)",
        r"дата-?центр", "хостинг", r"інтернет-?провайдер", "нкрзі", "ixp$",
    ],
    "finance": [
        r"банк(?!рут)", "ощадбанк", "приватбанк", "монобанк", "нбу$", "нацбанк",
        r"платіжн\w+\s+(?:систем|карт|сервіс|термінал|провайдер)", "еквайринг", "банкомат",
        "фінансов", "страхов", r"фондов\w+\s+бірж", r"цінн\w+\s+папер", "фінтех", "fintech",
        r"інтернет-?банкінг", r"мобільн\w+\s+банкінг", "liqpay", "portmone", "swift$",
        "фінмоніторинг",
    ],
    "transport": [
        "залізниц", "залізнич", "укрзалізниц", "аеропорт", "авіакомпан", "логістик", "метро$",
        "метрополітен", r"нова\s+пошта", "укрпошт", "meest", r"морськ\w+\s+порт", "судноплавн",
        "укравтодор", r"громадськ\w+\s+транспорт", r"електронн\w+\s+квиток",
        r"диспетчер\w*\s+(?:рух|аеропорт|поїзд)",
    ],
    "government": [
        "міністерств", "кабмін", r"кабінет\w*\s+міністрів", r"державн\w+\s+реєстр",
        r"(?:додаток|портал|застосунок)\s+«?дія", "мінцифр", "рнбо", r"верховн\w+\s+рад",
        r"офіс\s+президент", r"органи\s+державн", r"органи\s+влади", r"органів\s+влади",
        r"державн\w+\s+(?:орган|установ|служб|підприємств)", r"місцев\w+\s+самоврядуван",
        "міськрад", "облрад", "райдержадміністрац", "обладміністрац", "облдержадміністрац",
        r"територіальн\w+\s+громад", "мерія", r"єдин\w+\s+державн\w+\s+реєстр",
        r"пенсійн\w+\s+фонд", "пфу$", "дпс$", "дмс$", "дснс", "нацполіц", r"національн\w+\s+поліці",
        "держгеокадастр", "prozorro", "прозорро", "мвс$", "мзс$",
    ],
    "defense": [
        "міноборони", "зсу$", r"збройн\w+\s+сил", r"сил\w*\s+оборон", "генштаб",
        r"військов\w+\s+(?:частин|формуван|адміністрац|об.єкт)", "військовослужбовц",
        r"оборонн\w+\s+(?:промислов|підприємств|комплекс|сектор)", "оборонк",
        "оборонно-промислов", "нацгвард", "прикордонн",
    ],
    "justice": [
        "нотаріус", "нотаріат", "нотаріальн", "прокуратур", r"мін.?юст", "юстиці",
        r"(?:районн|міськ|окружн|апеляційн|господарськ|верховн|конституційн|печерськ)\w*\s+суд",
        r"судов\w+\s+(?:систем|реєстр|влад)", r"виконавч\w+\s+служб",
    ],
    "media": [
        "укрінформ", "телеканал", "радіостанц", r"інформаційн\w+\s+агентств",
        r"новинн\w+\s+(?:сайт|портал|агентств)", r"засоб\w+\s+масов\w+\s+інформац",
        "телебаченн", r"суспільн\w+\s+мовленн", "змі$",
    ],
    "healthcare": [
        "лікарн", "медичн", "госпітал", r"охорон\w+\s+здоров", "клінік", "поліклінік",
        "нзсу", "медзаклад", "пацієнт", r"швидк\w+\s+допомог", "аптек", "фармацевт",
        r"електронн\w+\s+(?:медичн|реєстр)", r"е-?здоров", "ehealth",
    ],
    "water": [
        "водоканал", "водопостач", "водовідвед", "водогін", "водоочисн", "каналізац",
        r"очисн\w+\s+споруд", r"питн\w+\s+вод", "водонапірн", "водосховищ", "гідротехнічн",
        r"комунальн\w+\s+(?:підприємств|служб|господарств)",
    ],
    "industry_ics": [
        "scada", "асутп", r"асу\s?тп", "плк$", "plc$", "hmi$", "ics$", "dcs$", "промислов",
        "виробництв", r"технологічн\w+\s+(?:мереж|процес)", "завод", "металург", "коксохім",
        "машинобудув", r"хімічн\w+\s+(?:підприємств|промислов|завод)", "агрохолдинг", "аграрн",
        r"харчов\w+\s+(?:промислов|виробництв)", "космічн",
    ],
}
CRITICAL_INFRA_GENERIC = [
    r"критичн\w+\s+інфраструктур", r"об.єкт\w*\s+критичн", r"critical\s+infrastructure",
    "життєзабезпеченн", r"ключов\w+\s+(?:інфраструктур|об.єкт)", r"оператор\w*\s+критичн",
]

CREDENTIAL_RE = re.compile(r"парол|логін|облікові\s+дані|credentials|токен|ключ\w*\s+доступ", re.I)
PERSONAL_RE = re.compile(r"персональн\w+\s+дан|паспорт|\bіпн\b|номер\w*\s+телефон|прізвищ", re.I)
TOPOLOGY_RE = re.compile(r"схем\w+\s+мереж|топологі|hostname|ip-?адрес|внутрішн\w+\s+(?:мереж|ip)", re.I)
DUMP_RE = re.compile(r"дамп|баз\w+\s+даних|злив", re.I)


def extract_iocs(text):
    t = text.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
    ips = [ip for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t))
           if all(int(o) <= 255 for o in ip.split("."))]
    return {
        "cve": sorted({m.upper() for m in re.findall(r"cve-\d{4}-\d{4,7}", t, re.I)}),
        "ipv4": sorted(ips),
        "hash": sorted({m.lower() for m in re.findall(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", t, re.I)}),
        "uac_groups": sorted({m.upper() for m in re.findall(r"\buac-\d{4}\b", t, re.I)}),
        "cert_refs": sorted(set(re.findall(r"CERT-UA#\d+", t, re.I))),
        "attack_ttp": sorted(set(re.findall(r"\bT[01]\d{3}(?:\.\d{3})?\b", t))),
    }


# Метод Сааті
# Шкала Сааті: 1 — рівна важливість, 3 — помірна перевага, 5 — суттєва,
# 7 — значна, 9 — дуже сильна (2,4,6,8 — проміжні). Зворотне порівняння = 1/a.
# Випадковий індекс узгодженості RI (Saaty) для n = 1..15
RI = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41,
      9: 1.45, 10: 1.49, 11: 1.51, 12: 1.48, 13: 1.56, 14: 1.57, 15: 1.59}

# Критерії скорингу релевантності публікації
CRITERIA = ["ioc", "attacks", "threats", "actors", "impacts",
            "infra", "info_ops", "actions", "tech", "noise"]

CRITERIA_LABELS = {
    "ioc": "Технічні індикатори (CVE, IP, хеші, UAC-групи)",
    "attacks": "Типи атак (фішинг, DDoS, ransomware, 0-day ...)",
    "threats": "Кіберзагрози (malware, експлойт, вразливість ...)",
    "actors": "Суб'єкти загрози (APT, UAC-xxxx, Sandworm ...)",
    "impacts": "Наслідки (витік, знеструмлення, збій ...)",
    "infra": "Об'єкти критичної інфраструктури (сектори)",
    "info_ops": "Інформаційні операції",
    "actions": "Дії зловмисника (проникнення, ексфільтрація ...)",
    "tech": "Технологічний контекст (SCADA, VPN, Cisco ...)",
    "noise": "Нерелевантна тематика (шум)",
}

INVERTED_CRITERIA = {"noise"}
SCORE_VERSION = "saaty"
_UPPER = {
    "ioc":      {"attacks": 1,   "threats": 3,   "actors": 3,   "impacts": 3,   "infra": 3,
                 "info_ops": 5,  "actions": 5,   "tech": 7,     "noise": 1},
    "attacks":  {"threats": 1,   "actors": 3,    "impacts": 3,  "infra": 3,
                 "info_ops": 5,  "actions": 3,   "tech": 5,     "noise": 1},
    "threats":  {"actors": 1,    "impacts": 1,   "infra": 3,    "info_ops": 3,
                 "actions": 3,   "tech": 5,      "noise": 1 / 3},
    "actors":   {"impacts": 1,   "infra": 1,     "info_ops": 3, "actions": 3,
                 "tech": 5,      "noise": 1 / 3},
    "impacts":  {"infra": 1,     "info_ops": 3,  "actions": 1,  "tech": 3,    "noise": 1 / 3},
    "infra":    {"info_ops": 3,  "actions": 1,   "tech": 3,     "noise": 1 / 3},
    "info_ops": {"actions": 1,   "tech": 1,      "noise": 1 / 5},
    "actions":  {"tech": 3,      "noise": 1 / 3},
    "tech":     {"noise": 1 / 5},
}


def build_matrix(names, upper):
    n = len(names)
    idx = {k: i for i, k in enumerate(names)}
    A = [[1.0] * n for _ in range(n)]
    for a, row in upper.items():
        for b, v in row.items():
            i, j = idx[a], idx[b]
            A[i][j] = float(v)
            A[j][i] = 1.0 / float(v)
    missing = [(names[i], names[j]) for i in range(n) for j in range(i + 1, n)
               if names[i] not in upper or names[j] not in upper.get(names[i], {})]
    if missing:
        raise ValueError(f"Не задано порівняння: {missing}")
    return A


def weights_row_sum(A):
    sums = [sum(r) for r in A]
    total = sum(sums)
    return [s / total for s in sums]


def weights_geomean(A):
    n = len(A)
    g = [prod(r) ** (1.0 / n) for r in A]
    total = sum(g)
    return [x / total for x in g]


def consistency(A, w=None):
    n = len(A)
    w = w or weights_geomean(A)
    lam = sum(sum(A[i][j] * w[j] for j in range(n)) / w[i] for i in range(n)) / n
    ci = (lam - n) / (n - 1) if n > 1 else 0.0
    ri = RI.get(n, 1.59)
    cr = ci / ri if ri else 0.0
    return lam, ci, cr


def compute_weights(method="row_sum", names=None, upper=None, check=True):
    names, upper = names or CRITERIA, upper or _UPPER
    A = build_matrix(names, upper)
    w = weights_row_sum(A) if method == "row_sum" else weights_geomean(A)
    if check:
        _, _, cr = consistency(A)
        if cr > 0.10:
            raise ValueError(f"Судження неузгоджені: CR={cr:.3f} > 0.10 — перегляньте матрицю")
    return dict(zip(names, w))

RELEVANCE_WEIGHTS = compute_weights("row_sum")


def saaty_report():
    names = CRITERIA
    A = build_matrix(names, _UPPER)
    w1, w2 = weights_row_sum(A), weights_geomean(A)
    lam, ci, cr = consistency(A)
    fmt = lambda v: f"{v:5.2f}"
    print("Матриця попарних порівнянь:")
    print(f"{'':10s}" + "".join(f"{k[:7]:>8s}" for k in names) + f"{'Σ рядка':>9s}{'w(Σ)':>7s}{'w(geo)':>8s}")
    for i, k in enumerate(names):
        print(f"{k:10s}" + "".join(f"{A[i][j]:8.2f}" for j in range(len(names)))
              + f"{sum(A[i]):9.2f}{w1[i]:7.3f}{w2[i]:8.3f}")
    print(f"{'Всього':10s}" + " " * 8 * len(names) + f"{sum(sum(r) for r in A):9.2f}{sum(w1):7.3f}{sum(w2):8.3f}")
    print(f"\nλmax={lam:.3f}  CI={ci:.3f}  CR={cr:.3f}  ->",
          "судження узгоджені (CR<=0.10)" if cr <= 0.10 else "НЕУЗГОДЖЕНІ, переглянути матрицю")
    print("\nКритерій -> вага:")
    for k, v in sorted(zip(names, w1), key=lambda t: -t[1]):
        mark = "(1-x)" if k in INVERTED_CRITERIA else "  x  "
        print(f"  {mark} {k:9s} {v:.3f}  {CRITERIA_LABELS[k]}")


class Analyzer:
    CAP = 1
    IOC_CAP = 1
    WEIGHTS = RELEVANCE_WEIGHTS

    def __init__(self):
        c = lambda lst: [(t, compile_term(t)) for t in lst]
        self.cats = {
            "threats": c(CYBER_THREATS), "attacks": c(ATTACK_TYPES),
            "actions": c(ATTACK_ACTIONS), "actors": c(THREAT_ACTORS),
            "tech": c(TECHNOLOGY), "impacts": c(IMPACTS), "info_ops": c(INFO_OPS),
        }
        self.leak = c(LEAK_TERMS)
        self.physical = c(PHYSICAL_TERMS)
        self.noise = c(KINETIC_NOISE)
        self.sectors = {k: c(v) for k, v in SECTORS.items()}
        self.infra_generic = c(CRITICAL_INFRA_GENERIC)

    @staticmethod
    def _hits(text, comp):
        return [t for t, rx in comp if rx.search(text)]

    def analyze(self, text):
        low = DASH_RE.sub("-", APOS_RE.sub("'", text.lower()))
        h = {name: self._hits(low, comp) for name, comp in self.cats.items()}
        leak = self._hits(low, self.leak)
        physical = self._hits(low, self.physical)
        noise = self._hits(low, self.noise)
        sectors = {k: hs for k, comp in self.sectors.items() if (hs := self._hits(low, comp))}
        infra_generic = self._hits(low, self.infra_generic)
        iocs = extract_iocs(text)
        n_ioc = sum(len(v) for k, v in iocs.items() if k in ("cve", "ipv4", "hash"))

        core = bool(h["threats"] or h["attacks"] or h["actors"] or n_ioc or iocs["uac_groups"])
        ipso = bool(h["info_ops"] and (core or h["tech"] or (sectors and h["impacts"])))
        gate = core or ipso or bool(leak)

        # Скоринг S = 100 · Σ w_i · x_i, де w_i — ваги за Сааті (Σ w_i = 1), x_i ∈ [0, 1];
        # для шуму x = 1 − (частка шумових збігів). Отже S ∈ [0, 100].
        n_infra = sum(len(v) for v in sectors.values()) + len(infra_generic)
        x = {n: min(len(h[n]), self.CAP) / self.CAP for n in self.cats}
        x["infra"] = min(n_infra, self.CAP) / self.CAP
        x["ioc"] = min(n_ioc + len(iocs["uac_groups"]), self.IOC_CAP) / self.IOC_CAP
        x["noise"] = min(len(noise), self.CAP) / self.CAP
        breakdown = {k: round(100 * self.WEIGHTS[k] * ((1 - x[k]) if k in INVERTED_CRITERIA else x[k]), 2)
                     for k in CRITERIA}
        score = round(sum(breakdown.values()), 1)

        event_hints = []
        if h["attacks"] or h["actions"] or h["threats"]:
            event_hints.append("cyber_incident")
        if leak:
            event_hints.append("data_leak")
        if ipso or h["info_ops"]:
            event_hints.append("info_operation")
        if re.search(r"cve-\d|вразливіст|zero.?day|0-?day", low):
            event_hints.append("vulnerability")
        if re.search(r"ddos", low):
            event_hints.append("ddos")

        if n_ioc or iocs["uac_groups"]:
            detail = 3
        elif iocs["attack_ttp"] or len(h["tech"]) >= 2 or (h["attacks"] and h["tech"]):
            detail = 2
        elif core:
            detail = 1
        else:
            detail = 0
        sens_flags = {
            "iocs": bool(n_ioc), "credentials": bool(CREDENTIAL_RE.search(text)),
            "personal_data": bool(PERSONAL_RE.search(text)), "topology": bool(TOPOLOGY_RE.search(text)),
            "dump": bool(DUMP_RE.search(text)),
        }
        prefeatures = {
            "sectors": sorted(sectors), "event_type_hints": event_hints,
            "technical_detail_hint": detail,
            "sensitivity_flags": sens_flags,
            "sensitivity_hint": min(sum(sens_flags.values()), 3),
            "physical_effect_hint": bool(physical), "physical_terms": physical,
        }
        return {
            "score": score, "breakdown": breakdown, "gate": gate, "iocs": iocs, "sectors": sorted(sectors),
            "indicators": {**h, "leak": leak, "infra": {**sectors}, "noise": noise, "gate": gate},
            "prefeatures": prefeatures,
        }


class Store:
    def __init__(self, path=DB_PATH):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS docs(
                id TEXT PRIMARY KEY, source_category TEXT, source_name TEXT, url TEXT,
                published_at TEXT, collected_at TEXT, title TEXT, text TEXT, text_hash TEXT,
                lang TEXT, trusted INTEGER, score REAL, is_candidate INTEGER,
                event_id TEXT, meta TEXT);
            CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
            CREATE INDEX IF NOT EXISTS ix_pub ON docs(published_at);
            CREATE INDEX IF NOT EXISTS ix_event ON docs(event_id);
        """)

    def seen(self, doc_id):
        return self.db.execute("SELECT 1 FROM docs WHERE id=?", (doc_id,)).fetchone() is not None

    def upsert(self, r):
        cols = ["id", "source_category", "source_name", "url", "published_at", "collected_at", "title",
                "text", "text_hash", "lang", "trusted", "score", "is_candidate", "event_id", "meta"]
        self.db.execute(f"INSERT OR REPLACE INTO docs({','.join(cols)}) VALUES({','.join(':' + c for c in cols)})", r)
        self.db.commit()

    def threshold(self):
        row = self.db.execute("SELECT value FROM kv WHERE key='threshold'").fetchone()
        ver = self.db.execute("SELECT value FROM kv WHERE key='threshold_version'").fetchone()
        if not row or not ver or ver["value"] != SCORE_VERSION:
            return None
        return float(row["value"])

    def set_threshold(self, v):
        self.db.execute("INSERT OR REPLACE INTO kv VALUES('threshold',?)", (str(v),))
        self.db.execute("INSERT OR REPLACE INTO kv VALUES('threshold_version',?)", (SCORE_VERSION,))
        self.db.commit()

    def stats(self):
        q = lambda s: self.db.execute(s).fetchone()[0]
        return {"total": q("SELECT COUNT(*) FROM docs"),
                "candidates": q("SELECT COUNT(*) FROM docs WHERE is_candidate=1")}


class Collector:
    def __init__(self, store, analyzer, full=False):
        self.store, self.analyzer, self.full = store, analyzer, full
        self.session = make_session()

    def fetch(self, url, **kw):
        try:
            r = self.session.get(url, timeout=50, **kw)
        except requests.RequestException as e:
            log.error("Запит не вдався %s: %s", url, e)
            return None
        time.sleep(SLEEP)
        return r

    def ingest(self, category, source, url, published, title, text, trusted=False,
               extra=None, raw=None, raw_ext="html"):
        title, text = normalize(title), normalize(text)
        if len(text) < 30:
            return False
        doc_id = url_id(url)
        a = self.analyzer.analyze(f"{title}\n\n{text}")
        thr = self.store.threshold()  # None до першого calibrate: відбір лише за gate
        cand = bool(trusted or (a["gate"] and (thr is None or a["score"] >= thr)))
        meta = {"indicators": a["indicators"], "score_breakdown": a["breakdown"],
                "iocs": a["iocs"], "sectors": a["sectors"],
                "prefeatures": a["prefeatures"], "raw_path": save_raw(category, doc_id, raw, raw_ext),
                **(extra or {})}
        self.store.upsert({
            "id": doc_id, "source_category": category, "source_name": source, "url": url,
            "published_at": published, "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "title": title, "text": text, "text_hash": fingerprint(text), "lang": detect_lang(text),
            "trusted": int(trusted), "score": a["score"], "is_candidate": int(cand),
            "event_id": None, "meta": json.dumps(meta, ensure_ascii=False)})
        return cand


class CertUA(Collector):
    LIST = "https://cert.gov.ua/api/articles/all?page={page}&lang=uk"
    DETAIL = "https://cert.gov.ua/api/articles/byId?id={id}&lang=uk"
    PAGE = "https://cert.gov.ua/article/{id}"
    HDR = {"Accept": "application/xml, text/xml, */*"}

    def collect(self):
        log.info("CERT-UA: старт (full=%s)", self.full)
        added = 0
        for page in range(20):
            r = self.fetch(self.LIST.format(page=page), headers=self.HDR)
            if r is None or r.status_code != 200:
                log.warning("CERT-UA список: недоступно (стор. %s)", page)
                break
            try:
                root = ET.fromstring(r.content)
            except ET.ParseError as e:
                log.error("CERT-UA XML стор. %s: %s", page, e)
                continue
            items = root.findall("./items/items")
            if not items:
                break
            if page == 0:
                log.info("CERT-UA: статей в архіві: %s", root.findtext("count"))
            n_old = n_seen = 0
            for item in items:
                aid = (item.findtext("id") or "").strip()
                if not aid:
                    continue
                pub = to_utc_iso(item.findtext("date"), dayfirst=True)
                if pub and pub < SINCE_ISO:
                    n_old += 1
                    continue
                front = self.PAGE.format(id=aid)
                if not self.full and self.store.seen(url_id(front)):
                    n_seen += 1
                    continue
                title = (item.findtext("title") or "").strip()
                text = BeautifulSoup(item.findtext("description") or "", "html.parser").get_text("\n", strip=True)
                raw = None
                d = self.fetch(self.DETAIL.format(id=aid), headers=self.HDR)


                if d is not None and d.status_code == 200:
                    try:
                        body = ""
                        content_type = d.headers.get("Content-Type", "").lower()


                        if "application/json" in content_type or d.text.strip().startswith("{"):
                            d_json = d.json()
                            if "data" in d_json and isinstance(d_json["data"], dict):
                                body = d_json["data"].get("body") or d_json["data"].get("content") or ""
                            else:
                                body = d_json.get("body") or d_json.get("content") or d_json.get("text") or ""


                        else:
                            droot = ET.fromstring(d.content)
                            body = droot.findtext(".//body") or droot.findtext(".//content") or droot.findtext(
                                ".//text") or ""

                        if body:
                            text = BeautifulSoup(body, "html.parser").get_text("\n", strip=True)
                        raw = d.content
                    except Exception as e:
                        log.warning("CERT-UA деталь %s: помилка розбору %s (беремо description)", aid, e)
                else:
                    log.warning("CERT-UA деталь %s недоступна", aid)

                tags = [t.findtext("name") for t in item.findall("./tags/tags") if t.findtext("name")]
                self.ingest("Gov_CERT", "CERT-UA", front, pub, title, f"{title}\n\n{text}",
                            trusted=True, extra={"cert_tags": tags}, raw=raw, raw_ext="xml")
                added += 1
            log.info("CERT-UA стор. %s: нових %s, старих %s, вже було %s", page,
                     len(items) - n_old - n_seen, n_old, n_seen)
            if n_old == len(items):
                break
            if not self.full and n_seen == len(items):
                break
        log.info("CERT-UA: додано %s", added)


class TelegramGov(Collector):
    CHANNELS = {"Держспецзв'язку": "dsszzi_official", "СБУ": "SBUkr", "Кіберполіція": "CyberpolUA"}
    DAYS_BACK = 500

    def collect(self):
        for name, channel in self.CHANNELS.items():
            self.collect_channel(name, channel)

    def collect_channel(self, name, channel):
        since_dt = datetime.now(timezone.utc) - timedelta(days=self.DAYS_BACK)
        since_iso = since_dt.isoformat(timespec="seconds")
        log.info("Telegram: %s (@%s) — ліміт збору від %s", name, channel, since_iso[:10])

        url, visited, added = f"https://t.me/s/{channel}", set(), 0
        for page in range(MAX_PAGES):
            r = self.fetch(url)
            if r is None or r.status_code != 200:
                log.warning("Telegram %s: статус %s", channel, getattr(r, "status_code", None))
                break
            soup = BeautifulSoup(r.text, "html.parser")
            msgs = soup.select("div.tgme_widget_message")
            if not msgs:
                break
            unseen = 0
            for msg in msgs:
                date_a = msg.select_one("a.tgme_widget_message_date")
                time_tag = date_a.select_one("time") if date_a else None
                pub = to_utc_iso(time_tag.get("datetime")) if time_tag else None

                if pub and pub < since_iso:
                    continue
                text_div = msg.select_one("div.tgme_widget_message_text")
                if not text_div:
                    continue
                post_url = date_a["href"] if date_a and date_a.get("href") else f"https://t.me/{channel}"
                if not self.full and self.store.seen(url_id(post_url)):
                    continue
                unseen += 1
                text = text_div.get_text("\n", strip=True)
                title = normalize(text).split("\n")[0][:120]
                if self.ingest("Gov_Security", name, post_url, pub, title, text, raw=str(msg)):
                    added += 1
            first = msgs[0].get("data-post", "")
            first_date = msgs[0].select_one("a.tgme_widget_message_date time")
            oldest_pub = to_utc_iso(first_date.get("datetime")) if first_date else None
            if "/" not in first:
                break
            oldest_id = first.split("/")[-1]
            if oldest_id in visited or oldest_id == "1":
                break
            visited.add(oldest_id)

            if oldest_pub and oldest_pub < since_iso:
                log.info("Telegram %s: досягнуто межу  (%s). Зупинка пагінації.", channel, oldest_pub[:10])
                break
            if not self.full and unseen == 0:
                break
            if page % 5 == 0:
                log.info("Telegram %s: стор. %s, найстаріший пост %s", channel, page + 1, oldest_pub)
            url = f"https://t.me/s/{channel}?before={oldest_id}"
        log.info("Telegram %s: кандидатів додано %s", channel, added)


def cmd_calibrate(store):
    rows = store.db.execute("SELECT score FROM docs WHERE trusted=1").fetchall()
    scores = sorted(r["score"] for r in rows)
    if len(scores) < CALIB_MIN_DOCS:
        log.warning("Замало довірених документів (%s) для калібрування", len(scores))
        return
    thr = scores[int(CALIB_PERCENTILE * (len(scores) - 1))]
    store.set_threshold(thr)
    untrusted = store.db.execute("SELECT score FROM docs WHERE trusted=0").fetchall()
    share = sum(r["score"] >= thr for r in untrusted) / max(len(untrusted), 1)
    log.info("Поріг=%s (p%d довірених, медіана=%s). Частка решти документів вище порога: %.1f%%",
             thr, int(CALIB_PERCENTILE * 100), scores[len(scores) // 2], share * 100)
    cmd_rescore(store)


def cmd_weights():
    saaty_report()


def cmd_rescore(store):
    an, thr = Analyzer(), store.threshold()
    if thr is None:
        log.warning("Поріг не відкалібровано (запустіть calibrate): відбір лише за gate")
    rows = store.db.execute("SELECT id, title, text, trusted, meta FROM docs").fetchall()
    for r in rows:
        a = an.analyze(f"{r['title']}\n\n{r['text']}")
        meta = json.loads(r["meta"] or "{}")
        meta.update({"indicators": a["indicators"], "score_breakdown": a["breakdown"],
                     "iocs": a["iocs"], "sectors": a["sectors"], "prefeatures": a["prefeatures"]})
        cand = int(bool(r["trusted"] or (a["gate"] and (thr is None or a["score"] >= thr))))
        store.db.execute("UPDATE docs SET score=?, is_candidate=?, meta=? WHERE id=?",
                         (a["score"], cand, json.dumps(meta, ensure_ascii=False), r["id"]))
    store.db.commit()
    log.info("Перераховано %s документів, поріг=%s. %s", len(rows), thr, store.stats())


# дедуплікація між джерелами
def cmd_cluster(store, threshold=0.5, window_days=7):
    from sklearn.feature_extraction.text import TfidfVectorizer
    rows = store.db.execute(
        "SELECT id, title, text, text_hash, published_at FROM docs WHERE is_candidate=1").fetchall()
    n = len(rows)
    if n == 0:
        log.warning("Немає кандидатів для кластеризації")
        return
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    def ts(i):
        p = rows[i]["published_at"]
        return datetime.fromisoformat(p) if p else None

    times = [ts(i) for i in range(n)]
    win = timedelta(days=window_days)

    by_hash = {}
    for i, r in enumerate(rows):
        if r["text_hash"] in by_hash:
            union(by_hash[r["text_hash"]], i)
        else:
            by_hash[r["text_hash"]] = i

    docs = [f"{r['title']}\n{URL_RE.sub(' ', r['text'])[:4000]}" for r in rows]
    X = TfidfVectorizer(sublinear_tf=True, ngram_range=(1, 2), max_df=0.8).fit_transform(docs)
    B = 500
    for s in range(0, n, B):
        sim = (X[s:s + B] @ X.T).tocoo()
        for a, b, v in zip(sim.row, sim.col, sim.data):
            a += s
            if a >= b or v < threshold:
                continue
            if times[a] and times[b] and abs(times[a] - times[b]) > win:
                continue
            union(a, b)

    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    for members in groups.values():
        first = min(members, key=lambda i: rows[i]["published_at"] or "9999")
        ev = "EV-" + hashlib.md5(rows[first]["id"].encode()).hexdigest()[:10]
        for i in members:
            store.db.execute("UPDATE docs SET event_id=? WHERE id=?", (ev, rows[i]["id"]))
    store.db.commit()
    log.info("Кластеризація: %s публікацій -> %s подій (поріг схожості %.2f, вікно ±%s дн.)",
             n, len(groups), threshold, window_days)


def cmd_export(store, docs_path="docs.jsonl", events_path="events.jsonl"):
    rows = store.db.execute("SELECT * FROM docs WHERE is_candidate=1 ORDER BY published_at").fetchall()
    events = {}
    with open(docs_path, "w", encoding="utf-8") as f:
        for r in rows:
            d = dict(r)
            d["meta"] = json.loads(d["meta"] or "{}")
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
            e = events.setdefault(d["event_id"] or f"SINGLE-{d['id']}", [])
            e.append(d)
    with open(events_path, "w", encoding="utf-8") as f:
        for ev, ds in events.items():
            ds.sort(key=lambda x: x["published_at"] or "")
            rep = max(ds, key=lambda x: len(x["text"]))
            union = lambda key: sorted({v for x in ds for v in x["meta"]["iocs"].get(key, [])})
            pre = [x["meta"]["prefeatures"] for x in ds]
            f.write(json.dumps({
                "event_id": ev,
                "first_published": ds[0]["published_at"], "last_published": ds[-1]["published_at"],
                "n_publications": len(ds), "sources": sorted({x["source_name"] for x in ds}),
                "n_sources": len({x["source_name"] for x in ds}),
                "urls": [x["url"] for x in ds],
                "iocs": {k: union(k) for k in ("cve", "ipv4", "hash", "uac_groups", "cert_refs", "attack_ttp")},
                "sectors_hint": sorted({s for p in pre for s in p["sectors"]}),
                "event_type_hints": sorted({t for p in pre for t in p["event_type_hints"]}),
                "technical_detail_hint": max(p["technical_detail_hint"] for p in pre),
                "sensitivity_hint": max(p["sensitivity_hint"] for p in pre),
                "physical_effect_hint": any(p["physical_effect_hint"] for p in pre),
                "title": rep["title"], "text": rep["text"],
            }, ensure_ascii=False) + "\n")
    log.info("Експорт: %s публікацій -> %s, %s подій -> %s", len(rows), docs_path, len(events), events_path)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--full", action="store_true", help="ігнорувати seen і збирати все заново")
    c.add_argument("--sources", nargs="+", default=["cert", "telegram"],
                   choices=["cert", "telegram"])
    sub.add_parser("calibrate")
    sub.add_parser("rescore")
    cl = sub.add_parser("cluster")
    cl.add_argument("--threshold", type=float, default=0.5)
    cl.add_argument("--window", type=int, default=7)
    sub.add_parser("export")
    sub.add_parser("weights")
    args = ap.parse_args()

    if args.cmd == "weights":
        return cmd_weights()
    store = Store()
    if args.cmd == "collect":
        an = Analyzer()
        classes = {"cert": CertUA, "telegram": TelegramGov}
        for s in args.sources:
            classes[s](store, an, full=args.full).collect()
        log.info("Підсумок: %s", store.stats())
    elif args.cmd == "calibrate":
        cmd_calibrate(store)
    elif args.cmd == "rescore":
        cmd_rescore(store)
    elif args.cmd == "cluster":
        cmd_cluster(store, args.threshold, args.window)
    elif args.cmd == "export":
        cmd_export(store)


if __name__ == "__main__":
    main()