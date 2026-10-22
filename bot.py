import hashlib
import logging
import os
import re
import sqlite3
import time
import unicodedata
from collections import defaultdict, deque
from contextlib import contextmanager

from telegram import Update
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)


BOT_TOKEN = os.environ["BOT_TOKEN"].strip()
VERSION = "1.8"
TARGET_CHAT_NAMES = tuple(dict.fromkeys(
    item.strip().lstrip("@").lower()
    for item in os.getenv("TARGET_CHAT_USERNAMES", os.getenv("TARGET_CHAT_USERNAME", "kitaichip")).split(",")
    if item.strip()
))
LEGACY_CHAT_ID = -1002351271722  # Verified ID of the original @kitaichip group.
TEST_TEXT = "Проверка антиспама 12345"
WARN_LIMIT = int(os.getenv("WARN_LIMIT", "3"))
FLOOD_COUNT = int(os.getenv("FLOOD_COUNT", "6"))
FLOOD_WINDOW = int(os.getenv("FLOOD_WINDOW", "10"))
DUPLICATE_WINDOW = int(os.getenv("DUPLICATE_WINDOW", "60"))
NEW_MEMBER_HOURS = int(os.getenv("NEW_MEMBER_HOURS", "24"))
BLOCK_TELEGRAM_LINKS = os.getenv("BLOCK_TELEGRAM_LINKS", "true").lower() == "true"
BLOCK_ALL_LINKS = os.getenv("BLOCK_ALL_LINKS", "false").lower() == "true"
ALLOWED_TG_USERNAMES = {
    item.strip().replace("@", "").lower()
    for item in os.getenv("ALLOWED_TG_USERNAMES", "kitaichip,GodchipBOT").split(",")
    if item.strip()
}
ALLOWED_TG_USERNAMES.update(TARGET_CHAT_NAMES)
DB_PATH = os.getenv("DB_PATH", "/app/data/antispam.db")

if not BOT_TOKEN or BOT_TOKEN == "ВСТАВЬТЕ_СЮДА_НОВЫЙ_ТОКЕН":
    raise RuntimeError("Откройте .env и укажите новый BOT_TOKEN")

class SafeFormatter(logging.Formatter):
    def format(self, record):
        text = super().format(record).replace(BOT_TOKEN, "[TOKEN]")
        return re.sub(r"\d{6,}:[A-Za-z0-9_-]{20,}", "[TOKEN]", text)


handler = logging.StreamHandler()
handler.setFormatter(SafeFormatter("%(asctime)s | %(levelname)s | %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("antispam")

SPAM_PHRASES = [
    "заработок без вложений", "легкий заработок", "лёгкий заработок",
    "дополнительный доход", "пассивный доход", "удаленная работа",
    "удалённая работа", "работа из дома", "ищем сотрудников",
    "требуются сотрудники", "подработка", "быстрый заработок",
    "гарантированный доход", "высокий доход", "инвестиционный проект",
    "инвестиции", "арбитраж криптовалют", "арбитраж", "крипта",
    "криптовалюта", "usdt", "casino", "казино", "ставки на спорт",
    "букмекер", "пиши в лс", "пишите в лс", "пишите в личку",
    "напиши мне в лс", "за подробностями в лс", "доход в день",
    "доход в неделю",
]

STRONG_SPAM_PATTERNS = [
    r"заработ\w*.{0,30}\d+\s*(?:₽|руб|рублей|\$|€)",
    r"\d+\s*(?:₽|руб|рублей|\$|€).{0,30}(?:день|сутки|час)",
    r"(?:ищу|набираю|требуются?).{0,25}(?:людей|сотрудников|менеджеров)",
    r"(?:выплат|доход).{0,20}(?:ежеднев|каждый день)",
]
STRONG_SPAM_RE = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in STRONG_SPAM_PATTERNS]
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>()]+", re.IGNORECASE)
TG_LINK_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_+/-]+)", re.IGNORECASE)

flood_cache = defaultdict(deque)
admin_cache = {}  # chat_id -> (updated_at, set(user_ids))
target_chats = {}  # Only resolved, explicitly configured groups.
target_notes = {}
test_sessions = {}  # (chat_id, user_id) -> expiry, only for TEST_TEXT.
recent_events = {}  # chat_id -> bounded deque; message contents are not logged.


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    with db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS meta_v2 (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("""CREATE TABLE IF NOT EXISTS warnings_v2 (
            chat_id INTEGER, user_id INTEGER, count INTEGER NOT NULL DEFAULT 0,
            last_reason TEXT, updated_at INTEGER, PRIMARY KEY(chat_id, user_id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS joins_v2 (
            chat_id INTEGER, user_id INTEGER, joined_at INTEGER,
            PRIMARY KEY(chat_id, user_id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS duplicates_v2 (
            chat_id INTEGER, user_id INTEGER, digest TEXT, message_id INTEGER,
            seen_at REAL, PRIMARY KEY(chat_id, user_id, digest))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS warned_messages_v2 (
            chat_id INTEGER, message_id INTEGER, PRIMARY KEY(chat_id, message_id))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS cross_user_promos_v15 (
            chat_id INTEGER, user_id INTEGER, digest TEXT, message_id INTEGER, seen_at REAL,
            PRIMARY KEY(chat_id,user_id,digest))""")
        # Existing counts belong only to the original group. Copy them once.
        if not conn.execute("SELECT 1 FROM meta_v2 WHERE key='legacy_migrated'").fetchone():
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "warnings" in tables:
                conn.execute("""INSERT OR IGNORE INTO warnings_v2
                    SELECT ?,user_id,count,last_reason,updated_at FROM warnings""", (LEGACY_CHAT_ID,))
            if "joins" in tables:
                conn.execute("""INSERT OR IGNORE INTO joins_v2
                    SELECT ?,user_id,joined_at FROM joins""", (LEGACY_CHAT_ID,))
            conn.execute("INSERT INTO meta_v2 VALUES ('legacy_migrated','1')")


def add_warning(chat_id, user_id, message_id, reason):
    now = int(time.time())
    with db() as conn:
        new = conn.execute("INSERT OR IGNORE INTO warned_messages_v2 VALUES (?,?)", (chat_id, message_id))
        if not new.rowcount:
            return None
        conn.execute(
            """INSERT INTO warnings_v2 (chat_id, user_id, count, last_reason, updated_at)
               VALUES (?, ?, 1, ?, ?)
               ON CONFLICT(chat_id, user_id) DO UPDATE SET
                   count = count + 1,
                   last_reason = excluded.last_reason,
                   updated_at = excluded.updated_at""",
            (chat_id, user_id, reason, now),
        )
        row = conn.execute("SELECT count FROM warnings_v2 WHERE chat_id=? AND user_id=?", (chat_id,user_id)).fetchone()
    return row[0]


def save_join(chat_id, user_id):
    with db() as conn:
        conn.execute(
            """INSERT INTO joins_v2 (chat_id, user_id, joined_at) VALUES (?, ?, ?)
               ON CONFLICT(chat_id, user_id) DO UPDATE SET joined_at = excluded.joined_at""",
            (chat_id, user_id, int(time.time())),
        )


def is_new_member(chat_id, user_id):
    with db() as conn:
        row = conn.execute("SELECT joined_at FROM joins_v2 WHERE chat_id=? AND user_id=?", (chat_id,user_id)).fetchone()
    return bool(row and time.time() - row[0] < NEW_MEMBER_HOURS * 3600)


def correct_chat(update: Update):
    chat = update.effective_chat
    return bool(chat and chat.type in ("group", "supergroup") and chat.id in target_chats)


def trace(update, decision):
    message = update.effective_message
    chat = update.effective_chat
    if not message or not chat:
        return
    sender = message.sender_chat
    user = message.from_user
    line = f"msg={message.message_id} user={user.id if user else '-'} sender_chat={sender.id if sender else '-'} {decision}"
    log.info("chat=%s %s", chat.id, line)
    # Retain group diagnostics only; bounded even if the bot is added elsewhere.
    if chat.id in target_chats:
        recent_events.setdefault(chat.id, deque(maxlen=8)).append(line)


async def resolve_targets(bot):
    resolved = {}
    notes = {}
    for name in TARGET_CHAT_NAMES:
        try:
            chat = await bot.get_chat("@" + name)
            if chat.type == "channel":
                if not chat.linked_chat_id:
                    notes[name] = "канал без доступной привязанной группы обсуждений"
                    continue
                chat = await bot.get_chat(chat.linked_chat_id)
            if chat.type not in ("group", "supergroup"):
                notes[name] = "адрес не ведёт на группу"
                continue
            resolved[chat.id] = chat.title or "@" + name
            notes[name] = f"{chat.title} (ID {chat.id})"
            try:
                member = await bot.get_chat_member(chat.id, bot.id)
                notes[name] += f"; бот: {member.status}"
                if not getattr(member, "can_delete_messages", False):
                    notes[name] += "; НЕТ ПРАВА УДАЛЕНИЯ"
                if not getattr(member, "can_restrict_members", False):
                    notes[name] += "; НЕТ ПРАВА БЛОКИРОВКИ"
            except TelegramError as exc:
                notes[name] += f"; проверка прав: {type(exc).__name__}"
        except TelegramError as exc:
            notes[name] = f"не удалось определить группу: {type(exc).__name__}"
    target_chats.clear()
    target_chats.update(resolved)
    target_notes.clear()
    target_notes.update(notes)
    for name, note in notes.items():
        log.info("TARGET @%s: %s", name, note)


async def on_start(app):
    await resolve_targets(app.bot)
    log.info("AntiSpam v%s ready; active group IDs=%s", VERSION, sorted(target_chats))
    if not target_chats:
        log.error("Нет доступных целевых групп. Проверьте адреса и добавление бота; затем перезапустите контейнер.")


async def get_admins(context, chat_id):
    now = time.time()
    cached = admin_cache.get(chat_id)
    if cached is None or now - cached[0] > 60:
        try:
            admins = await context.bot.get_chat_administrators(chat_id)
            cached = (now, {admin.user.id for admin in admins})
            admin_cache[chat_id] = cached
        except TelegramError as exc:
            log.error("Ошибка получения администраторов: %s", exc)
            return None
    return cached[1]


async def protected_user(update, context):
    user = update.effective_user
    if not user or user.is_bot:
        return True
    admins = await get_admins(context, update.effective_chat.id)
    if admins is None:
        return None
    if user.id not in admins:
        return False
    # A recently demoted admin should not remain exempt because of the cache.
    try:
        member = await context.bot.get_chat_member(update.effective_chat.id, user.id)
        return member.status in ("administrator", "creator")
    except TelegramError:
        return None


async def command_admin(update, context):
    if not correct_chat(update):
        return False
    msg = update.effective_message
    if msg.sender_chat:
        return msg.sender_chat.id == msg.chat_id  # Verified anonymous group admin.
    if not msg.from_user or msg.from_user.is_bot:
        return False
    try:
        member = await context.bot.get_chat_member(msg.chat_id, msg.from_user.id)
        return member.status in ("administrator", "creator")
    except TelegramError:
        return False


def normalize_text(text):
    text = unicodedata.normalize("NFKC", text).casefold()
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return re.sub(r"\s+", " ", text.strip())


def telegram_link_blocked(text):
    for match in TG_LINK_RE.finditer(text):
        username = match.group(1).split("/")[0].replace("+", "").lower()
        if username not in ALLOWED_TG_USERNAMES:
            return True
    return False


def has_normal_link(text):
    return bool(URL_RE.search(text))


def message_link_text(message):
    # Hidden links carry their destination separately from the displayed text.
    text = message.text or message.caption or ""
    entities = tuple(message.entities or ()) + tuple(message.caption_entities or ())
    urls = [entity.url for entity in entities if entity.type == "text_link" and entity.url]
    return "\n".join([text, *urls])


def earnings_ad(text, has_link=False):
    normalized = normalize_text(text).replace("ё", "е")
    # Compact only for this multi-signal rule, never for duplicate detection.
    compact = re.sub(r"[^а-яa-z0-9]", "", normalized)
    income = any(word in compact for word in ("доход", "заработ", "подработ"))
    no_investment = any(word in compact for word in (
        "безвложений", "вложенияотсутствуют", "безпервоначальныхвложений",
        "вложенийнетребуется", "ненужновложений"))
    action = any(word in compact for word in (
        "оформитьзаявку", "оформизаявку", "оставитьзаявку", "оставьзаявку",
        "податьзаявку", "подайзаявку", "пишитевличку", "пишивличку",
        "пишитевлс", "пишивлс", "напишимне", "переходипоссылке",
        "переходитепоссылке"))
    payout = bool(re.search(
        r"\d[\d\s.,]*\s*(?:тыс\w*|тысяч\w*|т\.\s*р\.?|к|₽|руб\w*|\$|€)"
        r"\s*(?:руб\w*|₽)?\s*(?:в|за|каждый|каждые)?\s*(?:день|сутки|час|неделю)",
        normalized))
    # Income alone, a link alone, and an age marker alone are insufficient.
    return income and (sum((no_investment, action, payout)) >= 2 or (action and has_link))


def obvious_job_scam(text, link_text):
    """High-confidence unsolicited job/income pitch with an external contact link."""
    norm = normalize_text(text).replace("ё", "е")
    compact = re.sub(r"[^а-яa-z0-9]", "", norm)
    link = bool(TG_LINK_RE.search(link_text) or URL_RE.search(link_text))
    job = any(w in compact for w in ("работа", "подработка", "вакансия", "заработок"))
    # Common ad: 'ДОХОД ОТ 25 000₽ / РАБОТА ДЛЯ 18+ / РОССИЯ / t.me/...'
    money = bool(re.search(r"(?:доход|заработ|оплата|выплат).{0,24}\d[\d\s.,]{1,12}\s*(?:₽|руб|р\b|\$|€)", norm))
    age = bool(re.search(r"(?:18\s*\+|от\s*18|для\s*18|совершеннолет)", norm))
    recruitment = any(w in compact for w in ("ищемлюдей", "набор", "приглашаем", "пишивлс"))
    return link and job and money and (age or recruitment or "доход" in compact)


# Conservative multi-signal solicitation detection. A single mention of crypto,
# cash, USDT or an exchange must not trigger an instant ban in an auto group.
CRYPTO_ASSET_RE = re.compile(r"(?:крипт\w*|биткоин\w*|bitcoin|btc|usdt|юсдт|eth|эфир\w*|стейблкоин\w*)", re.I)
CASH_RE = re.compile(r"(?:наличн\w*|наличк\w*|обнал\w*|кэш|cash|фиат\w*)", re.I)
TRADE_OFFER_RE = re.compile(
    r"(?:меняю|обменяю|обмениваю|обмен\w*|куплю|продам|покупаю|продаю|"
    r"скупаю|выкуплю|обналич\w*|выдаю|принимаю)", re.I)
CONTACT_CTA_RE = re.compile(
    r"(?:пишит\w*|напишит\w*|напиши|пиши|обращайт\w*|"
    r"в\s*лс|в\s*личк\w*|в\s*личны\w*|в\s*директ|"
    r"обсудим|подробност\w*|свяжит\w*|стучит\w*)", re.I)
VOLUME_RE = re.compile(r"(?:больш\w*\s+объ\w*|крупн\w*\s+сумм\w*|любы\w*\s+объ\w*|оптом)", re.I)


def unsolicited_crypto_trade(text, link_text=""):
    """Only confident sales/solicitation, not ordinary automotive crypto discussion."""
    norm = normalize_text(text).replace("ё", "е")
    link = bool(TG_LINK_RE.search(link_text) or URL_RE.search(link_text))
    explicit_crypto_cash = bool(CRYPTO_ASSET_RE.search(norm) and CASH_RE.search(norm))
    offering_trade = bool(TRADE_OFFER_RE.search(norm))
    pitch = bool(CONTACT_CTA_RE.search(norm) or VOLUME_RE.search(norm) or link)
    return explicit_crypto_cash and offering_trade and pitch


# High-confidence promotional pitches, including broken-up Cyrillic and mixed scripts.
# Do not flag ordinary discussion of money, cryptocurrency or employment.
HOMOGLYPHS = str.maketrans({"a":"а", "e":"е", "o":"о", "p":"р", "c":"с", "x":"х", "y":"у", "k":"к", "m":"м", "t":"т", "b":"в", "h":"н"})
# Common Greek/Latin lookalikes used to hide Russian spam from keyword checks.
GREEK_HOMOGLYPHS = str.maketrans({
    "α":"а", "β":"в", "ε":"е", "κ":"к", "μ":"м", "ν":"н", "ο":"о",
    "ρ":"р", "σ":"с", "ς":"с", "τ":"т", "υ":"у", "χ":"х", "π":"п",
    "ι":"і", "ζ":"з", "η":"н",
})

PROMO_CONTACT_RE = re.compile(r"(?:пиш(?:и|ите|ут)|напиш(?:и|ите)|обращай(?:ся|тесь)|в\s*(?:лс|личк\w*|директ)|подробност\w*\s*(?:в|по)|(?:t\.me|telegram\.me)/|@\w{4,})", re.I)
MONEY_RE = re.compile(r"(?:\d[\d\s.,]{1,12}\s*(?:₽|руб\w*|р\.|usd|usdt|\$|€)|(?:доход|прибыл|заработ|выплат)\w*)", re.I)
JOB_OFFER_RE = re.compile(r"(?:работ\w*|подработ\w*|ваканси\w*|набор\w*|сотрудник\w*|оператор\w*|менеджер\w*)", re.I)
JOB_HOOK_RE = re.compile(r"(?:без\s*опыта|без\s*вложен|удален\w*|свободн\w*\s*график|от\s*18|18\s*\+|ежедневн\w*\s*выплат|набира\w*|ищем\s*людей)", re.I)
FINANCE_PITCH_RE = re.compile(r"(?:инвест\w*|арбитраж\w*|сигнал\w*|раскрутк\w*|удво\w*\s*(?:депозит|вклад)|гарантир\w*\s*(?:прибыл|доход)|торгов\w*\s*бот)", re.I)
BETTING_PITCH_RE = re.compile(r"(?:ставк\w*\s*на\s*спорт|букмекер\w*|казино|прогноз\w*\s*на\s*матч|договорн\w*\s*матч)", re.I)
SALES_PITCH_RE = re.compile(r"(?:продам|продаю|куплю|покупаю|меняю|обменяю|скупаю|выкуплю|обналич\w*|обмен\w*)", re.I)


def promotion_normalize(text):
    norm = normalize_text(text).replace("ё", "е")
    norm = norm.translate(GREEK_HOMOGLYPHS).translate(HOMOGLYPHS)
    # Disruptions like «к р и п т а», «д.о.х.о.д», interspersed invisible marks.
    norm = re.sub(r"(?<!\w)(?:[а-яa-z0-9][\s._*·-]+){2,}[а-яa-z0-9](?!\w)",
                  lambda m: re.sub(r"[^а-яa-z0-9]", "", m.group(0)), norm)
    return norm


def weekly_earnings_spam(text, link_text=""):
    """Instant-ban high-confidence weekly-pay bait, including Greek/Latin disguise.

    A money figure alone or a discussion of employment alone is never enough.
    """
    norm = promotion_normalize(text).replace("z", "з")
    compact = re.sub(r"[^а-яa-z0-9]", "", norm)
    has_link = bool(TG_LINK_RE.search(link_text) or URL_RE.search(link_text))
    employment = any(k in compact for k in (
        "простаязанятость", "легкаязанятость", "подработка", "заработок",
        "заработа", "доходот", "работадля", "вакансия", "удаленнаяработа",
        "удаленка", "безопыта", "свободныйграфик"))
    large_weekly_pay = bool(re.search(
        r"\b(?:от\s*)?\d{2,3}(?:[\s.,]*\d{3})+\s*"
        r"(?:₽|руб\w*|рф|р\.|р)?\s*(?:за|в|/|в\s*течение)\s*недел\w*",
        norm))
    adult = bool(re.search(r"\b18\s*\+|от\s*18|для\s*18", norm))
    recruitment = bool(re.search(r"прост\w*\s*занятост|доход|заработ|подработ|ваканси", norm))
    return has_link and employment and large_weekly_pay and (adult or recruitment)


# v1.8: recruitment spam with abbreviated amounts (84к/неделю), emoji,
# mixed-script words, and an external Telegram contact link.
WEEKLY_K_RE = re.compile(
    r"(?:\bот\s*)?\d{2,3}\s*[кk](?:\s*(?:руб\w*|₽))?\s*"
    r"(?:за|в|/|\bza\b)\s*недел\w*", re.I)
RECRUITMENT_V18_RE = re.compile(
    r"(?:требу\w*\s+сотрудник\w*|ищем\s+сотрудник\w*|"
    r"набор\s+(?:сотрудник\w*|персонал\w*|людей)|"
    r"нужн\w*\s+(?:сотрудник\w*|люди)|"
    r"подработ\w*|прост\w*\s+занятост\w*|"
    r"удален\w*\s+работ\w*|быстр\w*\s+старт)", re.I)


def recruitment_weekly_spam(text, link_text=""):
    norm = promotion_normalize(text).replace("ё", "е")
    # Work with both full text and link entities, including t.me/m/ URLs.
    link = bool(TG_LINK_RE.search(link_text) or URL_RE.search(link_text))
    weekly = bool(WEEKLY_K_RE.search(norm) or re.search(
        r"\d{2,3}(?:[\s.,]*\d{3})+\s*(?:₽|руб\w*)?\s*"
        r"(?:за|в|/)\s*недел\w*", norm))
    recruitment = bool(RECRUITMENT_V18_RE.search(norm))
    audience = bool(re.search(r"18\s*\+|граждан\w*\s+рф|только\s+рф", norm))
    return link and weekly and recruitment and audience


def high_confidence_promo(text, link_text=""):
    norm = promotion_normalize(text)
    links = bool(URL_RE.search(link_text) or TG_LINK_RE.search(link_text))
    cta = bool(PROMO_CONTACT_RE.search(norm) or links)
    job = bool(JOB_OFFER_RE.search(norm) and MONEY_RE.search(norm) and
               (JOB_HOOK_RE.search(norm) or links) and cta)
    finance = bool(FINANCE_PITCH_RE.search(norm) and MONEY_RE.search(norm) and cta)
    betting = bool(BETTING_PITCH_RE.search(norm) and cta and (links or MONEY_RE.search(norm) or re.search(r"гарантир\w*\s*выигрыш|договорн\w*\s*матч", norm)))
    if job:
        return "навязчивая реклама работы/заработка"
    if finance:
        return "навязчивая финансовая реклама"
    if betting:
        return "навязчивая реклама ставок/казино"
    return None


# v1.6: Broad but multi-signal advertising filters. These intentionally do not
# ban users for mentioning a topic alone in normal automotive conversation.
DRIVER_DOC_RE = re.compile(r"(?:водительск\w*\s+(?:прав\w*|удостоверен\w*)|\bв\s*у\b|\bву\b|\bправ\w*)", re.I)
DRIVER_SERVICE_RE = re.compile(r"(?:категори\w*\s*[a-dа-д](?:\s*[-–—]\s*[a-dа-д])?|восстановлен\w*|замен\w*|оформлен\w*|получен\w*|лишени\w*|без\s*экзамен\w*|без\s*предоплат\w*|официальн\w*|помощ\w*|решени\w*\s*вопрос\w*)", re.I)
PROMO_OFFER_RE = re.compile(r"(?:помо(?:гу|щь)|оформл\w*|дела\w*|получ\w*|реш\w*|восстанов\w*|замен\w*|предлага\w*|услуг\w*|продам|куплю|оптом|заказ|без\s*предоплат\w*)", re.I)
DOC_AD_RE = re.compile(r"(?:диплом\w*|аттестат\w*|справк\w*|сертификат\w*|медкнижк\w*|военн\w*\s*билет\w*|паспорт\w*|регистраци\w*)", re.I)
SCAM_PITCH_RE = re.compile(r"(?:кредит\w*|займ\w*|микрозайм\w*|списан\w*\s*долг\w*|вывод\w*\s*средств|возврат\w*\s*денег|разблокиров\w*\s*счет\w*|заработ\w*|доход\w*|удален\w*\s*работ\w*|подработ\w*|инвест\w*|казино|букмекер|ставк\w*|арбитраж\w*|раскрутк\w*\s*депозит\w*)", re.I)
SALES_OFFER_RE = re.compile(r"(?:продам|предлага\w*|оказыва\w*|в наличии|по выгодн\w*|акци\w*|скидк\w*|оптом|доставк\w*|оплат\w*|гаранти\w*|без предоплат\w*|на заказ)", re.I)


def broad_spam_reason(text, link_text=""):
    """Return reason only for a combination of subject, offer and solicitation."""
    norm = promotion_normalize(text)
    links = bool(URL_RE.search(link_text) or TG_LINK_RE.search(link_text))
    cta = bool(PROMO_CONTACT_RE.search(norm) or CONTACT_CTA_RE.search(norm) or links)
    if DRIVER_DOC_RE.search(norm):
        services = DRIVER_SERVICE_RE.findall(norm)
        # E.g. 'Помощь с правами. Замена/восстановление. Пиши в личку'.
        if cta and (len(services) >= 2 or (services and PROMO_OFFER_RE.search(norm))):
            return "реклама оформления/восстановления водительских документов"
    if DOC_AD_RE.search(norm) and PROMO_OFFER_RE.search(norm) and cta and (SALES_OFFER_RE.search(norm) or links):
        return "навязчивая реклама оформления документов"
    if SCAM_PITCH_RE.search(norm) and cta and (MONEY_RE.search(norm) or SALES_OFFER_RE.search(norm) or links or re.search(r"(?:без\s*отказа|без\s*проверок|одобрен\w*|выдам|предлага\w*)", norm)):
        return "навязчивая финансовая/коммерческая реклама"
    return None


def cross_user_promo(chat_id, user_id, message_id, text, link_text=""):
    """Only repetitive solicitation; never punish generic repeated words alone."""
    norm = promotion_normalize(text)
    if len(norm) < 28 or not (PROMO_CONTACT_RE.search(norm) or URL_RE.search(link_text)):
        return False
    # A sales/recruitment pitch AND a contact CTA are required.
    if not (SALES_PITCH_RE.search(norm) or JOB_OFFER_RE.search(norm) or FINANCE_PITCH_RE.search(norm)):
        return False
    digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()
    now = time.time()
    with db() as conn:
        conn.execute("DELETE FROM cross_user_promos_v15 WHERE seen_at < ?", (now - 86400,))
        people = conn.execute("SELECT DISTINCT user_id FROM cross_user_promos_v15 WHERE chat_id=? AND digest=? AND user_id<>? AND seen_at>=?", (chat_id,digest,user_id,now-86400)).fetchall()
        conn.execute("INSERT OR REPLACE INTO cross_user_promos_v15 (chat_id,user_id,digest,message_id,seen_at) VALUES (?,?,?,?,?)", (chat_id,user_id,digest,message_id,now))
    return bool(people)


def spam_score(text):
    normalized = normalize_text(text)
    score = sum(1 for phrase in SPAM_PHRASES if phrase in normalized)
    score += sum(2 for pattern in STRONG_SPAM_RE if pattern.search(normalized))
    return score


def check_flood(chat_id, user_id):
    now = time.time()
    # Remove inactive senders; avoid unbounded memory growth.
    for key in list(flood_cache):
        if not flood_cache[key] or now - flood_cache[key][-1] > FLOOD_WINDOW:
            del flood_cache[key]
    queue = flood_cache[(chat_id, user_id)]
    queue.append(now)
    while queue and now - queue[0] > FLOOD_WINDOW:
        queue.popleft()
    return len(queue) >= FLOOD_COUNT


def check_duplicate(chat_id, user_id, message_id, text):
    normalized = normalize_text(text)
    if len(normalized) < 8:
        return False
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    now = time.time()
    with db() as conn:
        conn.execute("DELETE FROM duplicates_v2 WHERE seen_at < ?", (now - DUPLICATE_WINDOW,))
        previous = conn.execute("SELECT message_id,seen_at FROM duplicates_v2 WHERE chat_id=? AND user_id=? AND digest=?", (chat_id,user_id,digest)).fetchone()
        conn.execute("INSERT OR REPLACE INTO duplicates_v2 VALUES (?,?,?,?,?)", (chat_id,user_id,digest,message_id,now))
    return bool(previous and previous[0] != message_id and now - previous[1] <= DUPLICATE_WINDOW)


async def remove_message(message):
    try:
        await message.delete()
        return True
    except TelegramError as exc:
        log.warning("Не удалось удалить сообщение %s: %s", message.message_id, exc)
        return False


async def punish(update, context, reason, instant_ban=False):
    user = update.effective_user
    chat = update.effective_chat
    message = update.effective_message
    if not user:
        return
    # Refresh the role immediately before destructive actions.
    try:
        role = await context.bot.get_chat_member(chat.id, user.id)
    except TelegramError as exc:
        trace(update, "SKIP role_check_failed=" + type(exc).__name__)
        return
    if role.status in ("administrator", "creator"):
        trace(update, "SKIP protected_admin")
        return
    if not await remove_message(message):
        trace(update, "DELETE_FAILED reason=" + reason)
        return  # Never add a warning or ban after a failed deletion.
    if in_test(chat.id, user.id, message.text or message.caption or ""):
        trace(update, "TEST_DELETE reason=" + reason)
        return
    count = add_warning(chat.id, user.id, message.message_id, reason)
    if count is None:
        return
    trace(update, f"DELETE reason={reason} warning={count}/{WARN_LIMIT}")
    log.warning(
        "Удалено | user=%s | id=%s | reason=%s | warning=%s/%s",
        user.username or user.full_name, user.id, reason, count, WARN_LIMIT,
    )
    if instant_ban or count >= WARN_LIMIT:
        try:
            await context.bot.ban_chat_member(chat_id=chat.id, user_id=user.id)
            trace(update, f"BAN reason={reason} instant={instant_ban}")
            log.warning("BAN | user=%s | id=%s | reason=%s | instant=%s", user.username or user.full_name, user.id, reason, instant_ban)
        except TelegramError as exc:
            log.error("Не удалось забанить %s: %s", user.id, exc)


async def new_members(update, context):
    if not correct_chat(update) or not update.effective_message:
        return
    for user in update.effective_message.new_chat_members:
        if not user.is_bot:
            save_join(update.effective_chat.id, user.id)
            log.info("Новый участник: %s (%s)", user.username or user.full_name, user.id)


async def moderate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not correct_chat(update):
        trace(update, "SKIP not_target_group")
        return
    message = update.effective_message
    if not message:
        return
    if message.new_chat_members:
        trace(update, "SKIP service_join")
        return
    if message.sender_chat:
        # Anonymous group admins appear as the group itself: never auto-moderate them.
        # Posts on behalf of another channel have no reliable human sender ID.
        if message.sender_chat.id == message.chat_id:
            trace(update, "SKIP anonymous_group_admin")
            return
        anonymous_text = message.text or message.caption or ""
        if (recruitment_weekly_spam(anonymous_text, message_link_text(message))
                or weekly_earnings_spam(anonymous_text, message_link_text(message))
                or unsolicited_crypto_trade(anonymous_text, message_link_text(message))
                or obvious_job_scam(anonymous_text, message_link_text(message))
                or high_confidence_promo(anonymous_text, message_link_text(message))
                or broad_spam_reason(anonymous_text, message_link_text(message))):
            deleted = await remove_message(message)
            trace(update, "DELETE sender_chat_ad" if deleted else "DELETE_FAILED sender_chat_ad")
        else:
            trace(update, "SKIP sender_chat_other")
        return
    user = update.effective_user
    if not user or user.is_bot:
        trace(update, "SKIP no_user_or_bot")
        return
    protected = await protected_user(update, context)
    if protected is None:
        trace(update, "SKIP admin_lookup_failed")
        return
    if protected:
        trace(update, "SKIP protected_admin")
        return
    text = message.text or message.caption or ""
    if not text:
        trace(update, "SKIP no_text_or_caption")
        return
    link_text = message_link_text(message)
    new_promo_reason = ("реклама набора сотрудников с обещанием высокого дохода" if recruitment_weekly_spam(text, link_text)
                        else "реклама быстрого заработка за неделю" if weekly_earnings_spam(text, link_text)
                        else high_confidence_promo(text, link_text) or broad_spam_reason(text, link_text))
    if new_promo_reason:
        await punish(update, context, new_promo_reason, instant_ban=True)
        return
    if cross_user_promo(message.chat_id, user.id, message.message_id, text, link_text):
        await punish(update, context, "повтор рекламного шаблона другим аккаунтом", instant_ban=True)
        return
    if unsolicited_crypto_trade(text, link_text):
        await punish(update, context, "навязчивая реклама обмена криптовалюты/наличных", instant_ban=True)
        return
    if obvious_job_scam(text, link_text):
        await punish(update, context, "явная реклама работы/заработка с ссылкой", instant_ban=True)
        return
    if not update.edited_message and not in_test(message.chat_id, user.id, text) and check_flood(message.chat_id, user.id):
        await punish(update, context, "флуд")
        return
    if check_duplicate(message.chat_id, user.id, message.message_id, text):
        await punish(update, context, "повтор одинакового сообщения")
        return
    link_text = message_link_text(message)
    has_link = has_normal_link(link_text) or bool(TG_LINK_RE.search(link_text))
    if earnings_ad(text, has_link):
        await punish(update, context, "реклама заработка")
        return
    if BLOCK_TELEGRAM_LINKS and telegram_link_blocked(link_text):
        await punish(update, context, "реклама Telegram-канала/группы")
        return
    if is_new_member(message.chat_id, user.id) and has_link:
        await punish(update, context, "ссылка от нового пользователя")
        return
    if BLOCK_ALL_LINKS and has_link:
        await punish(update, context, "внешняя ссылка")
        return
    score = spam_score(text)
    if score >= 2:
        await punish(update, context, f"спам-текст, score={score}")
        return
    if score >= 1 and has_link:
        await punish(update, context, "рекламный текст + ссылка")
        return
    trace(update, "PASS")


def in_test(chat_id, user_id, text):
    now = time.time()
    for key, expiry in list(test_sessions.items()):
        if now >= expiry:
            del test_sessions[key]
    return test_sessions.get((chat_id,user_id), 0) > now and normalize_text(text) == normalize_text(TEST_TEXT)


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await command_admin(update, context):
        return
    me = await context.bot.get_chat_member(update.effective_chat.id, context.bot.id)
    registered = "\n".join(f"@{name}: {note}" for name,note in target_notes.items())
    await update.effective_message.reply_text(
        f"🛡 AntiSpam v{VERSION} работает\n\n"
        f"Текущая группа: {update.effective_chat.title}\n"
        f"ID: {update.effective_chat.id}\n"
        f"Бот: {me.status}; удаление: {bool(getattr(me, 'can_delete_messages', False))}; блокировка: {bool(getattr(me, 'can_restrict_members', False))}\n"
        f"Предупреждений до бана: {WARN_LIMIT}\n"
        f"Флуд: {FLOOD_COUNT} сообщений / {FLOOD_WINDOW} сек.\n"
        f"Дубли: {DUPLICATE_WINDOW} сек.\n"
        "Реклама заработка: ON; скрытые ссылки: проверяются\n"
        f"Защита новых участников: {NEW_MEMBER_HOURS} ч.\n"
        f"Telegram-ссылки: {'ON' if BLOCK_TELEGRAM_LINKS else 'OFF'}\n"
        f"Все внешние ссылки: {'BLOCK' if BLOCK_ALL_LINKS else 'ALLOW'}\n\n"
        f"Адреса при запуске:\n{registered}\n\n"
        "Предупреждения считаются отдельно в каждой группе.\n"
        "/antispam_debug — последние решения\n"
        "/antispam_test — ответом на тестовое сообщение участника"
    )


async def debug_command(update, context):
    if not await command_admin(update, context):
        return
    lines = list(recent_events.get(update.effective_chat.id, ()))
    reply = update.effective_message.reply_to_message
    extra = ""
    if reply:
        if reply.sender_chat:
            extra = f"\nВыбранное сообщение отправлено от имени чата {reply.sender_chat.id}; фильтр его пропускает."
        elif reply.from_user:
            role = await context.bot.get_chat_member(update.effective_chat.id, reply.from_user.id)
            extra = f"\nВыбранное сообщение: {reply.message_id}; user={reply.from_user.id}; роль={role.status}; бот={reply.from_user.is_bot}."
    await update.effective_message.reply_text(
        f"AntiSpam v{VERSION}, группа {update.effective_chat.id}\n"
        + ("\n".join(lines) if lines else "Обычные сообщения ещё не обработаны после запуска.")
        + extra + "\nPASS — пропущено фильтром; SKIP — исключение; DELETE — удалено; TEST_DELETE — тест без штрафа."
    )


async def test_command(update, context):
    if not await command_admin(update, context):
        return
    message = update.effective_message
    reply = message.reply_to_message
    if not reply or normalize_text(reply.text or reply.caption or "") != normalize_text(TEST_TEXT):
        await message.reply_text(f"Ответьте этой командой на сообщение обычного участника:\n{TEST_TEXT}")
        return
    if reply.sender_chat or not reply.from_user or reply.from_user.is_bot:
        await message.reply_text("Нужно сообщение от личного аккаунта обычного участника, а не от имени канала/группы.")
        return
    uid = reply.from_user.id
    role = await context.bot.get_chat_member(message.chat_id, uid)
    if role.status in ("administrator", "creator"):
        await message.reply_text("Это администратор; его сообщения защищены. Выберите обычного участника.")
        return
    test_sessions[(message.chat_id, uid)] = time.time() + 120
    digest = hashlib.sha256(normalize_text(TEST_TEXT).encode("utf-8")).hexdigest()
    with db() as conn:
        conn.execute("DELETE FROM duplicates_v2 WHERE chat_id=? AND user_id=? AND digest=?", (message.chat_id,uid,digest))
    deleted = await remove_message(reply)
    trace(update, f"TEST_ARM user={uid} manual_delete={deleted}")
    await message.reply_text(
        ("✅ Выбранное тестовое сообщение удалено." if deleted else "⚠️ Не удалось удалить выбранное сообщение; подробность в логах.")
        + f"\nТест для участника {uid} включён на 120 секунд.\n"
        + f"Пусть он отправит два новых сообщения подряд:\n{TEST_TEXT}\n"
        + "Первое должно остаться, второе удалиться. Только эта фраза у этого участника в этой группе сейчас проверяется без предупреждений и бана.\n"
        + "После теста администратор может вызвать /antispam_debug."
    )


async def error_handler(update, context):
    log.exception("Ошибка Telegram update:", exc_info=context.error)


def build_application():
    app = (Application.builder().token(BOT_TOKEN).post_init(on_start)
           .connect_timeout(20).read_timeout(20)
           .get_updates_connect_timeout(20).get_updates_read_timeout(30)
           .concurrent_updates(False).build())
    app.add_handler(CommandHandler("antispam_status", status), group=0)
    app.add_handler(CommandHandler("antispam_debug", debug_command), group=0)
    app.add_handler(CommandHandler("antispam_test", test_command), group=0)
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, new_members), group=0)
    app.add_handler(MessageHandler(filters.ALL, moderate), group=1)
    app.add_error_handler(error_handler)
    return app


def main():
    init_db()
    log.info("Запуск AntiSpam v%s для %s", VERSION, ", ".join("@" + n for n in TARGET_CHAT_NAMES))
    app = build_application()
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True, bootstrap_retries=5)


if __name__ == "__main__":
    main()
