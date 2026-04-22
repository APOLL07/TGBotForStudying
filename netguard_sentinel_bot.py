import os
import re
import logging
import httpx
import random
import hashlib
from datetime import datetime, timedelta, time as dt_time
from pathlib import Path
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)
from telegram.constants import ParseMode, ChatAction
from telegram import LinkPreviewOptions

from db import (
    init_db, close_db,
    get_schedule, get_next_lesson, add_lesson, delete_lesson,
    get_upcoming_lessons, save_fact, get_fact_history,
)

load_dotenv(dotenv_path=Path(__file__).parent / ".env")

BOT_TOKEN  = os.getenv("BOT_TOKEN", "")
COHERE_KEY = os.getenv("COHERE_API_KEY", "")
TAVILY_KEY = os.getenv("TAVILY_API_KEY", "")

try:
    from tavily import AsyncTavilyClient
    tavily_client = AsyncTavilyClient(api_key=TAVILY_KEY) if TAVILY_KEY else None
except ImportError:
    tavily_client = None

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("NetGuardSentinel")

# ─── System Prompt ────────────────────────────────────────────────
SYSTEM_PROMPT = """Ты — NetGuard Sentinel, умный, профессиональный и универсальный ИИ-ассистент.

ПРАВИЛА ОБЩЕНИЯ:
1. Отвечай профессионально и по делу.
2. Если пользователь просит уточнить детали новости или предыдущего ответа — ищи ответы СТРОГО в истории чата.
3. НЕ используй сложный LaTeX! Вместо \\mathbf{F} пиши просто F. Степени пиши юникодом (например 10³). Дроби пиши через слэш (a/b).

УПРАВЛЕНИЕ РАСПИСАНИЕМ:
Ты также можешь управлять расписанием уроков пользователя. 
- Если пользователь спрашивает "когда следующая пара", "какие уроки", "расписание" — покажи ему данные расписания, которые будут предоставлены ниже.
- Если пользователь просит "добавь пару" или "перенеси урок" — извлеки из его сообщения: название предмета, день недели (0=Пн, 1=Вт, 2=Ср, 3=Чт, 4=Пт, 5=Сб, 6=Вс), время начала (ЧЧ:ММ), и опционально ссылку. Ответь СТРОГО в формате JSON:
  {"action": "add", "subject": "...", "day": N, "time": "HH:MM", "url": "..."}
  или {"action": "delete", "id": N}
  Если данных недостаточно — вежливо переспроси.
- Если пользователь просит удалить пару — ответь JSON: {"action": "delete", "id": N}
"""

DAY_NAMES = ["Понедельник", "Вторник", "Среда", "Четверг", "Пятница", "Суббота", "Воскресенье"]
DAY_NAMES_SHORT = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]

# ─── State ────────────────────────────────────────────────────────
user_state: dict[int, dict] = {}
MAX_CONTEXT = 20

# Track which lessons already triggered a notification (to avoid spamming)
_notified_lessons: set[tuple[int, int]] = set()  # (user_id, lesson_id)


def get_state(uid: int) -> dict:
    if uid not in user_state:
        user_state[uid] = {"context": [], "menu": None, "subject": None}
    return user_state[uid]


def change_mode(uid: int, menu: str, subject=None):
    """
    Меняет текущий режим работы бота.
    Если мы переходим из одного раздела в другой — контекст сбрасывается.
    """
    state = get_state(uid)
    if state.get("menu") != menu or state.get("subject") != subject:
        state["context"] = []
        logger.info(f"User {uid}: Контекст сброшен. Смена режима: {menu}, Предмет: {subject}")
    state["menu"] = menu
    state["subject"] = subject


def add_to_context(uid: int, role: str, text: str):
    state = get_state(uid)
    state["context"].append({"role": role, "text": text})
    if len(state["context"]) > MAX_CONTEXT * 2:
        state["context"] = state["context"][-MAX_CONTEXT * 2:]
    while sum(len(msg["text"]) for msg in state["context"]) > 30000 and len(state["context"]) > 1:
        state["context"].pop(0)


# ─── Text cleaner ────────────────────────────────────────────────
SUPERSCRIPTS = str.maketrans("-0123456789", "⁻⁰¹²³⁴⁵⁶⁷⁸⁹")


def replace_power_braces(match):
    return match.group(1).translate(SUPERSCRIPTS)


def clean_bot_response(text: str) -> str:
    text = text.replace(r'\[', '').replace(r'\]', '')
    text = text.replace(r'\(', '').replace(r'\)', '')
    text = text.replace(r'$$', '').replace(r'$', '')
    text = text.replace(r'\,', ' ')
    text = text.replace(r'\;', ' ')

    text = re.sub(r'\\frac\{([^}]+)\}\{([^}]+)\}', r'(\1)/(\2)', text)
    text = re.sub(r'\\mathbf\{([^}]+)\}', r'\1', text)
    text = re.sub(r'\\text\{([^}]+)\}', r'\1', text)
    text = re.sub(r'\\sqrt\{([^}]+)\}', r'√(\1)', text)
    text = text.replace(r'\times', '×').replace(r'\cdot', '·')

    text = re.sub(r'\^\{([^}]+)\}', replace_power_braces, text)
    text = re.sub(r'\^(-?\d+)', replace_power_braces, text)

    text = re.sub(r'^###\s+(.+)$', r'*\1*', text, flags=re.MULTILINE)
    text = re.sub(r'^##\s+(.+)$', r'*\1*', text, flags=re.MULTILINE)
    text = re.sub(r'^#\s+(.+)$', r'*\1*', text, flags=re.MULTILINE)
    text = text.replace('***', '*').replace('* **', '*').replace('** *', '*')
    text = text.replace('**', '*')

    return text.strip()


# ─── Safe message sender ─────────────────────────────────────────
async def send_safe_message(chat, text: str, reply_markup=None):
    max_len = 3900
    parts = []
    current_part = ""
    for paragraph in text.split("\n\n"):
        if len(current_part) + len(paragraph) + 2 <= max_len:
            current_part += paragraph + "\n\n"
        else:
            if current_part:
                parts.append(current_part.strip())
            if len(paragraph) > max_len:
                for i in range(0, len(paragraph), max_len):
                    parts.append(paragraph[i:i + max_len])
                current_part = ""
            else:
                current_part = paragraph + "\n\n"
    if current_part:
        parts.append(current_part.strip())

    for i, part in enumerate(parts):
        markup = reply_markup if i == len(parts) - 1 else None
        try:
            await chat.send_message(
                part, parse_mode=ParseMode.MARKDOWN,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
                reply_markup=markup,
            )
        except Exception as e:
            logger.warning(f"Markdown parse error: {e}")
            await chat.send_message(
                part,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
                reply_markup=markup,
            )


# ─── Cohere API ──────────────────────────────────────────────────
async def ask_cohere(uid: int, user_message: str, use_search: bool = False,
                     explicit_search_query: str = None,
                     dynamic_preamble: str = None) -> str:
    if not COHERE_KEY:
        return "⚠️ *Cohere API Key не задан*"

    state = get_state(uid)

    if use_search and tavily_client:
        try:
            search_query = explicit_search_query if explicit_search_query else user_message
            logger.info(f"🔍 Ищу в Tavily: {search_query}")

            search_result = await tavily_client.search(
                query=search_query, topic="news", days=2, max_results=5,
            )

            if search_result and "results" in search_result and len(search_result["results"]) > 0:
                search_context = ""
                for idx, res in enumerate(search_result["results"], 1):
                    search_context += (
                        f"[{idx}] {res.get('title', '')}\n"
                        f"{res.get('content', '')}\nURL: {res.get('url', '')}\n\n"
                    )

                user_message = (
                    f"ЗАПРОС ПОЛЬЗОВАТЕЛЯ: {user_message}\n\n"
                    f"ДАННЫЕ ИЗ ПОИСКОВИКА (НОВЫЕ СТАТЬИ):\n{search_context}\n"
                    f"ИНСТРУКЦИЯ: \n"
                    f"Сделай ответ на основе этих данных. Выбери ДРУГУЮ новость, чтобы не повторяться."
                )
        except Exception as e:
            logger.error(f"Tavily Search error: {e}")

    chat_history = [{"role": msg["role"], "message": msg["text"]} for msg in state["context"]]

    preamble_to_use = dynamic_preamble if dynamic_preamble else SYSTEM_PROMPT

    payload = {
        "model": "command-a-03-2025",
        "message": user_message,
        "preamble": preamble_to_use,
        "chat_history": chat_history,
        "temperature": 0.4,
    }

    url = "https://api.cohere.ai/v1/chat"
    headers = {"Authorization": f"Bearer {COHERE_KEY}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code != 200:
                return f"❌ Ошибка API: {response.text}"
            return clean_bot_response(response.json()["text"])
    except Exception as e:
        return f"❌ Ошибка сети: {e}"


# ─── Intelligent IT Fact Generator ───────────────────────────────
IT_FACT_TOPICS = [
    "архитектура ПК и процессоров",
    "история ЭВМ и вычислительной техники",
    "компьютерные сети и протоколы",
    "кибербезопасность: знаменитые атаки и методы защиты",
    "языки программирования и их история",
    "криптография и шифрование",
    "операционные системы",
    "базы данных и хранение информации",
]


async def generate_fact(uid: int) -> str:
    """Generate a unique IT/Cybersecurity fact that was never shown to this user."""
    topic = random.choice(IT_FACT_TOPICS)

    # Fetch previous facts for anti-repeat
    try:
        previous_facts = await get_fact_history(uid, limit=50)
    except Exception:
        previous_facts = []

    exclusion_block = ""
    if previous_facts:
        facts_list = "\n".join(f"- {f}" for f in previous_facts)
        exclusion_block = (
            f"\n\nЖЁСТКОЕ ОГРАНИЧЕНИЕ — НИКОГДА не повторяй и не перефразируй "
            f"следующие факты, которые ты уже рассказывал этому пользователю:\n{facts_list}\n"
            f"Расскажи АБСОЛЮТНО НОВЫЙ факт, которого нет в списке выше."
        )

    prompt = (
        f"Расскажи один очень интересный, малоизвестный и удивительный факт "
        f"строго по теме: {topic}. "
        f"Факт должен быть из области IT и кибербезопасности. "
        f"Расскажи увлекательно, но кратко (3-5 предложений)."
        f"{exclusion_block}"
    )

    fact_preamble = (
        SYSTEM_PROMPT + "\n\nТы — эксперт в области IT и кибербезопасности. "
        "Генерируй только уникальные, малоизвестные и проверенные факты."
    )

    fact = await ask_cohere(uid, prompt, use_search=False, dynamic_preamble=fact_preamble)

    # Save to DB for future anti-repeat
    try:
        await save_fact(uid, fact)
    except Exception as e:
        logger.error(f"Failed to save fact to DB: {e}")

    return fact


# ─── Keyboards ───────────────────────────────────────────────────
def main_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📰 Новости", callback_data="menu_news"),
         InlineKeyboardButton("🎓 Обучение", callback_data="menu_edu")],
        [InlineKeyboardButton("🛡️ CVE Поиск", callback_data="menu_cve"),
         InlineKeyboardButton("📋 Анализ лога", callback_data="menu_log")],
        [InlineKeyboardButton("📅 Расписание", callback_data="menu_schedule"),
         InlineKeyboardButton("ℹ️ О боте", callback_data="menu_about")],
    ])


def news_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🤖 ИИ", callback_data="news_ai"),
         InlineKeyboardButton("🌎 Политика", callback_data="news_politics"),
         InlineKeyboardButton("🔬 Наука", callback_data="news_science")],
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
    ])


def edu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📐 Математика", callback_data="edu_math"),
         InlineKeyboardButton("🍎 Физика", callback_data="edu_physics"),
         InlineKeyboardButton("🇬🇧 Английский", callback_data="edu_english")],
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
    ])


# ─── Commands ────────────────────────────────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    name = update.effective_user.first_name or "Пользователь"

    change_mode(uid, "main")

    welcome_text = (
        f"👋 Привет, {name}! *NetGuard Sentinel v8.0* готов к работе.\n\n"
        f"Список доступных команд:\n"
        f"🔹 /menu — Открыть главное меню\n"
        f"🔹 /news — Лента новостей\n"
        f"🔹 /study — Режим обучения\n"
        f"🔹 /cve — Поиск уязвимостей\n"
        f"🔹 /log — Анализ логов\n"
        f"🔹 /schedule — Моё расписание\n"
        f"🔹 /randomfact — IT-факт дня\n"
        f"🔹 /clear — Очистить память диалога\n\n"
        f"💡 Также можно написать \"список команд\" для вызова меню.\n\n"
        f"Выбери нужный раздел с помощью команд или кнопок ниже:"
    )
    await send_safe_message(update.effective_chat, welcome_text, reply_markup=main_menu_keyboard())


async def cmd_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    change_mode(update.effective_user.id, "main")
    await update.message.reply_text(
        "🏠 *Главное меню*", parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_menu_keyboard(),
    )


async def cmd_news(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    change_mode(update.effective_user.id, "news")
    await update.message.reply_text(
        "📰 *Новости* — выбери категорию:", parse_mode=ParseMode.MARKDOWN,
        reply_markup=news_keyboard(),
    )


async def cmd_study(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    change_mode(update.effective_user.id, "edu")
    await update.message.reply_text(
        "🎓 *Обучение* — выбери предмет:", parse_mode=ParseMode.MARKDOWN,
        reply_markup=edu_keyboard(),
    )


async def cmd_cve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    change_mode(update.effective_user.id, "cve")
    await update.message.reply_text(
        "🛡️ *Режим поиска CVE активирован.*\n"
        "Напиши название программы или номер CVE (например, CVE-2023-1234).",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_log(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    change_mode(update.effective_user.id, "log")
    await update.message.reply_text(
        "📋 *Анализ логов активирован.*\n"
        "Отправь мне кусок лога (системного, серверного), и я найду аномалии.",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_randomfact(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    change_mode(uid, "randomfact")

    await update.message.chat.send_action(ChatAction.TYPING)
    fact = await generate_fact(uid)
    await send_safe_message(update.effective_chat, f"🎲 *IT-факт дня:*\n\n{fact}")


async def cmd_schedule(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Show the user's full schedule."""
    uid = update.effective_user.id
    change_mode(uid, "schedule")

    try:
        lessons = await get_schedule(uid)
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка БД: {e}")
        return

    if not lessons:
        await update.message.reply_text(
            "📅 *Расписание пусто.*\nНапиши, например: \"Добавь пару Математика в среду в 10:00\"",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    text = "📅 *Твоё расписание:*\n\n"
    current_day = -1
    for lesson in lessons:
        day = lesson["day_of_week"]
        if day != current_day:
            text += f"*{DAY_NAMES[day]}:*\n"
            current_day = day
        time_str = lesson["start_time"].strftime("%H:%M")
        url_part = f" | [ссылка]({lesson['url']})" if lesson.get("url") else ""
        text += f"  🔸 {time_str} — {lesson['subject']}{url_part} (id:{lesson['id']})\n"
    text += "\n💡 Напиши \"когда следующая пара\" или \"добавь пару ...\""

    await send_safe_message(update.effective_chat, text)


async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user_state.pop(update.effective_user.id, None)
    await update.message.reply_text(
        "🗑️ Оперативная память очищена. Контекст сброшен.",
        reply_markup=main_menu_keyboard(),
    )


# ─── Callback handler ───────────────────────────────────────────
NEWS_CATEGORIES = {
    "news_ai": ("ИИ", ["ИИ прорыв", "LLM релизы", "нейросети стартапы",
                        "ChatGPT конкуренты", "искусственный интеллект технологии"]),
    "news_politics": ("Политика", ["мировая политика", "геополитика конфликты",
                                    "международные отношения решения", "выборы в мире"]),
    "news_science": ("Наука", ["научные открытия космос", "физика квантовые технологии",
                                "биотехнологии прорыв", "астрономия новые планеты"]),
}
EDU_SUBJECTS = {
    "edu_math": ("math", "📐 Математика"),
    "edu_physics": ("physics", "🍎 Физика"),
    "edu_english": ("english", "🇬🇧 Английский"),
}


async def callback_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id

    if q.data in ("back_main", "menu_main"):
        change_mode(uid, "main")
        await q.edit_message_text(
            "🏠 *Главное меню*", parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_menu_keyboard(),
        )

    elif q.data == "menu_news":
        change_mode(uid, "news")
        await q.edit_message_text(
            "📰 *Новости* — выбери категорию:", parse_mode=ParseMode.MARKDOWN,
            reply_markup=news_keyboard(),
        )

    elif q.data == "menu_edu":
        change_mode(uid, "edu")
        await q.edit_message_text(
            "🎓 *Обучение* — выбери предмет:", parse_mode=ParseMode.MARKDOWN,
            reply_markup=edu_keyboard(),
        )

    elif q.data == "menu_cve":
        change_mode(uid, "cve")
        await q.edit_message_text(
            "🛡️ *Режим поиска CVE активирован.*\n"
            "Напиши название программы или номер CVE для поиска.",
            parse_mode=ParseMode.MARKDOWN,
        )

    elif q.data == "menu_log":
        change_mode(uid, "log")
        await q.edit_message_text(
            "📋 *Анализ логов активирован.*\n"
            "Отправь мне фрагмент лога, и я проанализирую его на аномалии.",
            parse_mode=ParseMode.MARKDOWN,
        )

    elif q.data == "menu_schedule":
        change_mode(uid, "schedule")
        # Can't call cmd_schedule directly from callback, replicate logic
        try:
            lessons = await get_schedule(uid)
        except Exception as e:
            await q.edit_message_text(f"❌ Ошибка БД: {e}")
            return

        if not lessons:
            await q.edit_message_text(
                "📅 *Расписание пусто.*\n"
                "Напиши: \"Добавь пару Математика в среду в 10:00\"",
                parse_mode=ParseMode.MARKDOWN,
            )
            return

        text = "📅 *Твоё расписание:*\n\n"
        current_day = -1
        for lesson in lessons:
            day = lesson["day_of_week"]
            if day != current_day:
                text += f"*{DAY_NAMES[day]}:*\n"
                current_day = day
            time_str = lesson["start_time"].strftime("%H:%M")
            url_part = f" | [ссылка]({lesson['url']})" if lesson.get("url") else ""
            text += f"  🔸 {time_str} — {lesson['subject']}{url_part} (id:{lesson['id']})\n"
        text += "\n💡 Напиши \"когда следующая пара\" или \"добавь пару ...\""

        await q.delete_message()
        await send_safe_message(update.effective_chat, text)

    elif q.data == "menu_about":
        change_mode(uid, "about")
        about_text = (
            "ℹ️ *NetGuard Sentinel v8.0* — универсальный бот с ИИ.\n\n"
            "🔹 Новости, обучение, CVE, анализ логов\n"
            "🔹 Расписание уроков с уведомлениями\n"
            "🔹 IT-факты с защитой от повторов\n\n"
            "Разработан на базе Cohere, Tavily и PostgreSQL."
        )
        await q.edit_message_text(
            about_text, parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_menu_keyboard(),
        )

    elif q.data in NEWS_CATEGORIES:
        change_mode(uid, "news_active")
        short_title, search_terms = NEWS_CATEGORIES[q.data]
        await q.edit_message_text(
            f"⏳ Ищу актуальные статьи: {short_title}...",
            parse_mode=ParseMode.MARKDOWN,
        )

        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        tavily_query = f"{random.choice(search_terms)} новости {now_str}"

        user_prompt = (
            f"Сделай дайджест последних новостей по теме: {short_title}. "
            f"Расскажи о 3-4 абсолютно новых событиях, о которых мы еще не говорили."
        )
        digest = await ask_cohere(uid, user_prompt, use_search=True,
                                  explicit_search_query=tavily_query)

        add_to_context(uid, "USER", f"Покажи новости: {short_title}")
        add_to_context(uid, "CHATBOT", digest)

        await send_safe_message(update.effective_chat, f"*{short_title}*\n\n{digest}")
        await q.delete_message()

    elif q.data in EDU_SUBJECTS:
        subj_key, subj_title = EDU_SUBJECTS[q.data]
        change_mode(uid, "edu_active", subj_key)
        await q.delete_message()
        await update.effective_chat.send_message(
            f"*{subj_title}* активирована.\n"
            f"Бот переведен в режим узкого специалиста. Задай вопрос!",
            parse_mode=ParseMode.MARKDOWN,
        )


# ─── NLP Schedule helpers ────────────────────────────────────────
SCHEDULE_TRIGGERS = [
    "расписание", "следующая пара", "когда пара", "какие пары",
    "добавь пару", "перенеси урок", "удали пару", "мои уроки",
    "когда занятие", "ближайший урок", "какие уроки",
]


def is_schedule_request(text_lower: str) -> bool:
    """Check if the user's message is about schedule management."""
    return any(trigger in text_lower for trigger in SCHEDULE_TRIGGERS)


async def handle_schedule_nlp(uid: int, text: str, chat) -> bool:
    """
    Process schedule-related NLP requests.
    Returns True if handled, False if should fall through to general AI.
    """
    import json as _json
    text_lower = text.lower()

    # ── "Next lesson" queries ──
    next_triggers = ["следующая пара", "когда пара", "ближайший урок", "когда занятие"]
    if any(t in text_lower for t in next_triggers):
        try:
            lesson = await get_next_lesson(uid)
        except Exception as e:
            await send_safe_message(chat, f"❌ Ошибка БД: {e}")
            return True

        if not lesson:
            await send_safe_message(chat, "📅 У тебя пока нет уроков в расписании.")
            return True

        day_name = DAY_NAMES[lesson["day_of_week"]]
        time_str = lesson["start_time"].strftime("%H:%M")
        url_part = f"\n🔗 Ссылка: {lesson['url']}" if lesson.get("url") else ""
        await send_safe_message(
            chat,
            f"📅 *Ближайшая пара:*\n\n"
            f"📚 {lesson['subject']}\n"
            f"🗓 {day_name}, {time_str}{url_part}",
        )
        return True

    # ── "Show schedule" queries ──
    show_triggers = ["расписание", "какие пары", "мои уроки", "какие уроки"]
    if any(t in text_lower for t in show_triggers):
        try:
            lessons = await get_schedule(uid)
        except Exception as e:
            await send_safe_message(chat, f"❌ Ошибка БД: {e}")
            return True

        if not lessons:
            await send_safe_message(chat, "📅 Расписание пусто. Напиши \"добавь пару ...\" чтобы добавить.")
            return True

        result = "📅 *Твоё расписание:*\n\n"
        current_day = -1
        for lesson in lessons:
            day = lesson["day_of_week"]
            if day != current_day:
                result += f"*{DAY_NAMES[day]}:*\n"
                current_day = day
            time_str = lesson["start_time"].strftime("%H:%M")
            url_part = f" | [ссылка]({lesson['url']})" if lesson.get("url") else ""
            result += f"  🔸 {time_str} — {lesson['subject']}{url_part} (id:{lesson['id']})\n"

        await send_safe_message(chat, result)
        return True

    # ── "Add / delete lesson" — delegate to Cohere for NLP extraction ──
    add_del_triggers = ["добавь пару", "перенеси урок", "удали пару", "добавь урок"]
    if any(t in text_lower for t in add_del_triggers):
        # Provide current schedule as context
        try:
            lessons = await get_schedule(uid)
        except Exception:
            lessons = []

        schedule_ctx = ""
        if lessons:
            schedule_ctx = "\n\nТекущее расписание пользователя:\n"
            for l in lessons:
                schedule_ctx += (
                    f"id:{l['id']} | {DAY_NAMES[l['day_of_week']]} "
                    f"{l['start_time'].strftime('%H:%M')} — {l['subject']}\n"
                )

        nlp_prompt = (
            f"Запрос пользователя: \"{text}\"\n{schedule_ctx}\n\n"
            f"Извлеки данные и ответь ТОЛЬКО JSON (без markdown, без текста):\n"
            f"Для добавления: {{\"action\": \"add\", \"subject\": \"...\", \"day\": N, \"time\": \"HH:MM\", \"url\": \"...\"}}\n"
            f"Для удаления: {{\"action\": \"delete\", \"id\": N}}\n"
            f"Если данных недостаточно — ответь: {{\"action\": \"need_info\", \"question\": \"...\"}}"
        )

        ai_response = await ask_cohere(uid, nlp_prompt, use_search=False)

        # Try to parse JSON from AI response
        try:
            # Strip markdown code fences if present
            cleaned = re.sub(r'```json?\s*', '', ai_response)
            cleaned = cleaned.replace('```', '').strip()
            data = _json.loads(cleaned)
        except (_json.JSONDecodeError, ValueError):
            # AI couldn't extract — show its response as-is
            await send_safe_message(chat, ai_response)
            return True

        if data.get("action") == "add":
            try:
                parts = data["time"].split(":")
                lesson_time = dt_time(int(parts[0]), int(parts[1]))
                lesson_id = await add_lesson(
                    uid, data["subject"], data["day"], lesson_time, data.get("url", ""),
                )
                day_name = DAY_NAMES[data["day"]]
                await send_safe_message(
                    chat,
                    f"✅ *Пара добавлена!*\n\n"
                    f"📚 {data['subject']}\n"
                    f"🗓 {day_name}, {data['time']}\n"
                    f"🆔 id: {lesson_id}",
                )
            except Exception as e:
                await send_safe_message(chat, f"❌ Ошибка при добавлении: {e}")
            return True

        elif data.get("action") == "delete":
            try:
                deleted = await delete_lesson(data["id"], uid)
                if deleted:
                    await send_safe_message(chat, f"✅ Пара id:{data['id']} удалена.")
                else:
                    await send_safe_message(chat, f"⚠️ Пара id:{data['id']} не найдена.")
            except Exception as e:
                await send_safe_message(chat, f"❌ Ошибка при удалении: {e}")
            return True

        elif data.get("action") == "need_info":
            await send_safe_message(chat, f"❓ {data.get('question', 'Уточни детали пары.')}")
            return True

    return False


# ─── Text handler ────────────────────────────────────────────────
MENU_TRIGGERS = {"список команд", "дай список команд", "команды", "меню"}


async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid, text = update.effective_user.id, update.message.text.strip()
    text_lower = text.lower()

    # 0. Text triggers for menu
    if text_lower in MENU_TRIGGERS:
        await cmd_menu(update, ctx)
        return

    # 1. Greetings → start
    greetings = {
        "привет", "привет!", "здравствуй", "здравствуйте", "hello", "hi",
        "хай", "добрый день", "доброе утро", "добрый вечер", "ку", "приветствую",
    }
    if text_lower in greetings or text_lower == "/start":
        await cmd_start(update, ctx)
        return

    # 2. Schedule NLP routing
    if is_schedule_request(text_lower):
        await update.message.chat.send_action(ChatAction.TYPING)
        handled = await handle_schedule_nlp(uid, text, update.effective_chat)
        if handled:
            return

    await update.message.chat.send_action(ChatAction.TYPING)

    state = get_state(uid)
    active_subj = state.get("subject")
    dynamic_preamble = SYSTEM_PROMPT

    # 3. Education mode — inject subject into preamble
    if active_subj:
        subject_names = {"math": "Математика", "physics": "Физика", "english": "Английский язык"}
        subj_ru = subject_names.get(active_subj, active_subj)

        dynamic_preamble += (
            f"\n\nВНИМАНИЕ: ТВОЯ ТЕКУЩАЯ РОЛЬ — ПРОФЕССИОНАЛЬНЫЙ РЕПЕТИТОР "
            f"ПО ПРЕДМЕТУ '{subj_ru}'. Отвечай ИСКЛЮЧИТЕЛЬНО в рамках этой дисциплины."
        )

        teach_triggers = ["научи", "расскажи", "дай тему", "интересно"]
        if any(t in text_lower for t in teach_triggers):
            processed_text = (
                f"{text}\n(Расскажи полезную концепцию по этому предмету "
                f"и в конце дай задачу/вопрос для проверки)."
            )
        else:
            processed_text = text
    else:
        processed_text = text

    # 4. Follow-up vs search detection
    history_triggers = [
        "про первую", "про 1", "про вторую", "про 2",
        "подробнее про", "что за", "почему", "объясни",
    ]
    is_follow_up = any(t in text_lower for t in history_triggers)

    needs_search = False
    if not is_follow_up and not active_subj:
        search_triggers = [
            "найди", "поищи", "cve", "новост", "последние",
            "сегодня", "рынок", "уязвимост",
        ]
        needs_search = any(t in text_lower for t in search_triggers)

    add_to_context(uid, "USER", processed_text)
    response = await ask_cohere(uid, processed_text, use_search=needs_search,
                                dynamic_preamble=dynamic_preamble)
    add_to_context(uid, "CHATBOT", response)

    await send_safe_message(update.effective_chat, response)


# ─── JobQueue: Lesson Notifications ─────────────────────────────
async def check_upcoming_lessons(context: ContextTypes.DEFAULT_TYPE):
    """Periodic job: check for lessons starting in ~10 minutes, send notifications."""
    global _notified_lessons
    try:
        upcoming = await get_upcoming_lessons(minutes=10)
    except Exception as e:
        logger.error(f"JobQueue: Failed to check upcoming lessons: {e}")
        return

    for lesson in upcoming:
        key = (lesson["user_id"], lesson["id"])
        if key in _notified_lessons:
            continue  # Already notified

        uid = lesson["user_id"]
        subject = lesson["subject"]
        time_str = lesson["start_time"].strftime("%H:%M")
        url = lesson.get("url", "")

        # ── Message 1: System notification ──
        notification = (
            f"⏰ *Через 10 минут начнётся пара!*\n\n"
            f"📚 {subject}\n"
            f"🕐 Начало: {time_str}"
        )
        if url:
            notification += f"\n🔗 Ссылка: {url}"

        try:
            await context.bot.send_message(
                chat_id=uid, text=notification,
                parse_mode=ParseMode.MARKDOWN,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        except Exception as e:
            logger.error(f"JobQueue: Failed to send notification to {uid}: {e}")
            continue

        # ── Message 2: IT fact (silent generation) ──
        try:
            fact = await generate_fact(uid)
            await context.bot.send_message(
                chat_id=uid,
                text=f"💡 *IT-факт перед парой:*\n\n{fact}",
                parse_mode=ParseMode.MARKDOWN,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        except Exception as e:
            logger.error(f"JobQueue: Failed to generate/send fact to {uid}: {e}")

        _notified_lessons.add(key)

    # Clean up old entries (keep set from growing indefinitely)
    # Reset every day at midnight
    now = datetime.now()
    if now.hour == 0 and now.minute < 2:
        _notified_lessons.clear()


# ─── Application lifecycle ──────────────────────────────────────
async def post_init(application: Application):
    """Called after app is built — init DB and start JobQueue."""
    await init_db()
    logger.info("Database initialised via post_init")

    # Run check_upcoming_lessons every 60 seconds
    application.job_queue.run_repeating(
        check_upcoming_lessons,
        interval=60,
        first=10,  # first run after 10 seconds
        name="lesson_checker",
    )
    logger.info("JobQueue: lesson_checker started (every 60s)")


async def post_shutdown(application: Application):
    """Gracefully close DB pool on shutdown."""
    await close_db()
    logger.info("Database closed via post_shutdown")


# ─── Main ────────────────────────────────────────────────────────
def main():
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("menu", cmd_menu))
    app.add_handler(CommandHandler("news", cmd_news))
    app.add_handler(CommandHandler("study", cmd_study))
    app.add_handler(CommandHandler("cve", cmd_cve))
    app.add_handler(CommandHandler("log", cmd_log))
    app.add_handler(CommandHandler("schedule", cmd_schedule))
    app.add_handler(CommandHandler("randomfact", cmd_randomfact))
    app.add_handler(CommandHandler("clear", cmd_clear))

    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("Бот запущен!")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()