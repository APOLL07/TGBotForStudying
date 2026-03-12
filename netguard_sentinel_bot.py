"""
NetGuard Sentinel — Telegram Bot v7.0 (Cohere + Tavily AI Search Edition)
Профессиональный RAG пайплайн для точного поиска.

Зависимости:
    pip install "python-telegram-bot==21.3" python-dotenv httpx tavily-python

Запуск:
    python netguard_sentinel_bot.py
"""

import os
import re
import logging
import httpx
from pathlib import Path
from dotenv import load_dotenv

# ── Загрузка переменных окружения ──────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

BOT_TOKEN  = os.getenv("BOT_TOKEN", "")
COHERE_KEY = os.getenv("COHERE_API_KEY", "")
TAVILY_KEY = os.getenv("TAVILY_API_KEY", "")

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

# Инициализация поискового клиента Tavily
try:
    from tavily import TavilyClient
    tavily_client = TavilyClient(api_key=TAVILY_KEY) if TAVILY_KEY else None
except ImportError:
    tavily_client = None

# ── Логирование ────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("NetGuardSentinel")

# ══════════════════════════════════════════════════════════════════════════════
# СИСТЕМНЫЙ ПРОМПТ
# ══════════════════════════════════════════════════════════════════════════════
SYSTEM_PROMPT = """Ты — NetGuard Sentinel, умный, профессиональный и универсальный ИИ-ассистент.

Твоя задача — помогать пользователю с любыми вопросами: программирование, кибербезопасность, математика, физика, языки, анализ логов, поиск информации в сети и общие темы.

ПРАВИЛА ОБЩЕНИЯ:
1. Отвечай нейтрально, профессионально, но дружелюбно.
2. Опирайся на предоставленный контекст при ответах на новостные или фактологические вопросы.
3. Помни весь контекст диалога.
4. Взлом и уязвимости обсуждаются исключительно в образовательных целях (white-hat).
5. Всегда используй Markdown для форматирования текста и кода."""

# ══════════════════════════════════════════════════════════════════════════════
# СОСТОЯНИЕ ПОЛЬЗОВАТЕЛЕЙ (in-memory)
# ══════════════════════════════════════════════════════════════════════════════
user_state: dict[int, dict] = {}
MAX_CONTEXT = 15

def get_state(uid: int) -> dict:
    if uid not in user_state:
        user_state[uid] = {"context": [], "menu": None, "subject": None}
    return user_state[uid]

def add_to_context(uid: int, role: str, text: str):
    state = get_state(uid)
    state["context"].append({"role": role, "text": text})
    if len(state["context"]) > MAX_CONTEXT * 2:
        state["context"] = state["context"][-MAX_CONTEXT * 2:]

# ══════════════════════════════════════════════════════════════════════════════
# БЕЗОПАСНАЯ ОТПРАВКА ДЛИННЫХ СООБЩЕНИЙ
# ══════════════════════════════════════════════════════════════════════════════

async def send_safe_message(chat, text: str, reply_markup=None):
    max_len = 3900 
    parts = [text[i:i+max_len] for i in range(0, len(text), max_len)]
    
    for i, part in enumerate(parts):
        markup = reply_markup if i == len(parts) - 1 else None
        try:
            await chat.send_message(part, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True, reply_markup=markup)
        except Exception as e:
            logger.warning(f"Markdown parse error: {e}")
            await chat.send_message(part, disable_web_page_preview=True, reply_markup=markup)

# ══════════════════════════════════════════════════════════════════════════════
# АНАЛИЗ ЛОГОВ
# ══════════════════════════════════════════════════════════════════════════════

def analyze_log(file_content: str) -> str:
    lines = file_content.splitlines()
    errors, warnings = [], []
    pat_err  = re.compile(r"\b(error|critical|fatal|exception|traceback|failed|failure)\b", re.I)
    pat_warn = re.compile(r"\b(warn(ing)?|deprecated|caution)\b", re.I)
    pat_cve  = re.compile(r"CVE-\d{4}-\d+", re.I)
    cves: set[str] = set()

    for ln in lines:
        for m in pat_cve.finditer(ln):
            cves.add(m.group().upper())
        if pat_err.search(ln):
            errors.append(ln.strip())
        elif pat_warn.search(ln):
            warnings.append(ln.strip())

    report = [f"📋 *Анализ лога* — {len(lines)} строк\n"]
    if errors:
        report.append(f"🔴 *Ошибки ({len(errors)}):*")
        report.extend(f"`{e[:120]}`" for e in errors[:10])
    if warnings:
        report.append(f"\n🟡 *Предупреждения ({len(warnings)}):*")
        report.extend(f"`{w[:120]}`" for w in warnings[:10])
    if cves:
        report.append(f"\n🚨 *Найдены CVE:* {', '.join(sorted(cves))}")
    if not errors and not warnings and not cves:
        report.append("✅ Критических проблем не обнаружено.")
    return "\n".join(report)

# ══════════════════════════════════════════════════════════════════════════════
# ПРЯМОЙ REST API ВЫЗОВ COHERE + TAVILY AI SEARCH
# ══════════════════════════════════════════════════════════════════════════════

async def ask_cohere(uid: int, user_message: str, use_search: bool = False) -> str:
    if not COHERE_KEY:
        return "⚠️ *Cohere API Key не задан*\nЗаполни файл `.env`"

    # 1. Если требуется поиск, гуглим через профессиональный Tavily API
    if use_search and tavily_client:
        try:
            logger.info(f"🔍 Ищу в Tavily: {user_message}")
            # Ищем информацию специально для AI
            search_result = tavily_client.search(query=user_message, search_depth="basic", max_results=3)
            
            if search_result and "results" in search_result:
                # Формируем чистый контекст
                search_context = ""
                for idx, res in enumerate(search_result["results"], 1):
                    search_context += f"[{idx}] {res['title']}\n{res['content']}\nИсточник: {res['url']}\n\n"
                
                # Обогащаем промпт
                user_message = (
                    f"ЗАПРОС ПОЛЬЗОВАТЕЛЯ: {user_message}\n\n"
                    f"Я нашел актуальные данные в интернете:\n{search_context}\n"
                    f"Используй ТОЛЬКО эти данные для составления актуального, подробного и структурированного ответа на русском языке. "
                    f"Обязательно ссылайся на источники (указывай [1], [2] и т.д.)."
                )
            else:
                user_message += "\n\n(Поиск не дал результатов. Ответь по своим знаниям)."
        except Exception as e:
            logger.error(f"Tavily Search error: {e}")
            user_message += "\n\n(Поисковик временно недоступен. Ответь по своим знаниям)."

    state = get_state(uid)
    
    # 2. Формируем историю диалога
    chat_history = []
    for msg in state["context"]:
        chat_history.append({
            "role": msg["role"],
            "message": msg["text"]
        })

    # 3. Формируем тело запроса для Cohere
    payload = {
        "model": "command-a-03-2025", 
        "message": user_message,
        "preamble": SYSTEM_PROMPT,
        "chat_history": chat_history,
        "temperature": 0.3,
    }

    url = "https://api.cohere.ai/v1/chat"
    headers = {
        "Authorization": f"Bearer {COHERE_KEY}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }

    # 4. Отправляем запрос в LLM
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            
            if response.status_code != 200:
                err_data = response.json()
                err_msg = err_data.get("message", response.text)
                return f"❌ Ошибка от Cohere (Код {response.status_code}):\n`{err_msg}`"
            
            data = response.json()
            return data["text"]
            
    except Exception as e:
        logger.error(f"Network error: {e}")
        return f"❌ Ошибка сети: Не удалось подключиться к Cohere.\n`{e}`"

# ══════════════════════════════════════════════════════════════════════════════
# КЛАВИАТУРЫ
# ══════════════════════════════════════════════════════════════════════════════

def main_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📰 Новости",    callback_data="menu_news"),
            InlineKeyboardButton("🎓 Обучение",   callback_data="menu_edu"),
        ],
        [
            InlineKeyboardButton("🛡️ CVE Поиск",   callback_data="menu_cve"),
            InlineKeyboardButton("📋 Анализ лога", callback_data="menu_log"),
        ],
        [InlineKeyboardButton("ℹ️ О боте", callback_data="menu_about")],
    ])

def news_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🤖 ИИ",       callback_data="news_ai"),
            InlineKeyboardButton("🌎 Политика",  callback_data="news_politics"),
            InlineKeyboardButton("🔬 Наука",     callback_data="news_science"),
        ],
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
    ])

def edu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📐 Математика", callback_data="edu_math"),
            InlineKeyboardButton("🍎 Физика",      callback_data="edu_physics"),
            InlineKeyboardButton("🇬🇧 Английский", callback_data="edu_english"),
        ],
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
    ])

def back_keyboard(target: str = "back_main") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("◀️ Назад", callback_data=target)]])

# ══════════════════════════════════════════════════════════════════════════════
# КОМАНДЫ
# ══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    name = update.effective_user.first_name or "Пользователь"
    state = get_state(uid)
    state.update({"menu": "main", "subject": None, "context": []})

    text = (
        f"👋 Привет, {name}! **NetGuard Sentinel v7.0** готов к работе.\n\n"
        f"🧠 ИИ Движок: {'✅ Cohere Command A' if COHERE_KEY else '❌ Не настроен'}\n"
        f"🌐 Модуль Поиска: {'✅ Tavily AI Search' if TAVILY_KEY else '❌ Отключен'}\n\n"
        "Выбери раздел ниже или просто отправь мне любой запрос в чат."
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu_keyboard())

async def cmd_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    state = get_state(uid)
    state["menu"] = "main"
    subj_map = {"math": "📐 Математика", "physics": "🍎 Физика", "english": "🇬🇧 Английский"}
    active = subj_map.get(state.get("subject"), "")
    active_str = f"\n_Активный фокус обучения: {active}_\n" if active else ""
    await update.message.reply_text(
        f"🏠 *Главное меню*{active_str}",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_menu_keyboard(),
    )

async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user_state.pop(update.effective_user.id, None)
    await update.message.reply_text("🗑️ Оперативная память очищена. Контекст диалога сброшен.", reply_markup=main_menu_keyboard())

async def cmd_search(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = " ".join(ctx.args)
    if not query:
        await update.message.reply_text("Использование: `/search <запрос>`", parse_mode=ParseMode.MARKDOWN)
        return
    await update.message.chat.send_action(ChatAction.TYPING)
    
    reply = await ask_cohere(update.effective_user.id, f"Найди в интернете актуальную информацию: {query}", use_search=True)
    await send_safe_message(update.effective_chat, f"🔍 *{query}*\n\n{reply}")

async def cmd_cve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    cve_id = " ".join(ctx.args).strip()
    if not cve_id:
        await update.message.reply_text("Использование: `/cve CVE-2024-XXXX`", parse_mode=ParseMode.MARKDOWN)
        return
    await update.message.chat.send_action(ChatAction.TYPING)

    reply = await ask_cohere(
        update.effective_user.id,
        f"Срочно найди свежую информацию об уязвимости {cve_id}. Суть, вектор атаки, CVSS и патчи.",
        use_search=True,
    )
    safe_id = cve_id.replace("_", "\\_")
    await send_safe_message(update.effective_chat, f"🚨 *{safe_id}*\n\n{reply}")

# ══════════════════════════════════════════════════════════════════════════════
# CALLBACK HANDLER
# ══════════════════════════════════════════════════════════════════════════════

NEWS_QUERIES = {
    "news_ai":       "Свежие новости про искусственный интеллект и нейросети за последние 24 часа",
    "news_politics": "Главные мировые политические новости сегодня",
    "news_science":  "Последние открытия в науке и технологиях",
}

EDU_SUBJECTS = {
    "edu_math":    ("math",    "📐 Математика",   "Выбрана *Математика*.\n\nНапиши «научи чему-то» или задай вопрос!"),
    "edu_physics": ("physics", "🍎 Физика",        "Выбрана *Физика*.\n\nНапиши «научи чему-то» или задай вопрос!"),
    "edu_english": ("english", "🇬🇧 Английский",  "Выбран *Английский*.\n\nНапиши «научи чему-то» или задай вопрос!"),
}

ABOUT_TEXT = (
    "🛡️ *NetGuard Sentinel v7.0*\n\n"
    "Универсальный ИИ-ассистент.\n\n"
    "*Движок:* Cohere Command A (03-2025)\n"
    "*Поиск:* Tavily Professional AI Search\n\n"
    "*Возможности:*\n"
    "• Веб-поиск в реальном времени\n"
    "• Анализ лог-файлов и уязвимостей\n"
    "• Обучение и ответы на вопросы\n\n"
    "*Команды:*\n"
    "`/start` `/menu` `/clear`\n"
    "`/search <запрос>` `/cve CVE-XXXX-XXXX`"
)

async def callback_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q     = update.callback_query
    await q.answer()
    data  = q.data
    uid   = q.from_user.id
    state = get_state(uid)

    if data in ("back_main", "menu_main"):
        state.update({"menu": "main", "subject": None})
        await q.edit_message_text("🏠 *Главное меню*", parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu_keyboard())

    elif data == "menu_news":
        state["menu"] = "news"
        await q.edit_message_text("📰 *Новости* — выбери категорию:", parse_mode=ParseMode.MARKDOWN, reply_markup=news_keyboard())

    elif data == "menu_edu":
        state["menu"] = "edu"
        await q.edit_message_text("🎓 *Обучение* — выбери предмет:", parse_mode=ParseMode.MARKDOWN, reply_markup=edu_keyboard())

    elif data == "menu_about":
        await q.edit_message_text(ABOUT_TEXT, parse_mode=ParseMode.MARKDOWN, reply_markup=back_keyboard())

    elif data == "menu_cve":
        await q.edit_message_text(
            "🚨 *CVE Поиск*\n\nОтправь команду: `/cve CVE-2024-12345`\nИли просто напиши название уязвимости в чат.",
            parse_mode=ParseMode.MARKDOWN, reply_markup=back_keyboard()
        )

    elif data == "menu_log":
        await q.edit_message_text(
            "📋 *Анализ лога*\n\nОтправь файл (.txt / .log / .py) или вставь текст в чат с префиксом `LOG:`",
            parse_mode=ParseMode.MARKDOWN, reply_markup=back_keyboard()
        )

    elif data in NEWS_QUERIES:
        title = NEWS_QUERIES[data]
        short_title = "ИИ" if "ai" in data else "Политика" if "politics" in data else "Наука"
        
        await q.edit_message_text(f"⏳ Ищу реальные статьи через Tavily: {short_title}...", parse_mode=ParseMode.MARKDOWN, reply_markup=None)
        
        user_prompt = f'Сделай краткий дайджест новостей по теме: {title}. Выдели 4-5 ключевых пунктов.'
        digest = await ask_cohere(uid, user_prompt, use_search=True)

        add_to_context(uid, "USER", user_prompt)
        add_to_context(uid, "CHATBOT", digest)

        await send_safe_message(update.effective_chat, f"*{short_title}*\n\n{digest}")
        await q.delete_message()

    elif data in EDU_SUBJECTS:
        subj_key, subj_title, subj_msg = EDU_SUBJECTS[data]
        state.update({"subject": subj_key, "menu": "edu_active"})
        
        await q.delete_message()
        await update.effective_chat.send_message(
            f"*{subj_title}* — модуль активирован\n\n"
            f"Напиши *«научи чему-то»* или задай любой вопрос. Я готов.\n\n"
            f"_/menu — вернуться в главное меню_",
            parse_mode=ParseMode.MARKDOWN,
        )

# ══════════════════════════════════════════════════════════════════════════════
# ОБРАБОТЧИКИ СООБЩЕНИЙ
# ══════════════════════════════════════════════════════════════════════════════

async def handle_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc:
        return
    if doc.file_size > 500_000:
        await update.message.reply_text("⚠️ Файл слишком большой (макс. 500 КБ).")
        return
    
    await update.message.chat.send_action(ChatAction.TYPING)
    file  = await ctx.bot.get_file(doc.file_id)
    raw   = await file.download_as_bytearray()
    content = raw.decode("utf-8", errors="replace")

    static  = analyze_log(content)
    cohere_reply  = await ask_cohere(
        update.effective_user.id,
        f"Проанализируй этот лог/код, найди критические ошибки или проблемы и предложи конкретные решения:\n\n{content[:3500]}",
        use_search=False
    )
    full = f"{static}\n\n🤖 *Глубокий анализ:*\n{cohere_reply}"
    await send_safe_message(update.effective_chat, full)

async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid   = update.effective_user.id
    text  = update.message.text.strip()
    state = get_state(uid)

    if text.upper().startswith("LOG:"):
        await update.message.reply_text(analyze_log(text[4:]), parse_mode=ParseMode.MARKDOWN)
        return

    await update.message.chat.send_action(ChatAction.TYPING)

    search_triggers = [
        "найди", "поищи", "cve", "уязвимост", "новост", "последние", "свежи", 
        "что такое", "кто такой", "что случилось", "значит", "повлияет", "экономик", "рынок"
    ]
    needs_search = any(t in text.lower() for t in search_triggers)

    teach_triggers = ["научи чему-то", "научи меня", "расскажи что-нибудь", "дай тему", "выбери тему"]
    if any(t in text.lower() for t in teach_triggers):
        subj = state.get("subject")
        prompts = {
            "math":    "Выбери интересную тему по математике и объясни от простого к сложному. В конце: 3-5 вопросов и 1 задача.",
            "physics": "Выбери интересную тему по физике и объясни от простого к сложному. В конце: 3-5 вопросов и 1 задача.",
            "english": "Выбери тему по английскому языку и объясни от простого к сложному. В конце: 3-5 вопросов.",
            None:      "Выбери интересную техническую или научную тему и проведи подробный урок от простого к сложному. В конце: вопросы и задача."
        }
        text = prompts.get(subj, prompts[None])

    subj_map = {"math": "Математика", "physics": "Физика", "english": "Английский"}
    active_subj = subj_map.get(state.get("subject"), "")
    context_hint = f"[Обучение: {active_subj}]\n{text}" if active_subj else text

    add_to_context(uid, "USER", context_hint)
    
    response = await ask_cohere(uid, context_hint, use_search=needs_search)
    
    add_to_context(uid, "CHATBOT", response)

    hint = "\n\n_/menu — открыть меню_" if len(state["context"]) <= 2 else ""
    await send_safe_message(update.effective_chat, response + hint)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not BOT_TOKEN or "ВСТАВЬ" in BOT_TOKEN:
        logger.error("❌ BOT_TOKEN не задан! Открой .env и вставь токен.")
        return

    logger.info("🚀 NetGuard Sentinel v7.0 (Cohere + Tavily) запускается...")
    
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("menu",   cmd_menu))
    app.add_handler(CommandHandler("clear",  cmd_clear))
    app.add_handler(CommandHandler("search", cmd_search))
    app.add_handler(CommandHandler("cve",    cmd_cve))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()