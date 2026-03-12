import os
import re
import logging
import httpx
import random
from datetime import datetime
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

SYSTEM_PROMPT = """Ты — NetGuard Sentinel, умный, профессиональный и универсальный ИИ-ассистент.

ПРАВИЛА ОБЩЕНИЯ:
1. Отвечай профессионально и по делу.
2. Если пользователь просит уточнить детали новости или предыдущего ответа — ищи ответы СТРОГО в истории чата.
3. НЕ используй сложный LaTeX! Вместо \mathbf{F} пиши просто F. Степени пиши юникодом (например 10³, а не 10^3). Дроби пиши через слэш (a/b)."""

user_state: dict[int, dict] = {}
MAX_CONTEXT = 20 

def get_state(uid: int) -> dict:
    if uid not in user_state:
        user_state[uid] = {"context": [], "menu": None, "subject": None}
    return user_state[uid]

def add_to_context(uid: int, role: str, text: str):
    state = get_state(uid)
    state["context"].append({"role": role, "text": text})
    if len(state["context"]) > MAX_CONTEXT * 2:
        state["context"] = state["context"][-MAX_CONTEXT * 2:]
    while sum(len(msg["text"]) for msg in state["context"]) > 30000 and len(state["context"]) > 1:
        state["context"].pop(0)

# --- УЛУЧШЕННЫЙ ПАРСЕР ТЕКСТА ---
SUPERSCRIPTS = str.maketrans("-0123456789", "⁻⁰¹²³⁴⁵⁶⁷⁸⁹")

def replace_power_braces(match):
    # Переводит ^{...} в надстрочные символы
    return match.group(1).translate(SUPERSCRIPTS)

def clean_bot_response(text: str) -> str:
    # Удаляем математические скобки
    text = text.replace(r'\[', '').replace(r'\]', '')
    text = text.replace(r'\(', '').replace(r'\)', '')
    text = text.replace(r'$$', '').replace(r'$', '')
    text = text.replace(r'\,', ' ') # Удаляем пробелы LaTeX
    text = text.replace(r'\;', ' ')
    
    # Дроби и базовые операторы
    text = re.sub(r'\\frac\{([^}]+)\}\{([^}]+)\}', r'(\1)/(\2)', text)
    text = re.sub(r'\\mathbf\{([^}]+)\}', r'\1', text)
    text = re.sub(r'\\text\{([^}]+)\}', r'\1', text)
    text = re.sub(r'\\sqrt\{([^}]+)\}', r'√(\1)', text)
    text = text.replace(r'\times', '×').replace(r'\cdot', '·')
    
    # ПЕРЕВОД СТЕПЕНЕЙ В ЮНИКОД (Например: 10^{-3} -> 10⁻³)
    text = re.sub(r'\^\{([^}]+)\}', replace_power_braces, text)
    text = re.sub(r'\^(-?\d+)', replace_power_braces, text) # Для форматов ^2 или ^-3
    
    # Markdown исправления заголовков
    text = re.sub(r'^###\s+(.+)$', r'*\1*', text, flags=re.MULTILINE)
    text = re.sub(r'^##\s+(.+)$', r'*\1*', text, flags=re.MULTILINE)
    text = re.sub(r'^#\s+(.+)$', r'*\1*', text, flags=re.MULTILINE)
    text = text.replace('***', '*').replace('* **', '*').replace('** *', '*')
    text = text.replace('**', '*') 
    
    return text.strip()

async def send_safe_message(chat, text: str, reply_markup=None):
    max_len = 3900 
    parts = []
    current_part = ""
    for paragraph in text.split("\n\n"):
        if len(current_part) + len(paragraph) + 2 <= max_len:
            current_part += paragraph + "\n\n"
        else:
            if current_part: parts.append(current_part.strip())
            if len(paragraph) > max_len:
                for i in range(0, len(paragraph), max_len): parts.append(paragraph[i:i+max_len])
                current_part = ""
            else:
                current_part = paragraph + "\n\n"
    if current_part: parts.append(current_part.strip())
        
    for i, part in enumerate(parts):
        markup = reply_markup if i == len(parts) - 1 else None
        try:
            await chat.send_message(part, parse_mode=ParseMode.MARKDOWN, link_preview_options=LinkPreviewOptions(is_disabled=True), reply_markup=markup)
        except Exception as e:
            logger.warning(f"Markdown parse error: {e}")
            await chat.send_message(part, link_preview_options=LinkPreviewOptions(is_disabled=True), reply_markup=markup)

async def ask_cohere(uid: int, user_message: str, use_search: bool = False, explicit_search_query: str = None) -> str:
    if not COHERE_KEY: return "⚠️ *Cohere API Key не задан*"

    state = get_state(uid)

    if use_search and tavily_client:
        try:
            search_query = explicit_search_query if explicit_search_query else user_message
            logger.info(f"🔍 Ищу в Tavily: {search_query}")
            
            # Установили days=2, чтобы искать только самое свежее
            search_result = await tavily_client.search(query=search_query, topic="news", days=2, max_results=5)
            
            if search_result and "results" in search_result and len(search_result["results"]) > 0:
                search_context = ""
                for idx, res in enumerate(search_result["results"], 1):
                    search_context += f"[{idx}] {res.get('title', '')}\n{res.get('content', '')}\nURL: {res.get('url', '')}\n\n"
                
                user_message = (
                    f"ЗАПРОС ПОЛЬЗОВАТЕЛЯ: {user_message}\n\n"
                    f"ДАННЫЕ ИЗ ПОИСКОВИКА (НОВЫЕ СТАТЬИ):\n{search_context}\n"
                    f"ИНСТРУКЦИЯ: \n"
                    f"Сделай ответ на основе этих данных. Если в истории чата мы уже обсуждали какую-то из этих новостей, выбери ДРУГУЮ новость из списка, чтобы не повторяться."
                )
        except Exception as e:
            logger.error(f"Tavily Search error: {e}")

    chat_history = [{"role": msg["role"], "message": msg["text"]} for msg in state["context"]]

    payload = {
        "model": "command-a-03-2025", 
        "message": user_message,
        "preamble": SYSTEM_PROMPT,
        "chat_history": chat_history,
        "temperature": 0.4, # Слегка подняли температуру для большего разнообразия
    }

    url = "https://api.cohere.ai/v1/chat"
    headers = {"Authorization": f"Bearer {COHERE_KEY}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code != 200: return f"❌ Ошибка API: {response.text}"
            return clean_bot_response(response.json()["text"])
    except Exception as e:
        return f"❌ Ошибка сети: {e}"

# --- Клавиатуры ---
def main_menu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📰 Новости", callback_data="menu_news"), InlineKeyboardButton("🎓 Обучение", callback_data="menu_edu")],
        [InlineKeyboardButton("🛡️ CVE Поиск", callback_data="menu_cve"), InlineKeyboardButton("📋 Анализ лога", callback_data="menu_log")],
        [InlineKeyboardButton("ℹ️ О боте", callback_data="menu_about")],
    ])

def news_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🤖 ИИ", callback_data="news_ai"), InlineKeyboardButton("🌎 Политика", callback_data="news_politics"), InlineKeyboardButton("🔬 Наука", callback_data="news_science")],
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
    ])

def edu_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📐 Математика", callback_data="edu_math"), InlineKeyboardButton("🍎 Физика", callback_data="edu_physics"), InlineKeyboardButton("🇬🇧 Английский", callback_data="edu_english")],
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
    ])

# --- Команды ---
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    name = update.effective_user.first_name or "Пользователь"
    get_state(uid).update({"menu": "main", "subject": None, "context": []})
    await update.message.reply_text(f"👋 Привет, {name}! **NetGuard Sentinel v7.0** готов.\n\nВыбери раздел ниже.", parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu_keyboard())

async def cmd_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    get_state(update.effective_user.id)["menu"] = "main"
    await update.message.reply_text("🏠 *Главное меню*", parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu_keyboard())

async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user_state.pop(update.effective_user.id, None)
    await update.message.reply_text("🗑️ Оперативная память очищена. Контекст сброшен.", reply_markup=main_menu_keyboard())

# --- Обработчик кнопок ---
NEWS_CATEGORIES = {
    "news_ai": ("ИИ", ["ИИ прорыв", "LLM релизы", "нейросети стартапы", "ChatGPT конкуренты", "искусственный интеллект технологии"]),
    "news_politics": ("Политика", ["мировая политика", "геополитика конфликты", "международные отношения решения", "выборы в мире"]),
    "news_science": ("Наука", ["научные открытия космос", "физика квантовые технологии", "биотехнологии прорыв", "астрономия новые планеты"])
}
EDU_SUBJECTS = {"edu_math": ("math", "📐 Математика"), "edu_physics": ("physics", "🍎 Физика"), "edu_english": ("english", "🇬🇧 Английский")}

async def callback_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = q.from_user.id
    state = get_state(uid)

    if q.data in ("back_main", "menu_main"):
        state.update({"menu": "main", "subject": None})
        await q.edit_message_text("🏠 *Главное меню*", parse_mode=ParseMode.MARKDOWN, reply_markup=main_menu_keyboard())

    elif q.data == "menu_news":
        await q.edit_message_text("📰 *Новости* — выбери категорию:", parse_mode=ParseMode.MARKDOWN, reply_markup=news_keyboard())

    elif q.data == "menu_edu":
        await q.edit_message_text("🎓 *Обучение* — выбери предмет:", parse_mode=ParseMode.MARKDOWN, reply_markup=edu_keyboard())

    elif q.data in NEWS_CATEGORIES:
        short_title, search_terms = NEWS_CATEGORIES[q.data]
        await q.edit_message_text(f"⏳ Ищу актуальные статьи: {short_title}...", parse_mode=ParseMode.MARKDOWN)
        
        # АНТИ-КЭШ: Берем случайную подтему + добавляем текущие ЧАСЫ, МИНУТЫ И СЕКУНДЫ
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        tavily_query = f"{random.choice(search_terms)} новости {now_str}"
        
        user_prompt = f"Сделай дайджест последних новостей по теме: {short_title}. Расскажи о 3-4 абсолютно новых событиях, о которых мы еще не говорили."
        
        digest = await ask_cohere(uid, user_prompt, use_search=True, explicit_search_query=tavily_query)

        add_to_context(uid, "USER", f"Покажи новости: {short_title}")
        add_to_context(uid, "CHATBOT", digest)

        await send_safe_message(update.effective_chat, f"*{short_title}*\n\n{digest}")
        await q.delete_message()

    elif q.data in EDU_SUBJECTS:
        subj_key, subj_title = EDU_SUBJECTS[q.data]
        state.update({"subject": subj_key, "menu": "edu_active"})
        await q.delete_message()
        await update.effective_chat.send_message(f"*{subj_title}* активирована.\nБот переведен в режим узкого специалиста. Задай вопрос!", parse_mode=ParseMode.MARKDOWN)

# --- Обработчик текста ---
async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid, text = update.effective_user.id, update.message.text.strip()
    state = get_state(uid)

    await update.message.chat.send_action(ChatAction.TYPING)

    # ЖЕСТКИЙ РОЛЕВОЙ ПРОМПТ ДЛЯ ПРЕДМЕТОВ
    active_subj = state.get("subject")
    if active_subj:
        subject_names = {"math": "Математики", "physics": "Физики", "english": "Английского языка"}
        subj_ru = subject_names[active_subj]
        
        teach_triggers = ["научи", "расскажи", "дай тему", "интересно"]
        if any(t in text.lower() for t in teach_triggers):
            text = f"Расскажи интересную и полезную концепцию или факт. В конце дай задачу или вопрос для проверки."
            
        # Оборачиваем запрос пользователя в жесткую системную команду
        processed_text = f"[СИСТЕМНОЕ ПРАВИЛО: Ты профессиональный репетитор {subj_ru}. Отвечай ИСКЛЮЧИТЕЛЬНО в рамках этого предмета. Игнорируй другие науки или ИИ.]\nЗапрос ученика: {text}"
    else:
        processed_text = text

    # Если мы просим рассказать подробнее про пункт (относится к памяти)
    history_triggers = ["про первую", "про 1", "про вторую", "про 2", "подробнее про", "что за", "почему"]
    is_follow_up = any(t in text.lower() for t in history_triggers)

    needs_search = False
    if not is_follow_up and not active_subj: # Если активирован предмет, гугл обычно не нужен (если только это не исторический факт, но мы обучаем)
        search_triggers = ["найди", "поищи", "cve", "новост", "последние", "сегодня", "рынок"]
        needs_search = any(t in text.lower() for t in search_triggers)

    add_to_context(uid, "USER", processed_text)
    response = await ask_cohere(uid, processed_text, use_search=needs_search)
    add_to_context(uid, "CHATBOT", response)

    await send_safe_message(update.effective_chat, response)

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("menu", cmd_menu))
    app.add_handler(CommandHandler("clear", cmd_clear))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()