# -*- coding: utf-8 -*-
"""
Валидатор email-адресов.
Поддерживает одиночную и пакетную проверку, ведёт историю в JSON,
позволяет использовать кастомное регулярное выражение и проверять домен через DNS.
"""

import re
import json
import os
import socket
from datetime import datetime
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
    TK_AVAILABLE = True
except ImportError:
    TK_AVAILABLE = False

# ============================================================
# 1. ЭТАЛОННОЕ РЕГУЛЯРНОЕ ВЫРАЖЕНИЕ
# ============================================================
# Разберём паттерн по частям (с флагом re.VERBOSE — комментарии внутри):
EMAIL_PATTERN = re.compile(
    r"""
    ^                                  # начало строки
    (?P<local>                         # --- ЛОКАЛЬНАЯ ЧАСТЬ ---
        [A-Za-z0-9]                    # начинается с буквы или цифры
        [A-Za-z0-9._-]{0,63}           # далее буквы/цифры/точка/дефис/подчёркивание
    )
    @                                  # обязательный символ @
    (?P<domain>                        # --- ДОМЕННАЯ ЧАСТЬ ---
        [A-Za-z0-9]                    # начинается с буквы или цифры
        [A-Za-z0-9.-]{0,253}           # буквы, цифры, дефисы, точки
        \.                             # обязательная точка перед зоной
        (?P<tld>[A-Za-z]{2,6})         # зона: от 2 до 6 букв
    )
    $                                  # конец строки
    """,
    re.VERBOSE
)

# Дополнительные «узкие» паттерны для диагностики причин ошибки
RE_HAS_AT        = re.compile(r"@")
RE_LOCAL_OK      = re.compile(r"^[A-Za-z0-9._-]+$")
RE_DOMAIN_OK     = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$")
RE_TLD_OK        = re.compile(r"\.[A-Za-z]{2,6}$")

HISTORY_FILE = "history.json"


# ============================================================
# 2. ФУНКЦИИ ВАЛИДАЦИИ
# ============================================================
def validate_email(email: str, custom_pattern: re.Pattern | None = None) -> tuple[bool, str]:
    """
    Проверяет один email.
    Возвращает (is_valid, reason).
    Если передан custom_pattern — используется он вместо эталонного.
    """
    email = (email or "").strip()

    if not email:
        return False, "Пустая строка"

    # Если есть кастомный паттерн — используем его
    if custom_pattern is not None:
        if custom_pattern.fullmatch(email):
            return True, "Корректен (по пользовательскому regex)"
        return False, "Не соответствует пользовательскому regex"

    # Пошаговая диагностика
    if "@" not in email:
        return False, "Отсутствует символ '@'"
    if email.count("@") > 1:
        return False, "Более одного символа '@'"

    local, _, domain = email.partition("@")

    if not local:
        return False, "Пустая локальная часть (до @)"
    if not domain:
        return False, "Пустая доменная часть (после @)"

    if not RE_LOCAL_OK.match(local):
        return False, f"Недопустимые символы в локальной части: '{local}'"
    if local.startswith(".") or local.endswith("."):
        return False, "Локальная часть не может начинаться/заканчиваться точкой"

    if "." not in domain:
        return False, "В домене отсутствует точка"
    if not RE_DOMAIN_OK.match(domain):
        return False, f"Некорректное доменное имя: '{domain}'"
    if not RE_TLD_OK.search(domain):
        return False, "Зона домена должна состоять из 2–6 букв"

    if not EMAIL_PATTERN.match(email):
        return False, "Адрес не соответствует общему шаблону"

    return True, "Корректен"


def check_domain_dns(domain: str, timeout: float = 3.0) -> tuple[bool, str]:
    """Проверяет существование домена через DNS (опционально)."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True, f"Домен '{domain}' разрешается"
    except socket.gaierror:
        return False, f"Домен '{domain}' не найден в DNS"
    except OSError as e:
        return False, f"Ошибка DNS-запроса: {e}"


# ============================================================
# 3. РАБОТА С ФАЙЛАМИ И ИСТОРИЕЙ
# ============================================================
def load_history() -> list[dict]:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Не удалось прочитать историю: {e}")
        return []


def save_history(records: list[dict]) -> None:
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"[!] Не удалось сохранить историю: {e}")


def add_to_history(email: str, is_valid: bool, reason: str) -> None:
    records = load_history()
    records.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "email": email,
        "result": "корректен" if is_valid else "некорректен",
        "reason": reason,
    })
    # Ограничим историю последними 500 записями
    records = records[-500:]
    save_history(records)


def validate_file(input_path: str, output_path: str | None = None) -> None:
    """Пакетная проверка: читает файл, пишет отчёт."""
    if not os.path.exists(input_path):
        print(f"[!] Файл '{input_path}' не найден.")
        return

    if output_path is None:
        base = Path(input_path).stem
        output_path = f"{base}_results.txt"

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            emails = [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        # Фоллбэк на cp1251, если UTF-8 не подошёл
        try:
            with open(input_path, "r", encoding="cp1251") as f:
                emails = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"[!] Ошибка чтения файла: {e}")
            return
    except OSError as e:
        print(f"[!] Ошибка чтения файла: {e}")
        return

    if not emails:
        print("[!] Файл пуст.")
        return

    valid_count = 0
    try:
        with open(output_path, "w", encoding="utf-8") as out:
            out.write(f"Результаты проверки ({datetime.now():%Y-%m-%d %H:%M:%S})\n")
            out.write("=" * 60 + "\n")
            for email in emails:
                is_valid, reason = validate_email(email)
                mark = "КОРРЕКТЕН" if is_valid else "НЕКОРРЕКТЕН"
                line = f"{email:<40} | {mark}"
                if not is_valid:
                    line += f" — {reason}"
                out.write(line + "\n")
                add_to_history(email, is_valid, reason)
                if is_valid:
                    valid_count += 1
    except OSError as e:
        print(f"[!] Ошибка записи в '{output_path}': {e}")
        return

    print(f"\n✓ Обработано: {len(emails)}")
    print(f"  Корректных: {valid_count}")
    print(f"  Некорректных: {len(emails) - valid_count}")
    print(f"  Отчёт сохранён в: {output_path}")


# ============================================================
# 4. КОНСОЛЬНОЕ МЕНЮ
# ============================================================
def print_menu():
    print("\n" + "=" * 50)
    print("   ВАЛИДАТОР EMAIL-АДРЕСОВ")
    print("=" * 50)
    print(" 1 — Проверить один email")
    print(" 2 — Пакетная проверка из файла")
    print(" 3 — Проверка с кастомным regex")
    print(" 4 — Проверка домена через DNS")
    print(" 5 — Показать историю проверок")
    print(" 6 — Запустить GUI (tkinter)")
    print(" 0 — Выход")
    print("=" * 50)


def menu_single():
    email = input("\nВведите email для проверки: ").strip()
    if not email:
        print("[!] Пустой ввод.")
        return
    is_valid, reason = validate_email(email)
    print(f"\nРезультат: {'КОРРЕКТЕН ✓' if is_valid else 'НЕКОРРЕКТЕН ✗'}")
    if not is_valid:
        print(f"Причина: {reason}")
    add_to_history(email, is_valid, reason)


def menu_batch():
    path = input("\nПуть к файлу со списком email: ").strip()
    if not path:
        print("[!] Путь не указан.")
        return
    validate_file(path)


def menu_custom_regex():
    print("\nВведите регулярное выражение (используйте Python-синтаксис):")
    pattern_str = input("> ").strip()
    if not pattern_str:
        print("[!] Regex не задан.")
        return
    try:
        custom = re.compile(pattern_str)
    except re.error as e:
        print(f"[!] Ошибка в regex: {e}")
        return
    email = input("Введите email для проверки: ").strip()
    if not email:
        print("[!] Пустой ввод.")
        return
    is_valid, reason = validate_email(email, custom_pattern=custom)
    print(f"\nРезультат: {'КОРРЕКТЕН ✓' if is_valid else 'НЕКОРРЕКТЕН ✗'}")
    print(f"Комментарий: {reason}")
    add_to_history(email, is_valid, reason)


def menu_dns():
    email = input("\nВведите email для DNS-проверки: ").strip()
    if not email:
        print("[!] Пустой ввод.")
        return
    is_valid, reason = validate_email(email)
    print(f"Валидация формата: {'OK' if is_valid else reason}")
    if is_valid:
        domain = email.split("@", 1)[1]
        ok, msg = check_domain_dns(domain)
        print(f"DNS-проверка: {msg}")
    add_to_history(email, is_valid, reason)


def menu_history():
    records = load_history()
    if not records:
        print("\n[!] История пуста.")
        return
    print(f"\nПоследние {min(10, len(records))} проверок:")
    print("-" * 70)
    for r in records[-10:]:
        mark = "✓" if r["result"] == "корректен" else "✗"
        print(f"{r['time']}  {mark}  {r['email']}")
        if r["result"] != "корректен":
            print(f"           └─ {r['reason']}")
    print("-" * 70)


# ============================================================
# 5. ОПЦИОНАЛЬНО: GUI НА TKINTER
# ============================================================
def run_gui():
    if not TK_AVAILABLE:
        print("[!] tkinter недоступен в этой установке Python.")
        return

    root = tk.Tk()
    root.title("Email Validator")
    root.geometry("640x480")

    tk.Label(root, text="Email для проверки:", font=("Arial", 11)).pack(pady=(10, 2))
    entry = tk.Entry(root, width=50, font=("Arial", 11))
    entry.pack()

    out = scrolledtext.ScrolledText(root, height=18, font=("Consolas", 10))
    out.pack(fill="both", expand=True, padx=10, pady=10)

    def do_validate():
        email = entry.get().strip()
        if not email:
            messagebox.showwarning("Внимание", "Введите email")
            return
        is_valid, reason = validate_email(email)
        add_to_history(email, is_valid, reason)
        out.insert("end", f"[{datetime.now():%H:%M:%S}] {email} → ")
        if is_valid:
            out.insert("end", "КОРРЕКТЕН ✓\n")
        else:
            out.insert("end", f"НЕКОРРЕКТЕН ✗ ({reason})\n")
        out.see("end")
        entry.delete(0, "end")

    def do_file():
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if not path:
            return
        out.insert("end", f"\n--- Пакетная проверка: {path} ---\n")
        try:
            with open(path, "r", encoding="utf-8") as f:
                emails = [l.strip() for l in f if l.strip()]
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return
        for email in emails:
            is_valid, reason = validate_email(email)
            add_to_history(email, is_valid, reason)
            mark = "✓" if is_valid else f"✗ {reason}"
            out.insert("end", f"{email:<35} {mark}\n")
        out.see("end")

    btns = tk.Frame(root)
    btns.pack(pady=5)
    tk.Button(btns, text="Проверить email", command=do_validate, width=20).pack(side="left", padx=5)
    tk.Button(btns, text="Выбрать файл...", command=do_file, width=20).pack(side="left", padx=5)

    root.mainloop()


# ============================================================
# 6. ТОЧКА ВХОДА
# ============================================================
def main():
    while True:
        print_menu()
        choice = input("Ваш выбор: ").strip()

        if choice == "1":
            menu_single()
        elif choice == "2":
            menu_batch()
        elif choice == "3":
            menu_custom_regex()
        elif choice == "4":
            menu_dns()
        elif choice == "5":
            menu_history()
        elif choice == "6":
            run_gui()
        elif choice == "0":
            print("До свидания!")
            break
        else:
            print("[!] Неизвестный пункт меню.")


if __name__ == "__main__":
    main()