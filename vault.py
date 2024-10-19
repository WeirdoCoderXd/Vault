import sqlite3
import os
import hashlib
from cryptography.fernet import Fernet
from getpass import getpass
from tabulate import tabulate
from pyfiglet import Figlet

DB_FILE = "vault.db"
KEY_FILE = "vault.key"

def generate_key():
    """Создаёт и сохраняет ключ шифрования, если его ещё нет."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)

def load_key():
    """Загружает ключ шифрования из файла."""
    with open(KEY_FILE, "rb") as f:
        return f.read()

def init_db():
    """Создаёт таблицу для паролей и мастер-пароля, если они отсутствуют."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT,
            username TEXT,
            password BLOB
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            password_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

def set_master_password():
    """Устанавливает мастер-пароль при первом запуске."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM master_password")
    if cursor.fetchone() is None:
        print("🚨 Важно: Запомните ваш мастер-пароль. Потеря пароля приведёт к невозможности доступа к данным!")
        password = getpass("Установите мастер-пароль: ")
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("INSERT INTO master_password (password_hash) VALUES (?)", (password_hash,))
        conn.commit()
        print("✅ Мастер-пароль успешно установлен!")
    conn.close()

def verify_master_password():
    """Проверяет введённый мастер-пароль."""
    password = getpass("Введите мастер-пароль: ")
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM master_password WHERE id = 1")
    stored_hash = cursor.fetchone()[0]
    conn.close()

    if password_hash == stored_hash:
        return True
    else:
        print("❌ Неверный мастер-пароль!")
        return False

def encrypt_password(password):
    """Шифрует пароль."""
    cipher = Fernet(load_key())
    return cipher.encrypt(password.encode())

def decrypt_password(encrypted_password):
    """Расшифровывает пароль."""
    cipher = Fernet(load_key())
    return cipher.decrypt(encrypted_password).decode()

def add_entry():
    """Добавляет запись в хранилище."""
    service = input("Введите название сервиса: ")
    username = input("Введите логин: ")
    password = getpass("Введите пароль: ")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vault (service, username, password) 
        VALUES (?, ?, ?)
    """, (service, username, encrypt_password(password)))
    conn.commit()
    conn.close()
    print("✅ Запись успешно добавлена!")

def list_entries():
    """Выводит все записи."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username FROM vault")
    entries = cursor.fetchall()
    conn.close()

    if entries:
        print(tabulate(entries, headers=["ID", "Сервис", "Логин"], tablefmt="fancy_grid"))
    else:
        print("📋 Хранилище пусто.")

def view_password():
    """Отображает пароль для указанной записи (после проверки мастер-пароля)."""
    if not verify_master_password():
        return

    entry_id = input("Введите ID записи: ")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM vault WHERE id = ?", (entry_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        print(f"🔑 Пароль: {decrypt_password(result[0])}")
    else:
        print("❌ Запись не найдена.")

def delete_entry():
    """Удаляет запись по ID."""
    entry_id = input("Введите ID записи для удаления: ")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    print("🗑️ Запись удалена!")

def banner():
    """Отображает баннер."""
    f = Figlet(font='slant')
    print(f.renderText('Password Vault'))

def menu():
    """Главное меню."""
    while True:
        print("\n1. Добавить запись")
        print("2. Показать все записи")
        print("3. Показать пароль")
        print("4. Удалить запись")
        print("5. Выйти")

        choice = input("Выберите действие: ")

        if choice == "1":
            add_entry()
        elif choice == "2":
            list_entries()
        elif choice == "3":
            view_password()
        elif choice == "4":
            delete_entry()
        elif choice == "5":
            print("До свидания!")
            break
        else:
            print("❌ Неверный выбор, попробуйте снова.")

def main():
    """Основная функция."""
    generate_key()
    init_db()
    set_master_password()
    banner()
    menu()

if __name__ == "__main__":
    main()
