import sqlite3
import os
import hashlib
import os
import base64
import time
from cryptography.fernet import Fernet
from getpass import getpass
from tabulate import tabulate
from pyfiglet import Figlet

DB_FILE = "vault.db"
KEY_FILE = "vault.key"

MAX_ATTEMPTS = 3
BLOCK_TIME = 30 
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)

def load_key():
    with open(KEY_FILE, "rb") as f:
        return f.read()

def init_db():
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
            password_hash TEXT,
            salt BLOB
        )
    """)
    conn.commit()
    conn.close()

def generate_salt():
    return os.urandom(16)  # 16 байт соли

def set_master_password():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM master_password")
    if cursor.fetchone() is None:
        print("🚨 Важно: Запомните ваш мастер-пароль. Потеря пароля приведёт к невозможности доступа к данным!")
        password = getpass("Установите мастер-пароль: ")
        salt = generate_salt()
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)  # Хэширование с солью
        cursor.execute("INSERT INTO master_password (password_hash, salt) VALUES (?, ?)", (password_hash, base64.b64encode(salt).decode()))
        conn.commit()
        print("✅ Мастер-пароль успешно установлен!")
    conn.close()

def verify_master_password():
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        password = getpass("Введите мастер-пароль: ")

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM master_password WHERE id = 1")
        result = cursor.fetchone()
        stored_hash, salt = result
        salt = base64.b64decode(salt)  # Декодируем соль
        conn.close()

        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)  # Хэширование с солью

        if password_hash == stored_hash:
            return True
        else:
            attempts += 1
            print(f"❌ Неверный мастер-пароль! Осталось попыток: {MAX_ATTEMPTS - attempts}")

    print("🚨 Превышено максимальное количество попыток. Блокировка на 30 секунд.")
    time.sleep(BLOCK_TIME)  # Блокировка на 30 секунд
    return False

def encrypt_password(password):
    cipher = Fernet(load_key())
    return cipher.encrypt(password.encode())

def decrypt_password(encrypted_password):
    cipher = Fernet(load_key())
    return cipher.decrypt(encrypted_password).decode()

def add_entry():
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
    f = Figlet(font='slant')
    print(f.renderText('Password Vault'))

def menu():
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
    generate_key()
    init_db()
    set_master_password()
    banner()
    menu()

if __name__ == "__main__":
    main()

