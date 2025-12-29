#!/usr/bin/env python3
"""
PixelEncoder v3.1

Исправления:
✅ Автогенерация пароля при пустом вводе
✅ Лимит MAX_ITERATIONS (защита от зависания)
✅ Улучшенный вывод сгенерированного пароля
"""

import math
import struct
import secrets
import sys
import os
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from typing import Tuple, Optional

# ══════════════════════════════════════════════════════════════
#                    КОНСТАНТЫ БЕЗОПАСНОСТИ
# ══════════════════════════════════════════════════════════════

SALT_SIZE = 16              
NONCE_SIZE = 12             
KEY_SIZE = 32               
MIN_ITERATIONS = 200_000
MAX_ITERATIONS = 5_000_000  # ~15-30 сек, защита от зависания
DEFAULT_ITERATIONS = 200_000
FORMAT_VERSION = 3
MAX_PADDING = 256           

# ══════════════════════════════════════════════════════════════
#                    КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ
# ══════════════════════════════════════════════════════════════

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Генерация ключа с переменным числом итераций."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_data(data: bytes, password: str, extension: str, iterations: int) -> bytes:
    """
    Шифрование данных + расширения файла.
    """
    ext_bytes = extension.encode('utf-8')
    if len(ext_bytes) > 255:
        ext_bytes = ext_bytes[:255]
    
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt, iterations)
    
    padding_size = secrets.randbelow(MAX_PADDING)
    
    inner_data = (
        struct.pack('<B', len(ext_bytes)) +
        ext_bytes +
        struct.pack('<I', len(data)) +
        data + 
        secrets.token_bytes(padding_size)
    )
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, inner_data, None)
    
    return (
        struct.pack('<B', FORMAT_VERSION) +
        struct.pack('<I', iterations) +
        salt +
        nonce +
        struct.pack('<I', len(ciphertext)) +
        ciphertext
    )


def decrypt_data(encrypted: bytes, password: str) -> Tuple[Optional[bytes], str, Optional[str]]:
    """
    Возвращает: (данные, расширение_файла, ошибка)
    """
    min_size = 1 + 4 + SALT_SIZE + NONCE_SIZE + 4 + 16
    if len(encrypted) < min_size:
        return None, "", "Данные слишком короткие или повреждены"
    
    offset = 0
    version = encrypted[offset]; offset += 1
    
    if version != FORMAT_VERSION:
        return None, "", f"Версия формата ({version}) не поддерживается (нужна v{FORMAT_VERSION})."
    
    iterations = struct.unpack('<I', encrypted[offset:offset+4])[0]; offset += 4
    salt = encrypted[offset:offset + SALT_SIZE]; offset += SALT_SIZE
    nonce = encrypted[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
    ciphertext_len = struct.unpack('<I', encrypted[offset:offset + 4])[0]; offset += 4
    
    if offset + ciphertext_len > len(encrypted):
        return None, "", "Повреждённый заголовок: длина данных не совпадает."
    
    ciphertext = encrypted[offset:offset + ciphertext_len]
    key = derive_key(password, salt, iterations)
    
    try:
        aesgcm = AESGCM(key)
        inner_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        ptr = 0
        ext_len = inner_data[ptr]; ptr += 1
        extension = inner_data[ptr:ptr+ext_len].decode('utf-8'); ptr += ext_len
        data_len = struct.unpack('<I', inner_data[ptr:ptr+4])[0]; ptr += 4
        
        if len(inner_data) < ptr + data_len:
            return None, "", "Ошибка целостности внутренней структуры."
            
        final_data = inner_data[ptr:ptr+data_len]
        return final_data, extension, None
        
    except Exception:
        return None, "", "Неверный пароль или данные повреждены."


# ══════════════════════════════════════════════════════════════
#                    РАБОТА С ИЗОБРАЖЕНИЯМИ
# ══════════════════════════════════════════════════════════════

def encode_data_to_image(data_bytes: bytes, password: str, extension: str, iterations: int, output_filename: str):
    print(f"🔐 Генерация ключа ({iterations:,} итераций)...")
    encrypted = encrypt_data(data_bytes, password, extension, iterations)
    
    total_bytes = len(encrypted)
    required_pixels = math.ceil(total_bytes / 3)
    side = int(math.ceil(math.sqrt(required_pixels)))
    
    if side > 2000:
        print(f"⚠️  Внимание: размер {side}x{side} может сжиматься мессенджерами!")
    
    padding_size = side * side * 3 - total_bytes
    full_data = encrypted + secrets.token_bytes(padding_size)
    
    pixels = [
        (full_data[i], full_data[i+1], full_data[i+2]) 
        for i in range(0, len(full_data), 3)
    ]
    
    img = Image.new('RGB', (side, side))
    img.putdata(pixels)
    img.save(output_filename, "PNG", compress_level=9)
    
    print(f"✅ Успешно! Файл сохранён: {output_filename}")
    print(f"   Размер: {side}×{side} px | Данные: {len(data_bytes):,} байт")


def decode_data_from_image(image_path: str, password: str) -> Tuple[Optional[bytes], str, Optional[str]]:
    try:
        img = Image.open(image_path).convert('RGB')
    except Exception as e:
        return None, "", f"Ошибка открытия: {e}"
    
    raw_bytes = bytearray()
    for pixel in img.getdata():
        raw_bytes.extend(pixel[:3])
    
    print("🔐 Расшифровка...")
    return decrypt_data(bytes(raw_bytes), password)


# ══════════════════════════════════════════════════════════════
#                    ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ══════════════════════════════════════════════════════════════

def generate_password(length: int = 20) -> str:
    """Генерация криптографически стойкого пароля."""
    return secrets.token_urlsafe(length)


def get_password(for_encryption: bool = True) -> str:
    """
    Запрос пароля с опцией автогенерации.
    
    Args:
        for_encryption: True = шифрование (можно генерировать), 
                       False = расшифровка (нужен существующий)
    """
    if for_encryption:
        prompt = "🔑 Пароль (Enter = сгенерировать случайный): "
    else:
        prompt = "🔑 Пароль: "
    
    password = input(prompt).strip()
    
    if not password:
        if for_encryption:
            # Генерируем случайный пароль
            password = generate_password()
            print()
            print("   ╔════════════════════════════════════════════╗")
            print(f"   ║  СГЕНЕРИРОВАННЫЙ ПАРОЛЬ:                   ║")
            print(f"   ║  {password:<40} ║")
            print("   ╠════════════════════════════════════════════╣")
            print("   ║  ⚠️  СОХРАНИТЕ ЕГО! Восстановить нельзя!   ║")
            print("   ╚════════════════════════════════════════════╝")
            print()
        else:
            # Для расшифровки пустой пароль недопустим
            print("❌ Пароль не может быть пустым!")
            return ""
    
    return password


def get_iterations() -> int:
    """Запрос итераций с валидацией."""
    print(f"\n⚙️  Итерации PBKDF2 (Enter = {DEFAULT_ITERATIONS:,}):")
    print(f"   Диапазон: {MIN_ITERATIONS:,} — {MAX_ITERATIONS:,}")
    val = input("   Ввод: ").strip()
    
    if not val:
        return DEFAULT_ITERATIONS
    
    try:
        iters = int(val.replace('_', '').replace(' ', '').replace(',', ''))
        
        if iters < MIN_ITERATIONS:
            print(f"   ⚠️  Минимум {MIN_ITERATIONS:,}. Установлено: {MIN_ITERATIONS:,}")
            return MIN_ITERATIONS
        
        if iters > MAX_ITERATIONS:
            print(f"   ⚠️  Максимум {MAX_ITERATIONS:,}. Установлено: {MAX_ITERATIONS:,}")
            return MAX_ITERATIONS
        
        return iters
        
    except ValueError:
        print(f"   ⚠️  Ошибка ввода. Используется: {DEFAULT_ITERATIONS:,}")
        return DEFAULT_ITERATIONS


def pause_exit(code: int = 0):
    """Пауза перед выходом для .exe"""
    print("\n" + "═" * 45)
    input("Нажмите Enter для выхода...")
    sys.exit(code)


# ══════════════════════════════════════════════════════════════
#                    ГЛАВНЫЙ ИНТЕРФЕЙС
# ══════════════════════════════════════════════════════════════

def main():
    try:
        print("═" * 55)
        print("  🔒 PixelEncoder v3.1")
        print("     AES-256-GCM │ PBKDF2 │ Auto-Extension")
        print("═" * 55)
        
        print("\n[1] Закодировать данные в картинку")
        print("[2] Раскодировать данные из картинки")
        mode = input("\nВыбор: ").strip()

        if mode == "1":
            # ═══════════════════════════════════════════
            #              КОДИРОВАНИЕ
            # ═══════════════════════════════════════════
            print("\n┌─ Тип данных ─────────────────┐")
            print("│ [1] Текст                    │")
            print("│ [2] Файл (любой)             │")
            print("└──────────────────────────────┘")
            type_choice = input("Выбор: ").strip()
            
            data = b""
            extension = ""
            
            if type_choice == "2":
                file_path = input("\n📁 Перетащите файл сюда: ").strip().strip('"\'')
                
                if not os.path.exists(file_path):
                    print("❌ Файл не найден!")
                    pause_exit(1)
                
                _, extension = os.path.splitext(file_path)
                
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                print(f"   ✓ Загружен: {os.path.basename(file_path)}")
                print(f"   ✓ Размер: {len(data):,} байт")
                print(f"   ✓ Расширение: {extension if extension else '(нет)'}")
            else:
                text = input("\n📝 Введите текст: ")
                data = text.encode('utf-8')
                extension = ".txt"
                print(f"   ✓ Размер: {len(data):,} байт")

            # Запрос пароля (с автогенерацией)
            print()
            password = get_password(for_encryption=True)
            if not password:
                pause_exit(1)

            # Запрос итераций
            iters = get_iterations()
            
            # Имя выходного файла
            out_name = input("\n💾 Имя картинки (Enter = encoded.png): ").strip()
            if not out_name:
                out_name = "encoded.png"
            if not out_name.lower().endswith('.png'):
                out_name += '.png'
            
            print()
            encode_data_to_image(data, password, extension, iters, out_name)

        elif mode == "2":
            # ═══════════════════════════════════════════
            #              ДЕКОДИРОВАНИЕ
            # ═══════════════════════════════════════════
            path = input("\n🖼️  Перетащите картинку сюда: ").strip().strip('"\'')
            
            if not os.path.exists(path):
                print("❌ Файл не найден!")
                pause_exit(1)

            password = get_password(for_encryption=False)
            if not password:
                pause_exit(1)
            
            content, ext, error = decode_data_from_image(path, password)
            
            if error:
                print(f"\n❌ ОШИБКА: {error}")
                pause_exit(1)
            
            print(f"\n✅ Расшифровано успешно!")
            print(f"   Размер: {len(content):,} байт")
            print(f"   Тип: {ext if ext else 'неизвестно'}")
            
            print("\n┌─ Что делать с данными? ──────┐")
            print("│ [1] Сохранить в файл         │")
            print("│ [2] Показать как текст       │")
            print("└──────────────────────────────┘")
            action = input("Выбор: ").strip()
            
            if action == "2":
                try:
                    print("\n" + "─" * 45)
                    print(content.decode('utf-8'))
                    print("─" * 45)
                except UnicodeDecodeError:
                    print("⚠️  Бинарные данные — сохраняю в файл...")
                    action = "1"
            
            if action == "1":
                # Формируем имя по умолчанию
                default_name = f"restored{ext}" if ext else "restored.bin"
                save_name = input(f"\n💾 Имя файла (Enter = {default_name}): ").strip()
                
                if not save_name:
                    save_name = default_name
                
                with open(save_name, 'wb') as f:
                    f.write(content)
                
                abs_path = os.path.abspath(save_name)
                print(f"\n✅ Сохранено: {abs_path}")

        else:
            print("❌ Неверный выбор. Введите 1 или 2.")

    except KeyboardInterrupt:
        print("\n\n⚠️  Прервано пользователем (Ctrl+C)")
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
    finally:
        pause_exit()


if __name__ == "__main__":
    main()
