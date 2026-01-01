#!/usr/bin/env python3
"""
PixelEncoder v5.0 (2026 Standard Edition)

Compliance:
- PEP 585/604 (Modern Typing)
- PEP 517 (Build System)
- Pathlib-first IO
- Typer CLI Architecture
"""

import math
import struct
import secrets
import hashlib
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich import box

from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# ══════════════════════════════════════════════════════════════
#                    КОНФИГУРАЦИЯ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
HASH_SIZE = 32
FORMAT_VERSION = 5

KEY_SIZE_MIN = 4
KEY_SIZE_MAX = 100
KEY_SIZE_DEFAULT = 4

ARGON2_DEFAULTS = {
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4
}

app = typer.Typer(help="PixelEncoder v5.0: Secure Steganography Tool")
console = Console()

# ══════════════════════════════════════════════════════════════
#                    DATA STRUCTURES
# ══════════════════════════════════════════════════════════════

class PixelEncoderError(Exception): pass
class CryptoError(PixelEncoderError): pass
class IntegrityError(PixelEncoderError): pass
class FormatError(PixelEncoderError): pass

@dataclass
class Argon2Params:
    time_cost: int = ARGON2_DEFAULTS["time_cost"]
    memory_cost: int = ARGON2_DEFAULTS["memory_cost"]
    parallelism: int = ARGON2_DEFAULTS["parallelism"]

@dataclass
class DecryptedPayload:
    data: bytes
    filename: str
    extension: str

# ══════════════════════════════════════════════════════════════
#                    CORE LOGIC
# ══════════════════════════════════════════════════════════════

def secure_zero(buffer: bytearray | memoryview) -> None:
    for i in range(len(buffer)):
        buffer[i] = 0

def derive_key(secret: bytes, salt: bytes, params: Argon2Params) -> bytes:
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID
    )

def load_key_material(key_source: str | Path) -> bytes:
    if isinstance(key_source, Path):
        if not key_source.exists():
            raise FileNotFoundError(f"Key file not found: {key_source}")
        return key_source.read_bytes()
    return key_source.encode("utf-8")

def encrypt_data(
    data: bytes,
    key_material: bytes,
    filename: str = "",
    extension: str = "",
    params: Argon2Params | None = None
) -> bytes:
    if params is None:
        params = Argon2Params()

    filename_bytes = filename.encode('utf-8')[:255]
    ext_bytes = extension.encode('utf-8')[:32]
    
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    
    key = derive_key(key_material, salt, params)
    key_buffer = bytearray(key)
    
    try:
        data_hash = hashlib.sha256(data).digest()
        
        inner_data = (
            struct.pack('<B', len(filename_bytes)) + filename_bytes +
            struct.pack('<B', len(ext_bytes)) + ext_bytes +
            struct.pack('<I', len(data)) + data +
            data_hash
        )
        
        header = (
            struct.pack('<B', FORMAT_VERSION) +
            struct.pack('<H', params.time_cost) +
            struct.pack('<I', params.memory_cost) +
            salt + nonce
        )
        
        aesgcm = AESGCM(bytes(key_buffer))
        ciphertext = aesgcm.encrypt(nonce, inner_data, header)
        
        return header + struct.pack('<I', len(ciphertext)) + ciphertext
    finally:
        secure_zero(key_buffer)

def decrypt_data(encrypted: bytes, key_material: bytes) -> DecryptedPayload:
    offset = 0
    version = encrypted[offset]
    if version != FORMAT_VERSION:
        if version == 4: pass 
        else: raise FormatError(f"Unsupported version: {version}")
    
    offset += 1
    time_cost = struct.unpack('<H', encrypted[offset:offset+2])[0]
    offset += 2
    memory_cost = struct.unpack('<I', encrypted[offset:offset+4])[0]
    offset += 4
    salt = encrypted[offset:offset+SALT_SIZE]
    offset += SALT_SIZE
    nonce = encrypted[offset:offset+NONCE_SIZE]
    offset += NONCE_SIZE
    
    ciphertext_len = struct.unpack('<I', encrypted[offset:offset+4])[0]
    offset += 4
    
    ciphertext = encrypted[offset:offset+ciphertext_len]
    header = encrypted[:offset-4]
    
    params = Argon2Params(time_cost=time_cost, memory_cost=memory_cost)
    key = derive_key(key_material, salt, params)
    key_buffer = bytearray(key)
    
    try:
        aesgcm = AESGCM(bytes(key_buffer))
        inner_data = aesgcm.decrypt(nonce, ciphertext, header)
    except Exception:
        raise CryptoError("Decryption failed: Invalid key or corrupted data")
    finally:
        secure_zero(key_buffer)

    ptr = 0
    fn_len = inner_data[ptr]; ptr += 1
    filename = inner_data[ptr:ptr+fn_len].decode('utf-8'); ptr += fn_len
    
    ext_len = inner_data[ptr]; ptr += 1
    extension = inner_data[ptr:ptr+ext_len].decode('utf-8'); ptr += ext_len
    
    data_len = struct.unpack('<I', inner_data[ptr:ptr+4])[0]; ptr += 4
    data = inner_data[ptr:ptr+data_len]; ptr += data_len
    stored_hash = inner_data[ptr:ptr+HASH_SIZE]
    
    if not secrets.compare_digest(hashlib.sha256(data).digest(), stored_hash):
        raise IntegrityError("Integrity check failed! Data corrupted.")
        
    return DecryptedPayload(data, filename, extension)

# ══════════════════════════════════════════════════════════════
#                    IMAGE HANDLERS
# ══════════════════════════════════════════════════════════════

def save_to_png(data: bytes, path: Path) -> Path:
    required_pixels = math.ceil(len(data) / 3)
    side = math.ceil(math.sqrt(required_pixels))
    full_data = data + secrets.token_bytes(side * side * 3 - len(data))
    
    img = Image.frombytes('RGB', (side, side), full_data)
    
    target_path = path.with_suffix('.png')
    img.save(target_path, 'PNG', compress_level=9)
    return target_path

def load_from_png(path: Path) -> bytes:
    with Image.open(path) as img:
        img = img.convert('RGB')
        return img.tobytes()

def generate_key_image(size: int) -> Image.Image:
    """Генерирует изображение с криптографически случайными пикселями."""
    entropy_bytes = size * size * 3
    data = secrets.token_bytes(entropy_bytes)
    return Image.frombytes('RGB', (size, size), data)

# ══════════════════════════════════════════════════════════════
#                    INTERACTIVE MODE
# ══════════════════════════════════════════════════════════════

def show_banner():
    """Отображает ASCII-баннер программы."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║  ____  _          _ _____                     _               ║
║ |  _ \\(_)_  _____| | ____|_ __   ___ ___   __| | ___ _ __     ║
║ | |_) | \\ \\/ / _ \\ |  _| | '_ \\ / __/ _ \\ / _` |/ _ \\ '__|    ║
║ |  __/| |>  <  __/ | |___| | | | (_| (_) | (_| |  __/ |       ║
║ |_|   |_/_/\\_\\___|_|_____|_| |_|\\___\\___/ \\__,_|\\___|_|       ║
║                                                               ║
║                    v5.0 - Secure Steganography                ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")

def interactive_menu() -> str:
    """Отображает главное меню и возвращает выбор пользователя."""
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    table.add_column("Option", style="bold yellow")
    table.add_column("Description", style="white")
    
    table.add_row("[1]", "🔐 Encode - Зашифровать данные в изображение")
    table.add_row("[2]", "🔓 Decode - Расшифровать данные из изображения")
    table.add_row("[3]", "🔑 KeyGen - Сгенерировать ключ-файл")
    table.add_row("[4]", "📖 Info   - Информация о программе")
    table.add_row("[0]", "🚪 Exit   - Выход")
    
    console.print(Panel(table, title="[bold]Главное меню[/bold]", border_style="blue"))
    
    choice = Prompt.ask(
        "[bold cyan]Выберите действие[/bold cyan]",
        choices=["0", "1", "2", "3", "4"],
        default="1"
    )
    return choice

def interactive_encode():
    """Интерактивный режим шифрования."""
    console.print("\n[bold blue]═══ РЕЖИМ ШИФРОВАНИЯ ═══[/bold blue]\n")
    
    # Шаг 1: Выбор типа данных
    console.print("[bold]Шаг 1/5:[/bold] Что вы хотите зашифровать?")
    data_type = Prompt.ask(
        "  Выберите тип",
        choices=["file", "text"],
        default="text"
    )
    
    raw_data = b""
    filename = "message"
    extension = ".txt"
    
    if data_type == "file":
        while True:
            file_path_str = Prompt.ask("  [cyan]Путь к файлу[/cyan]")
            file_path = Path(file_path_str).expanduser().resolve()
            
            if file_path.exists() and file_path.is_file():
                raw_data = file_path.read_bytes()
                filename = file_path.stem
                extension = file_path.suffix
                console.print(f"  [green]✓[/green] Файл загружен: {len(raw_data)} байт")
                break
            else:
                console.print(f"  [red]✗ Файл не найден: {file_path}[/red]")
    else:
        console.print("  [dim]Введите текст (для многострочного ввода завершите пустой строкой):[/dim]")
        lines = []
        while True:
            line = Prompt.ask("  ", default="")
            if line == "" and lines:
                break
            lines.append(line)
            if len(lines) == 1 and line != "":
                if not Confirm.ask("  Добавить ещё строки?", default=False):
                    break
        
        raw_data = "\n".join(lines).encode('utf-8')
        console.print(f"  [green]✓[/green] Текст принят: {len(raw_data)} байт")
    
    # Шаг 2: Выбор метода защиты
    console.print("\n[bold]Шаг 2/5:[/bold] Выберите метод защиты:")
    protection_table = Table(box=box.SIMPLE, show_header=False)
    protection_table.add_row("[1]", "Пароль", "[dim]Ввести свой пароль[/dim]")
    protection_table.add_row("[2]", "Ключ-файл", "[dim]Использовать PNG-ключ[/dim]")
    protection_table.add_row("[3]", "Авто-пароль", "[dim]Сгенерировать случайный[/dim]")
    console.print(protection_table)
    
    protection_method = Prompt.ask(
        "  Выбор",
        choices=["1", "2", "3"],
        default="1"
    )
    
    key_material = None
    generated_pw = None
    
    if protection_method == "1":
        while True:
            password = Prompt.ask("  [cyan]Введите пароль[/cyan]", password=True)
            password_confirm = Prompt.ask("  [cyan]Подтвердите пароль[/cyan]", password=True)
            
            if password == password_confirm:
                if len(password) < 8:
                    console.print("  [yellow]⚠ Рекомендуется пароль не менее 8 символов[/yellow]")
                    if not Confirm.ask("  Продолжить с коротким паролем?", default=False):
                        continue
                key_material = password.encode('utf-8')
                console.print("  [green]✓[/green] Пароль установлен")
                break
            else:
                console.print("  [red]✗ Пароли не совпадают![/red]")
                
    elif protection_method == "2":
        while True:
            keyfile_path_str = Prompt.ask("  [cyan]Путь к ключ-файлу[/cyan]")
            keyfile_path = Path(keyfile_path_str).expanduser().resolve()
            
            if keyfile_path.exists():
                key_material = load_key_material(keyfile_path)
                console.print(f"  [green]✓[/green] Ключ-файл загружен: {len(key_material)} байт")
                break
            else:
                console.print(f"  [red]✗ Файл не найден: {keyfile_path}[/red]")
                if Confirm.ask("  Сгенерировать новый ключ-файл?", default=True):
                    new_key_path = Path(Prompt.ask("  Путь для нового ключа", default="key.png"))
                    _interactive_keygen_helper(new_key_path)
                    key_material = load_key_material(new_key_path.with_suffix('.png'))
                    break
    else:
        generated_pw = secrets.token_urlsafe(24)
        key_material = generated_pw.encode('utf-8')
        console.print("  [green]✓[/green] Автоматический пароль сгенерирован")
    
    # Шаг 3: Параметры Argon2 (опционально)
    console.print("\n[bold]Шаг 3/5:[/bold] Настройки шифрования")
    
    use_custom_argon2 = Confirm.ask(
        "  Настроить параметры Argon2? (для продвинутых)",
        default=False
    )
    
    params = Argon2Params()
    if use_custom_argon2:
        console.print("  [dim]Выберите уровень защиты:[/dim]")
        level_table = Table(box=box.SIMPLE, show_header=False)
        level_table.add_row("[1]", "Быстрый", "[dim]time=2, memory=32MB[/dim]")
        level_table.add_row("[2]", "Стандарт", "[dim]time=3, memory=64MB (рекомендуется)[/dim]")
        level_table.add_row("[3]", "Высокий", "[dim]time=4, memory=128MB[/dim]")
        level_table.add_row("[4]", "Параноик", "[dim]time=6, memory=256MB (медленно!)[/dim]")
        level_table.add_row("[5]", "Custom", "[dim]Задать вручную[/dim]")
        console.print(level_table)
        
        level = Prompt.ask("  Уровень", choices=["1", "2", "3", "4", "5"], default="2")
        
        presets = {
            "1": Argon2Params(time_cost=2, memory_cost=32768),
            "2": Argon2Params(time_cost=3, memory_cost=65536),
            "3": Argon2Params(time_cost=4, memory_cost=131072),
            "4": Argon2Params(time_cost=6, memory_cost=262144),
        }
        
        if level == "5":
            time_cost = IntPrompt.ask("  Time cost (1-10)", default=3)
            memory_mb = IntPrompt.ask("  Memory (MB)", default=64)
            params = Argon2Params(time_cost=time_cost, memory_cost=memory_mb * 1024)
        else:
            params = presets[level]
        
        console.print(f"  [green]✓[/green] Argon2: time={params.time_cost}, memory={params.memory_cost // 1024}MB")
    else:
        console.print(f"  [dim]Используются стандартные параметры[/dim]")
    
    # Шаг 4: Путь вывода
    console.print("\n[bold]Шаг 4/5:[/bold] Куда сохранить результат?")
    
    default_output = f"encoded_{filename}.png"
    output_path_str = Prompt.ask(
        "  [cyan]Путь к выходному файлу[/cyan]",
        default=default_output
    )
    output_path = Path(output_path_str).expanduser()
    
    if output_path.exists():
        if not Confirm.ask(f"  [yellow]Файл {output_path} существует. Перезаписать?[/yellow]", default=False):
            output_path = Path(Prompt.ask("  Новое имя файла"))
    
    # Шаг 5: Подтверждение
    console.print("\n[bold]Шаг 5/5:[/bold] Подтверждение")
    
    summary_table = Table(box=box.ROUNDED, title="Сводка операции")
    summary_table.add_column("Параметр", style="cyan")
    summary_table.add_column("Значение", style="white")
    
    summary_table.add_row("Тип данных", "Файл" if data_type == "file" else "Текст")
    summary_table.add_row("Размер данных", f"{len(raw_data)} байт")
    summary_table.add_row("Защита", ["Пароль", "Ключ-файл", "Авто-пароль"][int(protection_method) - 1])
    summary_table.add_row("Argon2 memory", f"{params.memory_cost // 1024} MB")
    summary_table.add_row("Выходной файл", str(output_path))
    
    console.print(summary_table)
    
    if not Confirm.ask("\n  [bold]Начать шифрование?[/bold]", default=True):
        console.print("  [yellow]Операция отменена[/yellow]")
        return
    
    # Выполнение
    try:
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task(description="Шифрование (Argon2id + AES-GCM)...", total=None)
            
            encrypted_data = encrypt_data(
                raw_data, 
                key_material, 
                filename, 
                extension,
                params
            )
            
            final_path = save_to_png(encrypted_data, output_path)

        console.print(Panel(
            f"[bold green]✓ Успех![/bold green]\n\n"
            f"📁 Файл: [cyan]{final_path.resolve()}[/cyan]\n"
            f"📊 Размер: {len(raw_data)} → {final_path.stat().st_size} байт",
            title="Шифрование завершено",
            border_style="green"
        ))
        
        if generated_pw:
            console.print(Panel(
                f"[bold red]{generated_pw}[/bold red]\n\n"
                f"[dim]Сохраните этот пароль! Он не может быть восстановлен.[/dim]",
                title="⚠️  СГЕНЕРИРОВАННЫЙ ПАРОЛЬ ⚠️",
                border_style="red"
            ))

    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")

def interactive_decode():
    """Интерактивный режим дешифрования."""
    console.print("\n[bold blue]═══ РЕЖИМ ДЕШИФРОВАНИЯ ═══[/bold blue]\n")
    
    # Шаг 1: Выбор изображения
    console.print("[bold]Шаг 1/4:[/bold] Выберите изображение для расшифровки")
    
    while True:
        image_path_str = Prompt.ask("  [cyan]Путь к изображению[/cyan]")
        image_path = Path(image_path_str).expanduser().resolve()
        
        if image_path.exists() and image_path.suffix.lower() in ['.png', '.bmp']:
            console.print(f"  [green]✓[/green] Изображение найдено: {image_path.stat().st_size} байт")
            break
        else:
            console.print(f"  [red]✗ Файл не найден или неверный формат: {image_path}[/red]")
    
    # Шаг 2: Метод защиты
    console.print("\n[bold]Шаг 2/4:[/bold] Чем защищены данные?")
    
    protection_method = Prompt.ask(
        "  Метод",
        choices=["password", "keyfile"],
        default="password"
    )
    
    if protection_method == "password":
        password = Prompt.ask("  [cyan]Введите пароль[/cyan]", password=True)
        key_material = password.encode('utf-8')
    else:
        while True:
            keyfile_path_str = Prompt.ask("  [cyan]Путь к ключ-файлу[/cyan]")
            keyfile_path = Path(keyfile_path_str).expanduser().resolve()
            
            if keyfile_path.exists():
                key_material = load_key_material(keyfile_path)
                console.print(f"  [green]✓[/green] Ключ-файл загружен")
                break
            else:
                console.print(f"  [red]✗ Файл не найден[/red]")
    
    # Шаг 3: Директория вывода
    console.print("\n[bold]Шаг 3/4:[/bold] Куда сохранить расшифрованные данные?")
    
    output_dir_str = Prompt.ask(
        "  [cyan]Директория вывода[/cyan]",
        default="."
    )
    output_dir = Path(output_dir_str).expanduser().resolve()
    
    if not output_dir.exists():
        if Confirm.ask(f"  Директория {output_dir} не существует. Создать?", default=True):
            output_dir.mkdir(parents=True)
        else:
            console.print("  [yellow]Операция отменена[/yellow]")
            return
    
    # Шаг 4: Подтверждение
    console.print("\n[bold]Шаг 4/4:[/bold] Подтверждение")
    
    summary_table = Table(box=box.ROUNDED)
    summary_table.add_column("Параметр", style="cyan")
    summary_table.add_column("Значение")
    summary_table.add_row("Изображение", str(image_path))
    summary_table.add_row("Защита", protection_method.capitalize())
    summary_table.add_row("Вывод в", str(output_dir))
    
    console.print(summary_table)
    
    if not Confirm.ask("\n  [bold]Начать дешифрование?[/bold]", default=True):
        console.print("  [yellow]Операция отменена[/yellow]")
        return
    
    # Выполнение
    try:
        raw_bytes = load_from_png(image_path)
        
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task("Дешифрование и проверка целостности...", total=None)
            payload = decrypt_data(raw_bytes, key_material)
        
        safe_filename = Path(f"{payload.filename}{payload.extension}")
        safe_filename = Path(safe_filename.name)
        target_path = output_dir / safe_filename
        
        if not target_path.resolve().is_relative_to(output_dir.resolve()):
            console.print(f"[red]Ошибка безопасности: обнаружена попытка выхода за пределы директории[/red]")
            return
        
        if target_path.exists():
            if not Confirm.ask(f"  [yellow]Файл {target_path.name} существует. Перезаписать?[/yellow]", default=False):
                new_name = Prompt.ask("  Новое имя файла", default=f"decrypted_{safe_filename}")
                target_path = output_dir / new_name
        
        target_path.write_bytes(payload.data)
        
        console.print(Panel(
            f"[bold green]✓ Дешифрование успешно![/bold green]\n\n"
            f"📁 Сохранено: [cyan]{target_path.resolve()}[/cyan]\n"
            f"📝 Оригинальное имя: {payload.filename}{payload.extension}\n"
            f"📊 Размер: {len(payload.data)} байт",
            title="Успех",
            border_style="green"
        ))
        
        if payload.extension in ['.txt', '.md', '.json', '.xml', '.csv']:
            if Confirm.ask("  Показать содержимое?", default=False):
                try:
                    text_content = payload.data.decode('utf-8')
                    console.print(Panel(text_content[:2000] + ("..." if len(text_content) > 2000 else ""), 
                                       title="Содержимое"))
                except:
                    console.print("  [dim]Не удалось декодировать как текст[/dim]")

    except (CryptoError, IntegrityError, FormatError) as e:
        console.print(Panel(
            f"[bold red]✗ Ошибка дешифрования[/bold red]\n\n{e}",
            border_style="red"
        ))
    except Exception as e:
        console.print(f"[bold red]Непредвиденная ошибка:[/bold red] {e}")

def _interactive_keygen_helper(output_path: Path, size: int = KEY_SIZE_DEFAULT):
    """Вспомогательная функция генерации ключа."""
    img = generate_key_image(size)
    target = output_path.with_suffix('.png')
    img.save(target, format="PNG")
    
    entropy_bytes = size * size * 3
    console.print(f"  [green]✓[/green] Ключ-файл создан: {target} ({entropy_bytes} байт энтропии)")
    return target

def interactive_keygen():
    """Интерактивный режим генерации ключа."""
    console.print("\n[bold blue]═══ ГЕНЕРАЦИЯ КЛЮЧ-ФАЙЛА ═══[/bold blue]\n")
    
    # Пояснение
    console.print(Panel(
        "[dim]Изображение 4×4 уже содержит 48 байт (384 бита) случайных данных.\n"
        "Для AES-256 требуется всего 256 бит, поэтому бОльшие размеры\n"
        "не повышают криптографическую стойкость.[/dim]",
        title="💡 Почему 4×4 достаточно?",
        border_style="dim"
    ))
    
    # Размер
    console.print("\n[bold]Шаг 1/2:[/bold] Размер ключ-изображения")
    
    size_table = Table(box=box.SIMPLE, show_header=False)
    size_table.add_row("[1]", "4×4", "[green]48 байт — рекомендуется[/green]")
    size_table.add_row("[2]", "Свой размер", f"[dim]от {KEY_SIZE_MIN} до {KEY_SIZE_MAX}[/dim]")
    console.print(size_table)
    
    size_choice = Prompt.ask("  Выбор", choices=["1", "2"], default="1")
    
    if size_choice == "1":
        size = KEY_SIZE_DEFAULT
    else:
        while True:
            size = IntPrompt.ask(f"  Размер стороны квадрата (минимум {KEY_SIZE_MIN})", default=KEY_SIZE_DEFAULT)
            
            if size < KEY_SIZE_MIN:
                console.print(f"  [yellow]⚠ Минимальный размер: {KEY_SIZE_MIN}[/yellow]")
                continue
            elif size > KEY_SIZE_MAX:
                console.print(f"  [yellow]⚠ Максимальный размер: {KEY_SIZE_MAX} (больше не имеет смысла)[/yellow]")
                continue
            else:
                break
    
    entropy_bytes = size * size * 3
    console.print(f"  [dim]Выбрано: {size}×{size} = {entropy_bytes} байт ({entropy_bytes * 8} бит) энтропии[/dim]")
    
    # Путь
    console.print("\n[bold]Шаг 2/2:[/bold] Куда сохранить ключ?")
    
    output_path_str = Prompt.ask(
        "  [cyan]Путь к файлу[/cyan]",
        default="key.png"
    )
    output_path = Path(output_path_str).expanduser()
    
    if output_path.with_suffix('.png').exists():
        if not Confirm.ask(f"  [yellow]Файл существует. Перезаписать?[/yellow]", default=False):
            console.print("  [yellow]Отменено[/yellow]")
            return
    
    # Генерация
    try:
        img = generate_key_image(size)
        target = output_path.with_suffix('.png')
        img.save(target, format="PNG")
        
        console.print(Panel(
            f"[bold green]✓ Ключ-файл создан![/bold green]\n\n"
            f"📁 Путь: [cyan]{target.resolve()}[/cyan]\n"
            f"📐 Размер: {size}×{size} пикселей\n"
            f"🔐 Энтропия: {entropy_bytes} байт ({entropy_bytes * 8} бит)",
            title="KeyGen",
            border_style="green"
        ))
        
        console.print("\n[yellow]⚠ Храните этот файл в безопасном месте![/yellow]")
        console.print("[dim]Потеря ключ-файла = потеря доступа к зашифрованным данным[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")

def show_info():
    """Показать информацию о программе."""
    info_text = """
[bold cyan]PixelEncoder v5.0[/bold cyan]
[dim]Secure Steganography Tool (2026 Standard Edition)[/dim]

[bold]Возможности:[/bold]
• Шифрование файлов и текста в PNG-изображения
• AES-256-GCM + Argon2id для максимальной безопасности
• Поддержка ключ-файлов (PNG) для двухфакторной защиты
• Проверка целостности SHA-256
• Защита от Path Traversal атак

[bold]Алгоритмы:[/bold]
• [cyan]Argon2id[/cyan] - KDF, устойчивый к GPU/ASIC атакам
• [cyan]AES-256-GCM[/cyan] - AEAD шифрование
• [cyan]SHA-256[/cyan] - контрольная сумма данных

[bold]Использование:[/bold]
[dim]Интерактивный режим:[/dim]
  python pixel_encoder.py interactive
  
[dim]Командный режим:[/dim]
  python pixel_encoder.py encode --file secret.pdf --password "mypass"
  python pixel_encoder.py decode image.png --password "mypass"
  python pixel_encoder.py keygen key.png
    """
    console.print(Panel(info_text, title="О программе", border_style="blue"))

def run_interactive_mode():
    """Главный цикл интерактивного режима."""
    show_banner()
    
    while True:
        console.print()
        choice = interactive_menu()
        
        if choice == "0":
            console.print("\n[bold green]До свидания! 👋[/bold green]")
            break
        elif choice == "1":
            interactive_encode()
        elif choice == "2":
            interactive_decode()
        elif choice == "3":
            interactive_keygen()
        elif choice == "4":
            show_info()
        
        console.print()
        if choice != "0":
            if not Confirm.ask("[dim]Вернуться в главное меню?[/dim]", default=True):
                console.print("\n[bold green]До свидания! 👋[/bold green]")
                break

# ══════════════════════════════════════════════════════════════
#                    CLI COMMANDS (Typer)
# ══════════════════════════════════════════════════════════════

@app.command()
def interactive():
    """🎮 Запустить интерактивный режим с пошаговым вводом."""
    run_interactive_mode()

@app.command()
def keygen(
    output: Annotated[Path, typer.Argument(help="Output path for key file")] = Path("key.png"),
    size: Annotated[int, typer.Option("--size", "-s", help=f"Side size ({KEY_SIZE_MIN}-{KEY_SIZE_MAX})")] = KEY_SIZE_DEFAULT
):
    """🔑 Generate a high-entropy noise image to act as a key-file."""
    
    # Валидация размера
    original_size = size
    if size < KEY_SIZE_MIN:
        console.print(f"[yellow]Minimum size is {KEY_SIZE_MIN}. Using {KEY_SIZE_MIN}.[/yellow]")
        size = KEY_SIZE_MIN
    elif size > KEY_SIZE_MAX:
        console.print(f"[yellow]Maximum size is {KEY_SIZE_MAX} (larger is pointless for crypto). Using {KEY_SIZE_MAX}.[/yellow]")
        size = KEY_SIZE_MAX
    
    try:
        img = generate_key_image(size)
        target = output.with_suffix('.png')
        img.save(target, format="PNG")
        
        entropy_bytes = size * size * 3
        
        console.print(Panel(
            f"[green]Key file generated successfully![/green]\n"
            f"Path: {target.resolve()}\n"
            f"Size: {size}×{size} pixels\n"
            f"Entropy: {entropy_bytes} bytes ({entropy_bytes * 8} bits)\n\n"
            f"[dim]Note: 6×6 (108 bytes) is already more than enough for AES-256.[/dim]", 
            title="KeyGen"
        ))
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

@app.command()
def encode(
    file: Annotated[Path, typer.Option("--file", "-f", help="File to encrypt")] = None,
    text: Annotated[str, typer.Option("--text", "-t", help="Text to encrypt")] = None,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("encoded.png"),
    password: Annotated[str, typer.Option("--password", "-p")] = None,
    keyfile: Annotated[Path, typer.Option("--keyfile", "-k")] = None,
):
    """🔐 Encrypt data into a PNG image."""
    
    if not file and not text:
        console.print("[red]Error: Provide either --file or --text[/red]")
        raise typer.Exit(1)
        
    key_material = None
    generated_pw = None
    
    if not password and not keyfile:
        generated_pw = secrets.token_urlsafe(24)
        key_material = generated_pw.encode('utf-8')
    elif keyfile:
        key_material = load_key_material(keyfile)
    else:
        key_material = password.encode('utf-8')

    raw_data = b""
    filename = "message"
    extension = ".txt"
    
    if file:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        raw_data = file.read_bytes()
        filename = file.stem
        extension = file.suffix
    else:
        raw_data = text.encode('utf-8')

    try:
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task(description="Encrypting (Argon2id + AES-GCM)...", total=None)
            
            encrypted_data = encrypt_data(raw_data, key_material, filename, extension)
            final_path = save_to_png(encrypted_data, output)

        console.print(Panel(
            f"[bold green]Success![/bold green]\n"
            f"Image saved to: [cyan]{final_path.resolve()}[/cyan]\n"
            f"Size: {len(raw_data)} bytes -> {final_path.stat().st_size} bytes (PNG)",
            title="Encryption Report"
        ))
        
        if generated_pw:
            console.print(Panel(
                f"[bold red]{generated_pw}[/bold red]",
                title="⚠️  GENERATED PASSWORD (SAVE THIS) ⚠️",
                border_style="red"
            ))

    except Exception as e:
        console.print(f"[bold red]Critical Error:[/bold red] {e}")
        raise typer.Exit(1)

@app.command()
def decode(
    image: Annotated[Path, typer.Argument(help="Image with hidden data")],
    output_dir: Annotated[Path, typer.Option("--out-dir", "-d")] = Path("."),
    password: Annotated[str, typer.Option("--password", "-p")] = None,
    keyfile: Annotated[Path, typer.Option("--keyfile", "-k")] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files")] = False
):
    """🔓 Decrypt data from a PNG image."""
    
    if not image.exists():
        console.print(f"[red]Image not found: {image}[/red]")
        raise typer.Exit(1)
        
    if not password and not keyfile:
        password = Prompt.ask("Enter password", password=True)

    key_material = load_key_material(keyfile) if keyfile else password.encode('utf-8')

    try:
        raw_bytes = load_from_png(image)
        
        with Progress(
            SpinnerColumn(), 
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            progress.add_task("Decrypting and Verifying Integrity...", total=None)
            payload = decrypt_data(raw_bytes, key_material)
            
        safe_filename = Path(f"{payload.filename}{payload.extension}")
        safe_filename = Path(safe_filename.name)
        
        target_path = output_dir / safe_filename
        
        if not target_path.resolve().is_relative_to(output_dir.resolve()):
             console.print(f"[red]Security Alert:[/red] Path traversal detected")
             raise typer.Exit(1)

        if target_path.exists() and not force:
            if not Confirm.ask(f"File {target_path.name} exists. Overwrite?"):
                console.print("[yellow]Aborted.[/yellow]")
                raise typer.Exit(0)

        target_path.write_bytes(payload.data)
        
        console.print(Panel(
            f"[green]Decryption Successful![/green]\n"
            f"File saved: [cyan]{target_path.resolve()}[/cyan]\n"
            f"Original Name: {payload.filename}{payload.extension}",
            title="Success"
        ))

    except (CryptoError, IntegrityError, FormatError) as e:
        console.print(f"[bold red]Decryption Failed:[/bold red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected Error:[/bold red] {e}")
        raise typer.Exit(1)

# ══════════════════════════════════════════════════════════════
#                    CALLBACK ПО УМОЛЧАНИЮ
# ══════════════════════════════════════════════════════════════

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    PixelEncoder v5.0 - Secure Steganography Tool
    
    Запустите без аргументов для интерактивного режима.
    """
    if ctx.invoked_subcommand is None:
        run_interactive_mode()

if __name__ == "__main__":
    app()
