#!/usr/bin/env python3
"""
PixelEncoder v6.2 (Post-Quantum Edition - OQS)

Compliance:
- FIPS 203 (ML-KEM-768) via liboqs-python
- AES-256-GCM for symmetric payload encryption
- PEP 585/604 (Modern Typing)

Changes in v6.2:
- Universal path resolution (absolute, relative, ~, %ENV%)
- Capacity estimation before encoding
- Human-readable file sizes
- DLL path via environment variable
- Input validation & sanitization
"""

import time
import math
import struct
import secrets
import hashlib
import sys
import re
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Annotated, Optional




import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box

from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ══════════════════════════════════════════════════════════════
#          КОНФИГУРАЦИЯ ПУТИ К LIBOQS (через переменную среды)
# ══════════════════════════════════════════════════════════════

_oqs_dll_dir = os.environ.get("LIBOQS_DLL_DIR", "")
if _oqs_dll_dir:
    _resolved = str(Path(_oqs_dll_dir).expanduser().resolve())
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(_resolved)
    os.environ["PATH"] = _resolved + os.pathsep + os.environ.get("PATH", "")

try:
    import oqs
except ImportError:
    print("Ошибка: Отсутствует библиотека 'liboqs-python'.")
    print("Установите её командой: pip install liboqs-python")
    print("Если DLL не находится — задайте переменную среды LIBOQS_DLL_DIR")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════
#                    КОНФИГУРАЦИЯ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════

APP_VERSION = "6.2.0"
NONCE_SIZE = 12
HASH_SIZE = 32
FORMAT_VERSION = 6

KEM_ALGORITHM = "ML-KEM-768"
KYBER_PK_SIZE = 1184
KYBER_SK_SIZE = 2400
KYBER_CT_SIZE = 1088

# Максимальный размер входных данных (100 MB)
MAX_INPUT_SIZE = 100 * 1024 * 1024

# Запрещённые символы в именах файлов (кроссплатформенно)
_UNSAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

app = typer.Typer(help="PixelEncoder v6.2: Post-Quantum Steganography Tool")
console = Console()

# ══════════════════════════════════════════════════════════════
#                    DATA STRUCTURES
# ══════════════════════════════════════════════════════════════

class PixelEncoderError(Exception):
    pass

class CryptoError(PixelEncoderError):
    pass

class IntegrityError(PixelEncoderError):
    pass

class FormatError(PixelEncoderError):
    pass

class CapacityError(PixelEncoderError):
    pass

@dataclass
class DecryptedPayload:
    data: bytes
    filename: str
    extension: str

# ══════════════════════════════════════════════════════════════
#                    УТИЛИТЫ ДЛЯ ПУТЕЙ
# ══════════════════════════════════════════════════════════════

def resolve_path(raw: str | Path) -> Path:
    """
    Универсальный резолвер путей.

    Поддерживает:
      - Относительные:  ./data/file.txt,  ../keys/pub.kyber
      - Домашний каталог: ~/Documents/key.kyber
      - Переменные среды: %USERPROFILE%\\keys  или  $HOME/keys
      - Абсолютные:  C:\\Users\\...  или  /home/user/...
      - Смешанные разделители: C:/Users\\David/file.txt

    Автоочистка:
      - PowerShell:  & 'C:\\path\\to file'
      - CMD/PS:      "C:\\path\\to file"
      - Лишние кавычки и пробелы
    """
    s = str(raw).strip()

    # Убираем PowerShell-оператор вызова:  & 'path'  или  & "path"
    if s.startswith("& "):
        s = s[2:].strip()

    # Убираем обрамляющие кавычки (одинарные и двойные), даже вложенные
    while len(s) >= 2 and (
        (s[0] == '"' and s[-1] == '"') or
        (s[0] == "'" and s[-1] == "'")
    ):
        s = s[1:-1].strip()

    # Раскрываем переменные окружения (%VAR% на Windows, $VAR на Unix)
    s = os.path.expandvars(s)

    p = Path(s)

    # Раскрываем ~ → домашний каталог
    p = p.expanduser()

    # Превращаем в абсолютный путь относительно CWD
    p = p.resolve()

    return p

def sanitize_filename(name: str) -> str:
    """Удаляет опасные символы из имени файла."""
    cleaned = _UNSAFE_FILENAME_RE.sub("_", name)
    # Убираем ведущие/замыкающие точки и пробелы
    cleaned = cleaned.strip(". ")
    return cleaned or "unnamed"


def human_size(size_bytes: int) -> str:
    """Форматирует размер в человекочитаемый вид."""
    if size_bytes == 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    i = min(i, len(units) - 1)
    value = size_bytes / (1024 ** i)
    return f"{value:.1f} {units[i]}" if i > 0 else f"{size_bytes} B"


def validate_file_exists(path: Path, label: str = "Файл") -> Path:
    """Проверяет существование файла, кидает понятную ошибку."""
    if not path.exists():
        raise FileNotFoundError(f"{label} не найден: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"{label} — это директория, а не файл: {path}")
    return path


def ensure_dir(path: Path) -> Path:
    """Создаёт директорию, если не существует."""
    path.mkdir(parents=True, exist_ok=True)
    return path

# ══════════════════════════════════════════════════════════════
#                    CORE LOGIC
# ══════════════════════════════════════════════════════════════

def secure_zero(buffer: bytearray | memoryview) -> None:
    for i in range(len(buffer)):
        buffer[i] = 0


def generate_kyber_keys(output_dir: Path) -> tuple[Path, Path]:
    output_dir = ensure_dir(output_dir)

    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

    pub_path = output_dir / "public.kyber"
    priv_path = output_dir / "private.kyber"

    pub_path.write_bytes(public_key)
    priv_path.write_bytes(private_key)

    return pub_path, priv_path


def estimate_png_size(data_len: int) -> int:
    """Оценка размера PNG (верхняя граница, без сжатия)."""
    overhead = 1 + KYBER_CT_SIZE + NONCE_SIZE + 4 + 16  # header + GCM tag
    total = data_len + overhead + 256 + HASH_SIZE  # запас на метаданные
    required_pixels = math.ceil(total / 3)
    side = math.ceil(math.sqrt(required_pixels))
    return side * side * 3  # RGB-байт


def encrypt_data(
    data: bytes,
    public_key: bytes,
    filename: str = "",
    extension: str = "",
) -> bytes:
    if not data:
        raise ValueError("Нечего шифровать: входные данные пусты.")
    if len(data) > MAX_INPUT_SIZE:
        raise ValueError(
            f"Файл слишком большой: {human_size(len(data))}. "
            f"Максимум: {human_size(MAX_INPUT_SIZE)}"
        )

    filename_bytes = filename.encode("utf-8")[:255]
    ext_bytes = extension.encode("utf-8")[:32]

    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            kyber_ciphertext, shared_secret = kem.encap_secret(public_key)
    except Exception as e:
        raise CryptoError(f"Kyber encapsulation failed: {e}")

    shared_secret_buf = bytearray(shared_secret)

    try:
        data_hash = hashlib.sha256(data).digest()

        inner_data = (
            struct.pack("<B", len(filename_bytes)) + filename_bytes
            + struct.pack("<B", len(ext_bytes)) + ext_bytes
            + struct.pack("<I", len(data)) + data
            + data_hash
        )

        nonce = secrets.token_bytes(NONCE_SIZE)

        header = (
            struct.pack("<B", FORMAT_VERSION)
            + kyber_ciphertext
            + nonce
        )

        aesgcm = AESGCM(bytes(shared_secret_buf))
        ciphertext = aesgcm.encrypt(nonce, inner_data, header)

        return header + struct.pack("<I", len(ciphertext)) + ciphertext
    finally:
        secure_zero(shared_secret_buf)


def decrypt_data(encrypted: bytes, private_key: bytes) -> DecryptedPayload:
    offset = 0
    if len(encrypted) < 1:
        raise FormatError("Данные пусты — нечего расшифровывать.")

    version = encrypted[offset]
    if version != FORMAT_VERSION:
        raise FormatError(f"Неподдерживаемая версия формата: {version}")

    offset += 1
    min_len = offset + KYBER_CT_SIZE + NONCE_SIZE + 4
    if len(encrypted) < min_len:
        raise FormatError(
            f"Данные слишком короткие ({human_size(len(encrypted))}). "
            f"Минимум для ML-KEM заголовка: {human_size(min_len)}."
        )

    kyber_ciphertext = encrypted[offset : offset + KYBER_CT_SIZE]
    offset += KYBER_CT_SIZE

    nonce = encrypted[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext_len = struct.unpack("<I", encrypted[offset : offset + 4])[0]
    offset += 4

    ciphertext = encrypted[offset : offset + ciphertext_len]
    header = encrypted[: offset - 4]

    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(kyber_ciphertext)
    except Exception as e:
        raise CryptoError(f"Kyber decapsulation failed: {e}")

    shared_secret_buf = bytearray(shared_secret)

    try:
        aesgcm = AESGCM(bytes(shared_secret_buf))
        inner_data = aesgcm.decrypt(nonce, ciphertext, header)
    except Exception:
        raise CryptoError(
            "AES-GCM decryption failed: неверный ключ или повреждённые данные"
        )
    finally:
        secure_zero(shared_secret_buf)

    ptr = 0
    fn_len = inner_data[ptr]; ptr += 1
    filename = inner_data[ptr : ptr + fn_len].decode("utf-8"); ptr += fn_len
    ext_len = inner_data[ptr]; ptr += 1
    extension = inner_data[ptr : ptr + ext_len].decode("utf-8"); ptr += ext_len
    data_len = struct.unpack("<I", inner_data[ptr : ptr + 4])[0]; ptr += 4
    data = inner_data[ptr : ptr + data_len]; ptr += data_len
    stored_hash = inner_data[ptr : ptr + HASH_SIZE]

    if not secrets.compare_digest(hashlib.sha256(data).digest(), stored_hash):
        raise IntegrityError("Проверка целостности не пройдена! Данные повреждены.")

    # Санитизация имени файла из зашифрованных данных
    filename = sanitize_filename(filename)
    extension = sanitize_filename(extension)
    if extension and not extension.startswith("."):
        extension = "." + extension

    return DecryptedPayload(data, filename, extension)

# ══════════════════════════════════════════════════════════════
#                    IMAGE HANDLERS
# ══════════════════════════════════════════════════════════════

def save_to_png(data: bytes, path: Path) -> Path:
    required_pixels = math.ceil(len(data) / 3)
    side = math.ceil(math.sqrt(required_pixels))
    padded_len = side * side * 3
    full_data = data + secrets.token_bytes(padded_len - len(data))

    img = Image.frombytes("RGB", (side, side), full_data)

    target_path = path.with_suffix(".png")
    ensure_dir(target_path.parent)
    img.save(target_path, "PNG", compress_level=9)
    return target_path


def load_from_png(path: Path) -> bytes:
    path = validate_file_exists(path, "Изображение")
    with Image.open(path) as img:
        img = img.convert("RGB")
        return img.tobytes()

# ══════════════════════════════════════════════════════════════
#             ИНТЕРАКТИВНЫЙ ВВОД ПУТИ (с повтором)
# ══════════════════════════════════════════════════════════════

def ask_path(
    prompt: str,
    default: str = "",
    must_exist: bool = False,
    must_be_file: bool = False,
    must_be_dir: bool = False,
) -> Path:
    """
    Запрашивает у пользователя путь с валидацией и повторными попытками.
    Принимает любой формат: относительный, абсолютный, ~, %ENV%.
    """
    while True:
        raw = Prompt.ask(prompt, default=default) if default else Prompt.ask(prompt)
        try:
            p = resolve_path(raw)
        except Exception as e:
            console.print(f"[red]✗ Некорректный путь: {e}[/red]")
            continue

        if must_exist and not p.exists():
            console.print(f"[red]✗ Не найден: {p}[/red]")
            console.print(f"  [dim]Введённое значение: {raw!r}[/dim]")
            console.print(f"  [dim]Раскрыто в:         {p}[/dim]")
            continue

        if must_be_file and p.exists() and not p.is_file():
            console.print(f"[red]✗ Это не файл: {p}[/red]")
            continue

        if must_be_dir and p.exists() and not p.is_dir():
            console.print(f"[red]✗ Это не директория: {p}[/red]")
            continue

        return p

# ══════════════════════════════════════════════════════════════
#                    INTERACTIVE MODE
# ══════════════════════════════════════════════════════════════

def show_banner():
    banner = f"""
╔═══════════════════════════════════════════════════════════════╗
║  ____  _          _ _____                     _               ║
║ |  _ \\(_)_  _____| | ____|_ __   ___ ___   __| | ___ _ __     ║
║ | |_) | \\ \\/ / _ \\ |  _| | '_ \\ / __/ _ \\ / _` |/ _ \\ '__|    ║
║ |  __/| |>  <  __/ | |___| | | | (_| (_) | (_| |  __/ |       ║
║ |_|   |_/_/\\_\\___|_|_____|_| |_|\\___\\___/ \\__,_|\\___|_|       ║
║                                                               ║
║          v{APP_VERSION} - Post-Quantum Steganography                  ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def interactive_menu() -> str:
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    table.add_column("Option", style="bold yellow")
    table.add_column("Description", style="white")

    table.add_row("[1]", "🔐 Encode - Зашифровать (ML-KEM + AES)")
    table.add_row("[2]", "🔓 Decode - Расшифровать (ML-KEM + AES)")
    table.add_row("[3]", "🔑 KeyGen - Сгенерировать ключи Kyber")
    table.add_row("[4]", "📖 Info   - Информация о программе")
    table.add_row("[0]", "🚪 Exit   - Выход")

    console.print(Panel(table, title="Главное меню", border_style="blue"))
    return Prompt.ask(
        "Выберите действие", choices=["0", "1", "2", "3", "4"], default="1"
    )


def interactive_encode():
    console.print("\n═══ РЕЖИМ ШИФРОВАНИЯ ═══\n")

    console.print("Шаг 1/4: Что вы хотите зашифровать?")
    data_type = Prompt.ask("  Выберите тип", choices=["file", "text"], default="text")

    raw_data: bytes = b""
    filename: str = "message"
    extension: str = ".txt"

    if data_type == "file":
        file_path = ask_path(
            "  Путь к файлу",
            must_exist=True,
            must_be_file=True,
        )
        raw_data = file_path.read_bytes()
        if not raw_data:
            console.print("[red]✗ Файл пуст, нечего шифровать.[/red]")
            return
        filename = file_path.stem
        extension = file_path.suffix
        console.print(f"  ✓ Файл загружен: {human_size(len(raw_data))}")
    else:
        console.print("  Введите текст (пустая строка — конец ввода):")
        lines: list[str] = []
        while True:
            line = Prompt.ask("  ", default="")
            if not line and lines:
                break
            lines.append(line)
            if len(lines) == 1 and line:
                if not Confirm.ask("  Добавить ещё строки?", default=False):
                    break
        raw_data = "\n".join(lines).encode("utf-8")
        if not raw_data.strip():
            console.print("[red]✗ Текст пуст, нечего шифровать.[/red]")
            return

    console.print("\nШаг 2/4: Защита (ML-KEM-768)")
    pubkey_path = ask_path(
        "  Путь к публичному ключу получателя",
        default="public.kyber",
        must_exist=True,
        must_be_file=True,
    )
    public_key = pubkey_path.read_bytes()
    if len(public_key) != KYBER_PK_SIZE:
        console.print(
            f"  ⚠ Предупреждение: размер ключа {len(public_key)} байт, "
            f"ожидалось {KYBER_PK_SIZE}."
        )
    console.print("  ✓ Публичный ключ загружен")

    console.print("\nШаг 3/4: Куда сохранить результат?")
    console.print("  [dim]Допускаются: ./relative, ~/home, C:\\abs, %ENV%\\path[/dim]")
    output_path = ask_path(
        "  Выходной файл",
        default=f"encoded_{sanitize_filename(filename)}.png",
    )

    # Оценка размера
    est = estimate_png_size(len(raw_data))
    console.print(f"\n  📊 Входные данные: {human_size(len(raw_data))}")
    console.print(f"  📊 Оценка PNG:     ~{human_size(est)}")

    console.print("\nШаг 4/4: Подтверждение")
    if not Confirm.ask("\n  Начать шифрование?", default=True):
        return

    try:
        t_start = time.perf_counter()

        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(
                description="Шифрование (ML-KEM-768 + AES-GCM)...", total=None
            )
            encrypted_data = encrypt_data(raw_data, public_key, filename, extension)
            final_path = save_to_png(encrypted_data, output_path)

        elapsed = time.perf_counter() - t_start
        side = math.ceil(math.sqrt(math.ceil(len(encrypted_data) / 3)))

        console.print(
            Panel(
                f"✓ Успех!\n\n"
                f"📁 Файл: {final_path}\n"
                f"📊 Размер: {human_size(len(raw_data))} → "
                f"{human_size(final_path.stat().st_size)} (PNG)\n"
                f"🖼  Изображение: {side}×{side} px\n"
                f"⏱  Время: {elapsed:.2f} сек",
                title="Шифрование завершено",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")

def interactive_decode():
    console.print("\n═══ РЕЖИМ ДЕШИФРОВАНИЯ ═══\n")

    console.print("Шаг 1/3: Выберите изображение")
    image_path = ask_path(
        "  Путь к PNG",
        must_exist=True,
        must_be_file=True,
    )

    console.print("\nШаг 2/3: Дешифровка (ML-KEM-768)")
    privkey_path = ask_path(
        "  Путь к вашему приватному ключу",
        default="private.kyber",
        must_exist=True,
        must_be_file=True,
    )
    private_key = privkey_path.read_bytes()
    if len(private_key) != KYBER_SK_SIZE:
        console.print(
            f"  ⚠ Предупреждение: размер ключа {len(private_key)} байт, "
            f"ожидалось {KYBER_SK_SIZE}."
        )

    console.print("\nШаг 3/3: Директория вывода")
    output_dir = ask_path("  Путь", default=".")
    ensure_dir(output_dir)

    if not Confirm.ask("\n  Начать дешифрование?", default=True):
        return

    try:
        t_start = time.perf_counter()

        raw_bytes = load_from_png(image_path)
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(
                "Декапсуляция Kyber и AES дешифрование...", total=None
            )
            payload = decrypt_data(raw_bytes, private_key)

        elapsed = time.perf_counter() - t_start

        safe_name = sanitize_filename(payload.filename)
        target_path = output_dir / f"{safe_name}{payload.extension}"

        if target_path.exists():
            if not Confirm.ask(
                f"  Файл {target_path.name} существует. Перезаписать?",
                default=False,
            ):
                new_name = Prompt.ask("  Новое имя файла")
                target_path = output_dir / sanitize_filename(new_name)

        target_path.write_bytes(payload.data)

        console.print(
            Panel(
                f"✓ Дешифрование успешно!\n\n"
                f"📁 Сохранено: {target_path}\n"
                f"📊 Размер:    {human_size(len(payload.data))}\n"
                f"⏱  Время:     {elapsed:.2f} сек",
                title="Успех",
                border_style="green",
            )
        )
    except PixelEncoderError as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")
    except Exception as e:
        console.print(f"[bold red]Непредвиденная ошибка:[/bold red] {e}")


def interactive_keygen():
    console.print("\n═══ ГЕНЕРАЦИЯ КЛЮЧЕЙ KYBER (ML-KEM-768) ═══\n")
    console.print(
        Panel(
            "ML-KEM (Kyber) использует асимметричную криптографию.\n"
            "Публичный ключ (public.kyber) передайте тому, кто будет "
            "шифровать для вас.\n"
            "Приватный ключ (private.kyber) храните в секрете для расшифровки.",
            title="💡 Как это работает?",
            border_style="dim",
        )
    )

    console.print("[dim]Допускаются: ./relative, ~/home, C:\\abs, %ENV%\\path[/dim]")
    output_dir = ask_path("Директория сохранения", default=".")
    ensure_dir(output_dir)

    try:
        pub, priv = generate_kyber_keys(output_dir)
        console.print(
            Panel(
                f"✓ Пара ключей создана успешно!\n\n"
                f"🔓 Публичный: {pub} ({human_size(KYBER_PK_SIZE)})\n"
                f"🔐 Приватный: {priv} ({human_size(KYBER_SK_SIZE)})",
                title="KeyGen",
                border_style="green",
            )
        )
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")


def show_info():
    info_text = f"""[bold cyan]PixelEncoder v{APP_VERSION}[/bold cyan]
Post-Quantum Steganography Tool

[bold]Алгоритмы защиты:[/bold]
• [cyan]ML-KEM-768 (FIPS 203)[/cyan] — Постквантовая KEM через liboqs
• [cyan]AES-256-GCM[/cyan] — Симметричное шифрование с аутентификацией
• [cyan]SHA-256[/cyan] — Валидация целостности данных

[bold]Форматы путей (везде):[/bold]
• Относительные:  ./data/file.txt  или  ../keys/pub.kyber
• Домашний каталог: ~/Documents/key.kyber
• Переменные среды: %USERPROFILE%\\keys  или  $HOME/keys
• Абсолютные: C:\\Users\\...  или  /home/user/...

[bold]Как использовать:[/bold]
1. Сгенерируйте пару ключей через KeyGen
2. Передайте public.kyber отправителю
3. Отправитель делает Encode с вашим публичным ключом
4. Вы делаете Decode с полученным PNG и вашим private.kyber

[bold]Переменные окружения:[/bold]
• LIBOQS_DLL_DIR — путь к директории с oqs.dll"""

    console.print(Panel(info_text, title="О программе", border_style="blue"))


def run_interactive_mode():
    show_banner()
    while True:
        console.print()
        choice = interactive_menu()
        if choice == "0":
            break
        elif choice == "1":
            interactive_encode()
        elif choice == "2":
            interactive_decode()
        elif choice == "3":
            interactive_keygen()
        elif choice == "4":
            show_info()

        if choice != "0" and not Confirm.ask(
            "\nВернуться в главное меню?", default=True
        ):
            break
    console.print("\nДо свидания! 👋")

# ══════════════════════════════════════════════════════════════
#                    CLI COMMANDS
# ══════════════════════════════════════════════════════════════

def version_callback(value: bool):
    if value:
        console.print(f"PixelEncoder v{APP_VERSION}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-V", help="Show version", callback=version_callback, is_eager=True),
    ] = None,
):
    if ctx.invoked_subcommand is None:
        run_interactive_mode()


@app.command()
def interactive():
    """🎮 Запустить интерактивный режим."""
    run_interactive_mode()


@app.command()
def keygen(
    output_dir: Annotated[
        Path, typer.Argument(help="Directory to save keys")
    ] = Path("."),
):
    """🔑 Generate an ML-KEM-768 Asymmetric KeyPair."""
    output_dir = resolve_path(output_dir)
    ensure_dir(output_dir)
    pub, priv = generate_kyber_keys(output_dir)
    console.print(
        f"[green]Post-Quantum keys generated in {output_dir}[/green]\n"
        f"  🔓 {pub.name} ({human_size(KYBER_PK_SIZE)})\n"
        f"  🔐 {priv.name} ({human_size(KYBER_SK_SIZE)})"
    )


@app.command()
def encode(
    pubkey: Annotated[Path, typer.Argument(help="Path to public.kyber key")],
    file: Annotated[
        Optional[Path], typer.Option("--file", "-f", help="File to encrypt")
    ] = None,
    text: Annotated[
        Optional[str], typer.Option("--text", "-t", help="Text to encrypt")
    ] = None,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output PNG file")
    ] = Path("encoded.png"),
):
    """🔐 Encrypt data into a PNG using ML-KEM and AES-GCM."""
    if not file and not text:
        console.print("[red]Error: Provide either --file or --text[/red]")
        raise typer.Exit(1)

    pubkey = resolve_path(pubkey)
    validate_file_exists(pubkey, "Public key")
    public_key = pubkey.read_bytes()

    raw_data: bytes = b""
    filename: str = "message"
    extension: str = ".txt"

    if file:
        file = resolve_path(file)
        validate_file_exists(file, "Input file")
        raw_data = file.read_bytes()
        filename, extension = file.stem, file.suffix
    elif text:
        raw_data = text.encode("utf-8")

    output = resolve_path(output)

    try:
        t_start = time.perf_counter()

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), transient=True
        ) as progress:
            progress.add_task(
                description="Hybrid Encrypting (ML-KEM + AES)...", total=None
            )
            encrypted_data = encrypt_data(raw_data, public_key, filename, extension)
            final_path = save_to_png(encrypted_data, output)

        elapsed = time.perf_counter() - t_start

        console.print(
            Panel(
                f"[green]Success![/green]\n"
                f"Saved to: {final_path}\n"
                f"Size: {human_size(len(raw_data))} → "
                f"{human_size(final_path.stat().st_size)}\n"
                f"Time: {elapsed:.2f}s",
                title="Encryption Report",
            )
        )
    except Exception as e:
        console.print(f"[bold red]Critical Error:[/bold red] {e}")
        raise typer.Exit(1)

@app.command()
def decode(
    image: Annotated[Path, typer.Argument(help="Image with hidden data")],
    privkey: Annotated[Path, typer.Argument(help="Path to private.kyber key")],
    output_dir: Annotated[
        Path, typer.Option("--out-dir", "-d", help="Directory to save file")
    ] = Path("."),
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite existing files")
    ] = False,
):
    """🔓 Decrypt data from a PNG using ML-KEM and AES-GCM."""
    image = resolve_path(image)
    privkey = resolve_path(privkey)
    output_dir = resolve_path(output_dir)

    validate_file_exists(image, "Image")
    validate_file_exists(privkey, "Private key")
    ensure_dir(output_dir)

    private_key = privkey.read_bytes()

    try:
        t_start = time.perf_counter()

        raw_bytes = load_from_png(image)
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), transient=True
        ) as progress:
            progress.add_task(
                "Decapsulating Kyber and Verifying Integrity...", total=None
            )
            payload = decrypt_data(raw_bytes, private_key)

        elapsed = time.perf_counter() - t_start

        safe_name = sanitize_filename(payload.filename)
        target_path = output_dir / f"{safe_name}{payload.extension}"

        if target_path.exists() and not force:
            if not Confirm.ask(f"File {target_path.name} exists. Overwrite?"):
                raise typer.Exit(0)

        target_path.write_bytes(payload.data)
        console.print(
            Panel(
                f"[green]Decryption Successful![/green]\n"
                f"File saved: {target_path}\n"
                f"Size: {human_size(len(payload.data))}\n"
                f"Time: {elapsed:.2f}s",
                title="Success",
            )
        )
    except PixelEncoderError as e:
        console.print(f"[bold red]Decryption Failed:[/bold red] {e}")
        raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Unexpected Error:[/bold red] {e}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
