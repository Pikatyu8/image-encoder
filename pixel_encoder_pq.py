#!/usr/bin/env python3
"""
PixelEncoder v6.4 (Post-Quantum Edition - OQS)

Changes in v6.4:
- Dual output format: raw .enc binary + PNG steganographic
- Auto-detection of format on decode
- Smaller output for .enc (no pixel overhead)
- Capacity estimation for both formats
"""

import time
import math
import struct
import secrets
import hashlib
import sys
import re
import os
import json
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
#      АВТОПОДГРУЗКА BUNDLED liboqs
# ══════════════════════════════════════════════════════════════

def _setup_oqs():
    dirs_to_add: list[str] = []
    env_dir = os.environ.get("LIBOQS_DLL_DIR", "")
    if env_dir:
        dirs_to_add.append(str(Path(env_dir).expanduser().resolve()))
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        base = Path(meipass) if meipass else Path(sys.executable).parent
        for sub in ("oqs_native", "oqs", "."):
            d = base / sub if sub != "." else base
            if d.is_dir():
                dirs_to_add.append(str(d))
    else:
        local_libs = Path(__file__).parent / "bundled_libs"
        if local_libs.is_dir():
            dirs_to_add.append(str(local_libs))
    for d in dirs_to_add:
        if hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(d)
            except OSError:
                pass
        os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")

_setup_oqs()
oqs = None
try:
    import oqs
except ImportError:
    print("═" * 60)
    print("ОШИБКА: Библиотека liboqs не найдена!")
    print("  1. Положите oqs.dll рядом с исполняемым файлом")
    print("  2. pip install liboqs-python")
    print("  3. set LIBOQS_DLL_DIR=C:\\path\\to\\dll")
    print("═" * 60)
    sys.exit(1)


# ══════════════════════════════════════════════════════════════
#                    КОНФИГУРАЦИЯ
# ══════════════════════════════════════════════════════════════

APP_VERSION = "6.4.0"
NONCE_SIZE = 12
HASH_SIZE = 32
FORMAT_VERSION = 6

# Магические байты для .enc файлов — быстрое определение формата
ENC_MAGIC = b"PXEN"  # 4 bytes: PixelENcoder

KEM_ALGORITHM = "ML-KEM-768"
KYBER_PK_SIZE = 1184
KYBER_SK_SIZE = 2400
KYBER_CT_SIZE = 1088

MAX_INPUT_SIZE = 100 * 1024 * 1024

_UNSAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

PROFILES_DIR = Path.home() / ".pixelencoder"
PROFILES_FILE = PROFILES_DIR / "profiles.json"

app = typer.Typer(help="PixelEncoder v6.4: Post-Quantum Ciphering Tool")
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
    s = str(raw).strip()
    if s.startswith("& "):
        s = s[2:].strip()
    while len(s) >= 2 and (
        (s[0] == '"' and s[-1] == '"') or
        (s[0] == "'" and s[-1] == "'")
    ):
        s = s[1:-1].strip()
    s = os.path.expandvars(s)
    return Path(s).expanduser().resolve()


def sanitize_filename(name: str) -> str:
    cleaned = _UNSAFE_FILENAME_RE.sub("_", name).strip(". ")
    return cleaned or "unnamed"


def human_size(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    i = min(int(math.floor(math.log(size_bytes, 1024))), len(units) - 1)
    value = size_bytes / (1024 ** i)
    return f"{value:.1f} {units[i]}" if i > 0 else f"{size_bytes} B"


def validate_file_exists(path: Path, label: str = "Файл") -> Path:
    if not path.exists():
        raise FileNotFoundError(f"{label} не найден: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"{label} — это директория: {path}")
    return path


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def ask_path(
    prompt: str,
    default: str = "",
    must_exist: bool = False,
    must_be_file: bool = False,
    must_be_dir: bool = False,
) -> Path:
    while True:
        raw = Prompt.ask(prompt, default=default) if default else Prompt.ask(prompt)
        try:
            p = resolve_path(raw)
        except Exception as e:
            console.print(f"[red]  ✗ Некорректный путь: {e}[/red]")
            continue
        if must_exist and not p.exists():
            console.print(f"[red]  ✗ Не найден: {p}[/red]")
            continue
        if must_be_file and p.exists() and not p.is_file():
            console.print(f"[red]  ✗ Это не файл: {p}[/red]")
            continue
        if must_be_dir and p.exists() and not p.is_dir():
            console.print(f"[red]  ✗ Это не директория: {p}[/red]")
            continue
        return p


# ══════════════════════════════════════════════════════════════
#                    PROFILE MANAGEMENT
# ══════════════════════════════════════════════════════════════

def load_profiles() -> dict:
    try:
        if PROFILES_FILE.exists():
            data = json.loads(PROFILES_FILE.read_text("utf-8"))
            data.setdefault("my_profile", None)
            data.setdefault("contacts", {})
            return data
    except (json.JSONDecodeError, KeyError, OSError):
        pass
    return {"my_profile": None, "contacts": {}}


def save_profiles(profiles: dict) -> None:
    ensure_dir(PROFILES_DIR)
    PROFILES_FILE.write_text(
        json.dumps(profiles, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def show_profiles_summary(profiles: dict) -> None:
    my = profiles.get("my_profile")
    if my:
        pub_p = my.get("public_key", "")
        priv_p = my.get("private_key", "")
        pub_ok = Path(pub_p).exists() if pub_p else False
        priv_ok = Path(priv_p).exists() if priv_p else False
        my_text = (
            f"  Имя:       [cyan]{my['name']}[/cyan]\n"
            f"  Публичный: [dim]{pub_p or 'не указан'}[/dim] "
            f"{'[green]✓[/]' if pub_ok else '[red]✗[/]'}\n"
            f"  Приватный: [dim]{priv_p or 'не указан'}[/dim] "
            f"{'[green]✓[/]' if priv_ok else '[red]✗[/]'}"
        )
    else:
        my_text = "  [dim]Не настроен.[/dim]"
    console.print(Panel(my_text, title="👤 Мой профиль", border_style="cyan"))

    contacts = profiles.get("contacts", {})
    if contacts:
        table = Table(box=box.SIMPLE, padding=(0, 2), show_edge=False)
        table.add_column("#", style="bold yellow", width=4)
        table.add_column("Имя", style="cyan", min_width=14)
        table.add_column("Публичный ключ", style="dim")
        table.add_column("", width=2)
        for i, (name, key_path) in enumerate(contacts.items(), 1):
            exists = Path(key_path).exists()
            table.add_row(
                str(i), name, str(key_path),
                "[green]✓[/]" if exists else "[red]✗[/]",
            )
        console.print(Panel(table, title="📋 Контакты", border_style="blue"))
    else:
        console.print(Panel(
            "  [dim]Контактов нет.[/dim]",
            title="📋 Контакты", border_style="blue",
        ))


def setup_my_profile(profiles: dict) -> None:
    console.print("\n[bold]  Настройка вашего профиля[/bold]\n")
    current = profiles.get("my_profile")
    if current:
        console.print(f"  Текущий: [cyan]{current['name']}[/cyan]")
        if not Confirm.ask("  Перезаписать?", default=True):
            return
    name = Prompt.ask("  Ваше имя", default=current["name"] if current else "User")
    pub_def = current.get("public_key", "public.kyber") if current else "public.kyber"
    pub_path = ask_path("  Путь к публичному ключу", default=pub_def)
    priv_def = current.get("private_key", "private.kyber") if current else "private.kyber"
    priv_path = ask_path("  Путь к приватному ключу", default=priv_def)
    profiles["my_profile"] = {
        "name": name,
        "public_key": str(pub_path),
        "private_key": str(priv_path),
    }
    save_profiles(profiles)
    console.print("  [green]✓ Профиль сохранён![/green]")


def add_contact(profiles: dict) -> None:
    console.print("\n[bold]  Добавление контакта[/bold]\n")
    name = Prompt.ask("  Имя контакта").strip()
    if not name:
        console.print("  [red]✗ Имя пустое.[/red]")
        return
    if name in profiles.get("contacts", {}):
        if not Confirm.ask(f"  «{name}» существует. Обновить?", default=True):
            return
    pub_path = ask_path("  Публичный ключ контакта", must_exist=True, must_be_file=True)
    key_bytes = pub_path.read_bytes()
    if len(key_bytes) != KYBER_PK_SIZE:
        console.print(f"  [yellow]⚠ Размер {len(key_bytes)} B, ожидалось {KYBER_PK_SIZE}[/yellow]")
        if not Confirm.ask("  Сохранить?", default=False):
            return
    profiles.setdefault("contacts", {})[name] = str(pub_path)
    save_profiles(profiles)
    console.print(f"  [green]✓ «{name}» сохранён![/green]")


def delete_contact(profiles: dict) -> None:
    contacts = profiles.get("contacts", {})
    if not contacts:
        console.print("  [dim]Нет контактов.[/dim]")
        return
    names = list(contacts.keys())
    for i, name in enumerate(names, 1):
        console.print(f"  [{i}] {name}")
    choice = Prompt.ask("  Номер", choices=[str(i) for i in range(1, len(names) + 1)])
    target = names[int(choice) - 1]
    if Confirm.ask(f"  Удалить «{target}»?", default=False):
        del profiles["contacts"][target]
        save_profiles(profiles)
        console.print(f"  [green]✓ «{target}» удалён.[/green]")


def select_recipient(profiles: dict) -> bytes | None:
    contacts = profiles.get("contacts", {})
    if contacts:
        console.print()
        table = Table(box=box.SIMPLE, padding=(0, 2), show_edge=False, title="Контакты")
        table.add_column("#", style="bold yellow", width=4)
        table.add_column("Имя", style="cyan", min_width=14)
        table.add_column("Ключ", style="dim")
        table.add_column("", width=2)
        names = list(contacts.keys())
        for i, name in enumerate(names, 1):
            kp = Path(contacts[name])
            table.add_row(str(i), name, str(kp), "[green]✓[/]" if kp.exists() else "[red]✗[/]")
        console.print(table)
        console.print("  [dim][M] Ввести путь вручную[/dim]\n")
        valid = [str(i) for i in range(1, len(names) + 1)] + ["m", "M"]
        choice = Prompt.ask("  Выбор", choices=valid, default="1")
        if choice.upper() != "M":
            idx = int(choice) - 1
            kp = resolve_path(contacts[names[idx]])
            if not kp.exists():
                console.print(f"  [red]✗ Ключ не найден: {kp}[/red]")
                return None
            console.print(f"  ✓ Получатель: [cyan]{names[idx]}[/cyan]")
            return kp.read_bytes()
    if not contacts:
        console.print("  [dim]Контактов нет.[/dim]")
    pubkey_path = ask_path("  Публичный ключ получателя", default="public.kyber",
                           must_exist=True, must_be_file=True)
    return pubkey_path.read_bytes()


def select_my_private_key(profiles: dict) -> bytes | None:
    my = profiles.get("my_profile")
    if my and my.get("private_key"):
        priv_path = resolve_path(my["private_key"])
        console.print(f"  📋 Профиль: [cyan]{my['name']}[/cyan]")
        console.print(f"  🔐 Ключ: [dim]{priv_path}[/dim]")
        if priv_path.exists():
            if Confirm.ask("  Использовать?", default=True):
                return priv_path.read_bytes()
        else:
            console.print(f"  [red]✗ Не найден: {priv_path}[/red]")
    privkey_path = ask_path("  Приватный ключ", default="private.kyber",
                            must_exist=True, must_be_file=True)
    return privkey_path.read_bytes()


# ══════════════════════════════════════════════════════════════
#                    CORE CRYPTO
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


def estimate_enc_size(data_len: int) -> int:
    """Оценка размера .enc файла."""
    # magic(4) + format_version(1) + kyber_ct + nonce + ciphertext_len(4) +
    # AES-GCM(fn_meta + data + hash + tag)
    inner_overhead = 1 + 255 + 1 + 32 + 4 + HASH_SIZE + 16  # max metadata + GCM tag
    return (len(ENC_MAGIC) + 1 + KYBER_CT_SIZE + NONCE_SIZE
            + 4 + data_len + inner_overhead)


def estimate_png_size(data_len: int) -> int:
    enc_size = estimate_enc_size(data_len) - len(ENC_MAGIC)  # PNG не имеет magic
    required_pixels = math.ceil(enc_size / 3)
    side = math.ceil(math.sqrt(required_pixels))
    # PNG сжатие ~70-100% от raw (рандомные данные почти не сжимаются)
    return side * side * 3


def encrypt_data(
    data: bytes,
    public_key: bytes,
    filename: str = "",
    extension: str = "",
) -> bytes:
    """Шифрует данные. Возвращает сырой шифротекст (без magic prefix)."""
    if not data:
        raise ValueError("Данные пусты.")
    if len(data) > MAX_INPUT_SIZE:
        raise ValueError(f"Слишком большой: {human_size(len(data))} (макс {human_size(MAX_INPUT_SIZE)})")

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
        header = struct.pack("<B", FORMAT_VERSION) + kyber_ciphertext + nonce
        aesgcm = AESGCM(bytes(shared_secret_buf))
        ciphertext = aesgcm.encrypt(nonce, inner_data, header)
        return header + struct.pack("<I", len(ciphertext)) + ciphertext
    finally:
        secure_zero(shared_secret_buf)


def decrypt_data(encrypted: bytes, private_key: bytes) -> DecryptedPayload:
    offset = 0
    if len(encrypted) < 1:
        raise FormatError("Данные пусты.")

    version = encrypted[offset]
    if version != FORMAT_VERSION:
        raise FormatError(f"Неподдерживаемая версия: {version}")
    offset += 1

    min_len = offset + KYBER_CT_SIZE + NONCE_SIZE + 4
    if len(encrypted) < min_len:
        raise FormatError(f"Данные слишком короткие ({human_size(len(encrypted))})")

    kyber_ct = encrypted[offset:offset + KYBER_CT_SIZE]; offset += KYBER_CT_SIZE
    nonce = encrypted[offset:offset + NONCE_SIZE]; offset += NONCE_SIZE
    ct_len = struct.unpack("<I", encrypted[offset:offset + 4])[0]; offset += 4
    ciphertext = encrypted[offset:offset + ct_len]
    header = encrypted[:offset - 4]

    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(kyber_ct)
    except Exception as e:
        raise CryptoError(f"Kyber decapsulation failed: {e}")

    shared_secret_buf = bytearray(shared_secret)
    try:
        aesgcm = AESGCM(bytes(shared_secret_buf))
        inner_data = aesgcm.decrypt(nonce, ciphertext, header)
    except Exception:
        raise CryptoError("AES-GCM: неверный ключ или повреждение")
    finally:
        secure_zero(shared_secret_buf)

    ptr = 0
    fn_len = inner_data[ptr]; ptr += 1
    filename = inner_data[ptr:ptr + fn_len].decode("utf-8"); ptr += fn_len
    ext_len = inner_data[ptr]; ptr += 1
    extension = inner_data[ptr:ptr + ext_len].decode("utf-8"); ptr += ext_len
    data_len = struct.unpack("<I", inner_data[ptr:ptr + 4])[0]; ptr += 4
    data = inner_data[ptr:ptr + data_len]; ptr += data_len
    stored_hash = inner_data[ptr:ptr + HASH_SIZE]

    if not secrets.compare_digest(hashlib.sha256(data).digest(), stored_hash):
        raise IntegrityError("Целостность нарушена!")

    filename = sanitize_filename(filename)
    extension = sanitize_filename(extension)
    if extension and not extension.startswith("."):
        extension = "." + extension
    return DecryptedPayload(data, filename, extension)


# ══════════════════════════════════════════════════════════════
#          OUTPUT FORMATS: .enc (binary) и .png (image)
# ══════════════════════════════════════════════════════════════

def save_to_enc(data: bytes, path: Path) -> Path:
    """Сохраняет шифротекст как сырой бинарный файл с magic header."""
    target = path.with_suffix(".enc")
    ensure_dir(target.parent)
    target.write_bytes(ENC_MAGIC + data)
    return target


def load_from_enc(path: Path) -> bytes:
    """Читает .enc файл, проверяет magic, возвращает шифротекст."""
    path = validate_file_exists(path, "Файл .enc")
    raw = path.read_bytes()
    if not raw.startswith(ENC_MAGIC):
        raise FormatError(
            f"Файл не является PixelEncoder .enc (нет magic bytes)"
        )
    return raw[len(ENC_MAGIC):]


def save_to_png(data: bytes, path: Path) -> Path:
    """Сохраняет шифротекст как PNG-изображение."""
    required_pixels = math.ceil(len(data) / 3)
    side = math.ceil(math.sqrt(required_pixels))
    padded_len = side * side * 3
    full_data = data + secrets.token_bytes(padded_len - len(data))
    img = Image.frombytes("RGB", (side, side), full_data)
    target = path.with_suffix(".png")
    ensure_dir(target.parent)
    img.save(target, "PNG", compress_level=9)
    return target


def load_from_png(path: Path) -> bytes:
    """Извлекает байты из PNG-изображения."""
    path = validate_file_exists(path, "Изображение")
    with Image.open(path) as img:
        img = img.convert("RGB")
        return img.tobytes()


def detect_and_load(path: Path) -> bytes:
    """Автоопределение формата: .enc или .png."""
    path = validate_file_exists(path, "Входной файл")

    # Проверяем magic bytes
    with open(path, "rb") as f:
        header = f.read(4)

    if header == ENC_MAGIC:
        console.print(f"  📦 Формат: [cyan].enc (бинарный)[/cyan]")
        return load_from_enc(path)

    # Пробуем как PNG
    if header[:4] == b'\x89PNG' or path.suffix.lower() == ".png":
        console.print(f"  🖼  Формат: [cyan].png (изображение)[/cyan]")
        return load_from_png(path)

    # Если расширение .enc но без magic — попробовать как сырой
    if path.suffix.lower() == ".enc":
        console.print(f"  📦 Формат: [cyan].enc (без magic, legacy)[/cyan]")
        raw = path.read_bytes()
        if raw.startswith(ENC_MAGIC):
            return raw[len(ENC_MAGIC):]
        return raw

    # Fallback: пробуем как PNG
    console.print(f"  [yellow]⚠ Неизвестный формат, пробую как PNG…[/yellow]")
    return load_from_png(path)


# ══════════════════════════════════════════════════════════════
#                    INTERACTIVE UI
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
║          v{APP_VERSION} — Post-Quantum Ciphering                      ║
╚═══════════════════════════════════════════════════════════════╝"""
    console.print(banner, style="bold cyan")


def show_info():
    info_text = f"""[bold cyan]PixelEncoder v{APP_VERSION}[/bold cyan] — Post-Quantum Ciphering Tool

[bold]Алгоритмы:[/bold]
  • [cyan]ML-KEM-768 (FIPS 203)[/cyan] — постквантовая KEM
  • [cyan]AES-256-GCM[/cyan] — шифрование + аутентификация
  • [cyan]SHA-256[/cyan] — контроль целостности

[bold]Форматы вывода:[/bold]
  • [green].enc[/green] — компактный бинарный файл (рекомендуется)
  • [yellow].png[/yellow] — шифротекст в пикселях изображения

[bold]Как пользоваться:[/bold]
  1. 🔑 KeyGen   — сгенерируйте ключи
  2. 👤 Profiles — настройте профиль и контакты
  3. 🔐 Encode   — зашифруйте файл/текст
  4. 🔓 Decode   — расшифруйте (авто-определение формата)"""
    console.print(Panel(info_text, border_style="blue", padding=(1, 2)))


def render_nav():
    tabs = Table(show_header=False, box=box.ROUNDED, padding=(0, 2),
                 expand=True, style="bold")
    tabs.add_column(justify="center", style="yellow")
    tabs.add_column(justify="center", style="yellow")
    tabs.add_column(justify="center", style="yellow")
    tabs.add_column(justify="center", style="green")
    tabs.add_column(justify="center", style="red")
    tabs.add_row("1  🔐 Encode", "2  🔓 Decode", "3  🔑 KeyGen",
                 "4  👤 Profiles", "0  🚪 Exit")
    console.print(tabs)


# ── Encode ──

def interactive_encode():
    profiles = load_profiles()
    console.print("\n[bold cyan]═══ 🔐 ШИФРОВАНИЕ ═══[/bold cyan]\n")

    # Получатель
    console.print("[bold]Шаг 1/5 · Получатель[/bold]")
    public_key = select_recipient(profiles)
    if public_key is None:
        return
    if len(public_key) != KYBER_PK_SIZE:
        console.print(f"  [yellow]⚠ Размер {len(public_key)} B ≠ {KYBER_PK_SIZE}[/yellow]")
    console.print("  [green]✓[/green] Ключ загружен\n")

    # Данные
    console.print("[bold]Шаг 2/5 · Данные[/bold]")
    data_type = Prompt.ask("  Тип", choices=["file", "text"], default="text")

    raw_data: bytes = b""
    filename: str = "message"
    extension: str = ".txt"

    if data_type == "file":
        file_path = ask_path("  Файл", must_exist=True, must_be_file=True)
        raw_data = file_path.read_bytes()
        if not raw_data:
            console.print("[red]  ✗ Файл пуст.[/red]")
            return
        filename = file_path.stem
        extension = file_path.suffix
        console.print(f"  ✓ {human_size(len(raw_data))}")
    else:
        console.print("  Текст (пустая строка → конец):")
        lines: list[str] = []
        while True:
            line = Prompt.ask("  ", default="")
            if not line and lines:
                break
            lines.append(line)
            if len(lines) == 1 and line:
                if not Confirm.ask("  Ещё?", default=False):
                    break
        raw_data = "\n".join(lines).encode("utf-8")
        if not raw_data.strip():
            console.print("[red]  ✗ Пусто.[/red]")
            return

    # Формат вывода
    console.print(f"\n[bold]Шаг 3/5 · Формат вывода[/bold]")
    console.print("  [green][1] .enc[/green] — бинарный (компактный, рекомендуется)")
    console.print("  [yellow][2] .png[/yellow] — изображение (больше размер)")

    fmt_choice = Prompt.ask("  Формат", choices=["1", "2"], default="1")
    use_png = (fmt_choice == "2")
    default_ext = ".png" if use_png else ".enc"

    # Путь вывода
    console.print(f"\n[bold]Шаг 4/5 · Выходной файл[/bold]")
    output_path = ask_path(
        "  Путь",
        default=f"encoded_{sanitize_filename(filename)}{default_ext}",
    )

    # Оценка размера
    if use_png:
        est = estimate_png_size(len(raw_data))
    else:
        est = estimate_enc_size(len(raw_data))
    console.print(f"\n  📊 Вход: {human_size(len(raw_data))}  →  ~{human_size(est)} ({default_ext})")

    # Подтверждение
    console.print(f"\n[bold]Шаг 5/5 · Подтверждение[/bold]")
    if not Confirm.ask("  Шифровать?", default=True):
        return

    try:
        t0 = time.perf_counter()
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            p.add_task("ML-KEM-768 + AES-256-GCM …", total=None)
            encrypted = encrypt_data(raw_data, public_key, filename, extension)

            if use_png:
                final = save_to_png(encrypted, output_path)
            else:
                final = save_to_enc(encrypted, output_path)

        dt = time.perf_counter() - t0
        final_size = final.stat().st_size

        extra = ""
        if use_png:
            side = math.ceil(math.sqrt(math.ceil(len(encrypted) / 3)))
            extra = f"\n🖼  Изображение: {side}×{side} px"

        console.print(Panel(
            f"✓ Зашифровано!\n\n"
            f"📁 Файл:   {final}\n"
            f"📊 Размер: {human_size(len(raw_data))} → {human_size(final_size)}"
            f"{extra}\n"
            f"⏱  Время:  {dt:.2f} сек",
            title="Шифрование завершено",
            border_style="green",
        ))
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")


# ── Decode ──

def interactive_decode():
    profiles = load_profiles()
    console.print("\n[bold cyan]═══ 🔓 ДЕШИФРОВАНИЕ ═══[/bold cyan]\n")

    console.print("[bold]Шаг 1/3 · Входной файл (.enc или .png)[/bold]")
    input_path = ask_path("  Файл", must_exist=True, must_be_file=True)

    console.print(f"\n[bold]Шаг 2/3 · Приватный ключ[/bold]")
    private_key = select_my_private_key(profiles)
    if private_key is None:
        return
    if len(private_key) != KYBER_SK_SIZE:
        console.print(f"  [yellow]⚠ Размер {len(private_key)} B ≠ {KYBER_SK_SIZE}[/yellow]")

    console.print(f"\n[bold]Шаг 3/3 · Директория вывода[/bold]")
    output_dir = ask_path("  Путь", default=".")
    ensure_dir(output_dir)

    if not Confirm.ask("\n  Дешифровать?", default=True):
        return

    try:
        t0 = time.perf_counter()

        # Автоопределение формата
        raw = detect_and_load(input_path)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            p.add_task("Kyber decap + AES-GCM …", total=None)
            payload = decrypt_data(raw, private_key)

        dt = time.perf_counter() - t0

        safe = sanitize_filename(payload.filename)
        target = output_dir / f"{safe}{payload.extension}"

        if target.exists():
            if not Confirm.ask(f"  {target.name} существует. Перезаписать?", default=False):
                new_name = Prompt.ask("  Новое имя")
                target = output_dir / sanitize_filename(new_name)

        target.write_bytes(payload.data)

        console.print(Panel(
            f"✓ Расшифровано!\n\n"
            f"📁 Сохранено: {target}\n"
            f"📊 Размер:    {human_size(len(payload.data))}\n"
            f"⏱  Время:     {dt:.2f} сек",
            title="Дешифрование завершено",
            border_style="green",
        ))
    except PixelEncoderError as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")
    except Exception as e:
        console.print(f"[bold red]Непредвиденная ошибка:[/bold red] {e}")


# ── KeyGen ──

def interactive_keygen():
    console.print("\n[bold cyan]═══ 🔑 ГЕНЕРАЦИЯ КЛЮЧЕЙ ═══[/bold cyan]\n")
    output_dir = ask_path("  Директория", default=".")
    ensure_dir(output_dir)
    try:
        pub, priv = generate_kyber_keys(output_dir)
        console.print(Panel(
            f"✓ Ключи созданы!\n\n"
            f"🔓 Публичный: {pub} ({human_size(KYBER_PK_SIZE)})\n"
            f"🔐 Приватный: {priv} ({human_size(KYBER_SK_SIZE)})",
            title="KeyGen", border_style="green",
        ))
        if Confirm.ask("\n  Сохранить как профиль?", default=False):
            name = Prompt.ask("  Имя", default="My Profile")
            profiles = load_profiles()
            profiles["my_profile"] = {
                "name": name,
                "public_key": str(pub),
                "private_key": str(priv),
            }
            save_profiles(profiles)
            console.print("  [green]✓ Сохранено![/green]")
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")


# ── Profiles ──

def interactive_profiles():
    while True:
        profiles = load_profiles()
        console.print("\n[bold cyan]═══ 👤 ПРОФИЛИ ═══[/bold cyan]\n")
        show_profiles_summary(profiles)
        console.print()
        menu = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        menu.add_column(style="bold yellow", width=4)
        menu.add_column()
        menu.add_row("[1]", "👤  Мой профиль")
        menu.add_row("[2]", "➕  Добавить контакт")
        menu.add_row("[3]", "🗑️   Удалить контакт")
        menu.add_row("[0]", "↩️   Назад")
        console.print(menu)
        choice = Prompt.ask("  Действие", choices=["0", "1", "2", "3"], default="0")
        if choice == "0":
            break
        elif choice == "1":
            setup_my_profile(profiles)
        elif choice == "2":
            add_contact(profiles)
        elif choice == "3":
            delete_contact(profiles)


# ── Main loop ──

def run_interactive_mode():
    show_banner()
    show_info()
    while True:
        console.print()
        render_nav()
        choice = Prompt.ask("  Вкладка", choices=["0", "1", "2", "3", "4"], default="1")
        if choice == "0":
            break
        elif choice == "1":
            interactive_encode()
        elif choice == "2":
            interactive_decode()
        elif choice == "3":
            interactive_keygen()
        elif choice == "4":
            interactive_profiles()
    console.print("\nДо свидания! 👋\n")


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
    version: Annotated[Optional[bool], typer.Option(
        "--version", "-V", help="Show version",
        callback=version_callback, is_eager=True,
    )] = None,
):
    if ctx.invoked_subcommand is None:
        run_interactive_mode()


@app.command()
def interactive():
    """🎮 Интерактивный режим."""
    run_interactive_mode()


@app.command()
def keygen(
    output_dir: Annotated[Path, typer.Argument(help="Directory")] = Path("."),
):
    """🔑 Generate ML-KEM-768 keypair."""
    output_dir = resolve_path(output_dir)
    ensure_dir(output_dir)
    pub, priv = generate_kyber_keys(output_dir)
    console.print(f"[green]Keys generated in {output_dir}[/green]")


@app.command()
def encode(
    pubkey: Annotated[Path, typer.Argument(help="Public key")],
    file: Annotated[Optional[Path], typer.Option("--file", "-f")] = None,
    text: Annotated[Optional[str], typer.Option("--text", "-t")] = None,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("encoded.enc"),
    fmt: Annotated[str, typer.Option(
        "--format", help="Output format: enc or png"
    )] = "enc",
):
    """🔐 Encrypt data (ML-KEM + AES-GCM). Formats: enc, png."""
    if not file and not text:
        console.print("[red]Provide --file or --text[/red]")
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
        t0 = time.perf_counter()
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            p.add_task("Encrypting…", total=None)
            encrypted = encrypt_data(raw_data, public_key, filename, extension)

            if fmt.lower() == "png":
                final = save_to_png(encrypted, output)
            else:
                final = save_to_enc(encrypted, output)

        dt = time.perf_counter() - t0
        console.print(Panel(
            f"[green]Done![/green] → {final}\n"
            f"Size: {human_size(len(raw_data))} → {human_size(final.stat().st_size)}\n"
            f"Time: {dt:.2f}s",
            title="Encrypted",
        ))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def decode(
    input_file: Annotated[Path, typer.Argument(help=".enc or .png file")],
    privkey: Annotated[Path, typer.Argument(help="Private key")],
    output_dir: Annotated[Path, typer.Option("--out-dir", "-d")] = Path("."),
    force: Annotated[bool, typer.Option("--force")] = False,
):
    """🔓 Decrypt data from .enc or .png (auto-detected)."""
    input_file = resolve_path(input_file)
    privkey = resolve_path(privkey)
    output_dir = resolve_path(output_dir)

    validate_file_exists(input_file, "Input")
    validate_file_exists(privkey, "Private key")
    ensure_dir(output_dir)

    private_key = privkey.read_bytes()

    try:
        t0 = time.perf_counter()
        raw = detect_and_load(input_file)
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            p.add_task("Decrypting…", total=None)
            payload = decrypt_data(raw, private_key)
        dt = time.perf_counter() - t0

        safe = sanitize_filename(payload.filename)
        target = output_dir / f"{safe}{payload.extension}"

        if target.exists() and not force:
            if not Confirm.ask(f"Overwrite {target.name}?"):
                raise typer.Exit(0)

        target.write_bytes(payload.data)
        console.print(Panel(
            f"[green]Decrypted![/green] → {target}\n"
            f"Size: {human_size(len(payload.data))}\nTime: {dt:.2f}s",
            title="Success",
        ))
    except PixelEncoderError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Unexpected:[/bold red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
