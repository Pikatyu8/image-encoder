#!/usr/bin/env python3
"""
PixelEncoder v6.3 (Post-Quantum Edition - OQS)

Compliance:
- FIPS 203 (ML-KEM-768) via liboqs-python
- AES-256-GCM for symmetric payload encryption
- PEP 585/604 (Modern Typing)

Changes in v6.3:
- Tabbed interactive UI
- User/contact profile management with key paths
- Auto-display info on startup
- Profile-aware encode/decode workflows
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
#      АВТОПОДГРУЗКА BUNDLED liboqs (+ fallback на переменную)
# ══════════════════════════════════════════════════════════════

def _setup_oqs():
    """Настраивает пути для поиска oqs.dll ДО импорта oqs."""
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
    print()
    print("Возможные решения:")
    print("  1. Положите oqs.dll рядом с исполняемым файлом")
    print("  2. Установите: pip install liboqs-python")
    print("  3. Задайте переменную: set LIBOQS_DLL_DIR=C:\\path\\to\\dll")
    print("═" * 60)
    sys.exit(1)


# ══════════════════════════════════════════════════════════════
#                    КОНФИГУРАЦИЯ И КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════

APP_VERSION = "6.3.0"
NONCE_SIZE = 12
HASH_SIZE = 32
FORMAT_VERSION = 6

KEM_ALGORITHM = "ML-KEM-768"
KYBER_PK_SIZE = 1184
KYBER_SK_SIZE = 2400
KYBER_CT_SIZE = 1088

MAX_INPUT_SIZE = 100 * 1024 * 1024

_UNSAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

PROFILES_DIR = Path.home() / ".pixelencoder"
PROFILES_FILE = PROFILES_DIR / "profiles.json"

app = typer.Typer(help="PixelEncoder v6.3: Post-Quantum Ciphering Tool")
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
    p = Path(s).expanduser().resolve()
    return p


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
        raise IsADirectoryError(f"{label} — это директория, а не файл: {path}")
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
            console.print(f"    [dim]Введено: {raw!r} → {p}[/dim]")
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
    """
    Формат profiles.json:
    {
      "my_profile": {"name": "...", "public_key": "...", "private_key": "..."}  | null,
      "contacts": {"Alice": "/path/to/pub.kyber", "Bob": "..."}
    }
    """
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
        json.dumps(profiles, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def show_profiles_summary(profiles: dict) -> None:
    """Красивый вывод всех профилей."""
    my = profiles.get("my_profile")

    # ── Мой профиль ──
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
        my_text = "  [dim]Не настроен. Выберите «Настроить мой профиль».[/dim]"

    console.print(Panel(my_text, title="👤 Мой профиль", border_style="cyan"))

    # ── Контакты ──
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
            "  [dim]Контактов нет. Добавьте через «Добавить контакт».[/dim]",
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
    if not pub_path.exists():
        console.print(f"  [yellow]⚠ Файл пока не существует: {pub_path}[/yellow]")

    priv_def = current.get("private_key", "private.kyber") if current else "private.kyber"
    priv_path = ask_path("  Путь к приватному ключу", default=priv_def)
    if not priv_path.exists():
        console.print(f"  [yellow]⚠ Файл пока не существует: {priv_path}[/yellow]")

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
        console.print("  [red]✗ Имя не может быть пустым.[/red]")
        return

    if name in profiles.get("contacts", {}):
        if not Confirm.ask(f"  Контакт «{name}» уже существует. Обновить?", default=True):
            return

    pub_path = ask_path(
        "  Путь к публичному ключу контакта",
        must_exist=True,
        must_be_file=True,
    )

    key_bytes = pub_path.read_bytes()
    if len(key_bytes) != KYBER_PK_SIZE:
        console.print(
            f"  [yellow]⚠ Размер ключа {len(key_bytes)} B, "
            f"ожидалось {KYBER_PK_SIZE} B (ML-KEM-768).[/yellow]"
        )
        if not Confirm.ask("  Всё равно сохранить?", default=False):
            return

    profiles.setdefault("contacts", {})[name] = str(pub_path)
    save_profiles(profiles)
    console.print(f"  [green]✓ Контакт «{name}» сохранён![/green]")


def delete_contact(profiles: dict) -> None:
    contacts = profiles.get("contacts", {})
    if not contacts:
        console.print("  [dim]Нет контактов для удаления.[/dim]")
        return

    console.print("\n[bold]  Удаление контакта[/bold]\n")
    names = list(contacts.keys())
    for i, name in enumerate(names, 1):
        console.print(f"  [{i}] {name}")

    choice = Prompt.ask(
        "  Номер",
        choices=[str(i) for i in range(1, len(names) + 1)],
    )
    target = names[int(choice) - 1]

    if Confirm.ask(f"  Удалить «{target}»?", default=False):
        del profiles["contacts"][target]
        save_profiles(profiles)
        console.print(f"  [green]✓ Контакт «{target}» удалён.[/green]")


# ── Выбор получателя / своего ключа для encode/decode ──

def select_recipient(profiles: dict) -> bytes | None:
    """Выбрать контакт или ввести путь вручную. Возвращает public key bytes."""
    contacts = profiles.get("contacts", {})

    if contacts:
        console.print()
        table = Table(
            box=box.SIMPLE, padding=(0, 2), show_edge=False,
            title="Контакты",
        )
        table.add_column("#", style="bold yellow", width=4)
        table.add_column("Имя", style="cyan", min_width=14)
        table.add_column("Ключ", style="dim")
        table.add_column("", width=2)

        names = list(contacts.keys())
        for i, name in enumerate(names, 1):
            kp = Path(contacts[name])
            table.add_row(
                str(i), name, str(kp),
                "[green]✓[/]" if kp.exists() else "[red]✗[/]",
            )
        console.print(table)
        console.print("  [dim][M] Ввести путь вручную[/dim]\n")

        valid = [str(i) for i in range(1, len(names) + 1)] + ["m", "M"]
        choice = Prompt.ask("  Выбор", choices=valid, default="1")

        if choice.upper() != "M":
            idx = int(choice) - 1
            name = names[idx]
            kp = resolve_path(contacts[name])
            if not kp.exists():
                console.print(f"  [red]✗ Ключ не найден: {kp}[/red]")
                return None
            console.print(f"  ✓ Получатель: [cyan]{name}[/cyan]")
            return kp.read_bytes()

    if not contacts:
        console.print("  [dim]Контактов нет. Добавьте во вкладке «Профили».[/dim]")

    pubkey_path = ask_path(
        "  Путь к публичному ключу получателя",
        default="public.kyber",
        must_exist=True,
        must_be_file=True,
    )
    return pubkey_path.read_bytes()


def select_my_private_key(profiles: dict) -> bytes | None:
    """Предложить свой профиль или ввести путь вручную."""
    my = profiles.get("my_profile")

    if my and my.get("private_key"):
        priv_path = resolve_path(my["private_key"])
        console.print(f"  📋 Ваш профиль: [cyan]{my['name']}[/cyan]")
        console.print(f"  🔐 Приватный ключ: [dim]{priv_path}[/dim]")

        if priv_path.exists():
            if Confirm.ask("  Использовать этот ключ?", default=True):
                return priv_path.read_bytes()
        else:
            console.print(f"  [red]✗ Файл не найден: {priv_path}[/red]")

    privkey_path = ask_path(
        "  Путь к приватному ключу",
        default="private.kyber",
        must_exist=True,
        must_be_file=True,
    )
    return privkey_path.read_bytes()


# ══════════════════════════════════════════════════════════════
#                    CORE CRYPTO LOGIC
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
    overhead = 1 + KYBER_CT_SIZE + NONCE_SIZE + 4 + 16
    total = data_len + overhead + 256 + HASH_SIZE
    required_pixels = math.ceil(total / 3)
    side = math.ceil(math.sqrt(required_pixels))
    return side * side * 3


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
        header = struct.pack("<B", FORMAT_VERSION) + kyber_ciphertext + nonce
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
            f"Минимум: {human_size(min_len)}."
        )

    kyber_ciphertext = encrypted[offset : offset + KYBER_CT_SIZE]; offset += KYBER_CT_SIZE
    nonce = encrypted[offset : offset + NONCE_SIZE]; offset += NONCE_SIZE
    ciphertext_len = struct.unpack("<I", encrypted[offset : offset + 4])[0]; offset += 4
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
  • [cyan]ML-KEM-768 (FIPS 203)[/cyan] — постквантовая KEM (liboqs)
  • [cyan]AES-256-GCM[/cyan] — симметричное шифрование + аутентификация
  • [cyan]SHA-256[/cyan] — контроль целостности

[bold]Как пользоваться:[/bold]
  1. 🔑 [bold]KeyGen[/bold]  — сгенерируйте пару ключей
  2. 👤 [bold]Profiles[/bold] — настройте свой профиль и добавьте контакты
  3. 🔐 [bold]Encode[/bold]  — зашифруйте файл/текст для контакта
  4. 🔓 [bold]Decode[/bold]  — расшифруйте PNG своим приватным ключом

[bold]Форматы путей:[/bold]  ./relative  ~/home  C:\\absolute  %ENV%\\path

[bold]Окружение:[/bold]  LIBOQS_DLL_DIR — путь к oqs.dll"""

    console.print(Panel(info_text, border_style="blue", padding=(1, 2)))


def render_nav():
    tabs = Table(
        show_header=False,
        box=box.ROUNDED,
        padding=(0, 2),
        expand=True,
        style="bold",
    )
    tabs.add_column(justify="center", style="yellow")
    tabs.add_column(justify="center", style="yellow")
    tabs.add_column(justify="center", style="yellow")
    tabs.add_column(justify="center", style="green")
    tabs.add_column(justify="center", style="red")
    tabs.add_row(
        "1  🔐 Encode",
        "2  🔓 Decode",
        "3  🔑 KeyGen",
        "4  👤 Profiles",
        "0  🚪 Exit",
    )
    console.print(tabs)


# ── Вкладка 1: Encode ──

def interactive_encode():
    profiles = load_profiles()
    console.print("\n[bold cyan]═══ 🔐 ШИФРОВАНИЕ (ML-KEM-768 + AES-256-GCM) ═══[/bold cyan]\n")

    # ── Шаг 1: Получатель ──
    console.print("[bold]Шаг 1/4 · Получатель[/bold]")
    public_key = select_recipient(profiles)
    if public_key is None:
        return
    if len(public_key) != KYBER_PK_SIZE:
        console.print(
            f"  [yellow]⚠ Размер ключа {len(public_key)} B, "
            f"ожидалось {KYBER_PK_SIZE} B[/yellow]"
        )
    console.print("  [green]✓[/green] Публичный ключ загружен\n")

    # ── Шаг 2: Данные ──
    console.print("[bold]Шаг 2/4 · Данные для шифрования[/bold]")
    data_type = Prompt.ask("  Тип", choices=["file", "text"], default="text")

    raw_data: bytes = b""
    filename: str = "message"
    extension: str = ".txt"

    if data_type == "file":
        file_path = ask_path("  Путь к файлу", must_exist=True, must_be_file=True)
        raw_data = file_path.read_bytes()
        if not raw_data:
            console.print("[red]  ✗ Файл пуст.[/red]")
            return
        filename = file_path.stem
        extension = file_path.suffix
        console.print(f"  ✓ Загружено: {human_size(len(raw_data))}")
    else:
        console.print("  Введите текст (пустая строка → конец):")
        lines: list[str] = []
        while True:
            line = Prompt.ask("  ", default="")
            if not line and lines:
                break
            lines.append(line)
            if len(lines) == 1 and line:
                if not Confirm.ask("  Ещё строки?", default=False):
                    break
        raw_data = "\n".join(lines).encode("utf-8")
        if not raw_data.strip():
            console.print("[red]  ✗ Текст пуст.[/red]")
            return

    # ── Шаг 3: Выход ──
    console.print(f"\n[bold]Шаг 3/4 · Выходной файл[/bold]")
    console.print("  [dim]Допускаются: ./relative, ~/home, C:\\abs, %ENV%\\path[/dim]")
    output_path = ask_path(
        "  Путь",
        default=f"encoded_{sanitize_filename(filename)}.png",
    )

    est = estimate_png_size(len(raw_data))
    console.print(f"\n  📊 Вход: {human_size(len(raw_data))}  →  ~{human_size(est)} (PNG)")

    # ── Шаг 4: Подтверждение ──
    console.print(f"\n[bold]Шаг 4/4 · Подтверждение[/bold]")
    if not Confirm.ask("  Начать шифрование?", default=True):
        return

    try:
        t0 = time.perf_counter()
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            p.add_task("ML-KEM-768 + AES-256-GCM …", total=None)
            encrypted = encrypt_data(raw_data, public_key, filename, extension)
            final = save_to_png(encrypted, output_path)
        dt = time.perf_counter() - t0
        side = math.ceil(math.sqrt(math.ceil(len(encrypted) / 3)))

        console.print(Panel(
            f"✓ Зашифровано!\n\n"
            f"📁 Файл:       {final}\n"
            f"📊 Размер:     {human_size(len(raw_data))} → "
            f"{human_size(final.stat().st_size)} (PNG)\n"
            f"🖼  Изображение: {side}×{side} px\n"
            f"⏱  Время:       {dt:.2f} сек",
            title="Шифрование завершено",
            border_style="green",
        ))
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")


# ── Вкладка 2: Decode ──

def interactive_decode():
    profiles = load_profiles()
    console.print("\n[bold cyan]═══ 🔓 ДЕШИФРОВАНИЕ (ML-KEM-768 + AES-256-GCM) ═══[/bold cyan]\n")

    # ── Шаг 1: Изображение ──
    console.print("[bold]Шаг 1/3 · Выберите изображение[/bold]")
    image_path = ask_path("  PNG файл", must_exist=True, must_be_file=True)

    # ── Шаг 2: Приватный ключ ──
    console.print("\n[bold]Шаг 2/3 · Приватный ключ[/bold]")
    private_key = select_my_private_key(profiles)
    if private_key is None:
        return
    if len(private_key) != KYBER_SK_SIZE:
        console.print(
            f"  [yellow]⚠ Размер ключа {len(private_key)} B, "
            f"ожидалось {KYBER_SK_SIZE} B[/yellow]"
        )

    # ── Шаг 3: Директория ──
    console.print("\n[bold]Шаг 3/3 · Директория вывода[/bold]")
    output_dir = ask_path("  Путь", default=".")
    ensure_dir(output_dir)

    if not Confirm.ask("\n  Начать дешифрование?", default=True):
        return

    try:
        t0 = time.perf_counter()
        raw = load_from_png(image_path)
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            p.add_task("Декапсуляция Kyber + AES-GCM …", total=None)
            payload = decrypt_data(raw, private_key)
        dt = time.perf_counter() - t0

        safe = sanitize_filename(payload.filename)
        target = output_dir / f"{safe}{payload.extension}"

        if target.exists():
            if not Confirm.ask(
                f"  Файл {target.name} существует. Перезаписать?", default=False
            ):
                new_name = Prompt.ask("  Новое имя файла")
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


# ── Вкладка 3: KeyGen ──

def interactive_keygen():
    console.print("\n[bold cyan]═══ 🔑 ГЕНЕРАЦИЯ КЛЮЧЕЙ ML-KEM-768 ═══[/bold cyan]\n")
    console.print(Panel(
        "ML-KEM (Kyber) — асимметричная криптография.\n"
        "[bold]public.kyber[/bold]  → передайте отправителю.\n"
        "[bold]private.kyber[/bold] → храните в секрете для расшифровки.",
        title="💡 Справка",
        border_style="dim",
    ))

    console.print("  [dim]Допускаются: ./relative, ~/home, C:\\abs, %ENV%\\path[/dim]")
    output_dir = ask_path("  Директория для ключей", default=".")
    ensure_dir(output_dir)

    try:
        pub, priv = generate_kyber_keys(output_dir)
        console.print(Panel(
            f"✓ Пара ключей создана!\n\n"
            f"🔓 Публичный: {pub} ({human_size(KYBER_PK_SIZE)})\n"
            f"🔐 Приватный: {priv} ({human_size(KYBER_SK_SIZE)})",
            title="KeyGen",
            border_style="green",
        ))

        # Предложить сохранить как профиль
        if Confirm.ask("\n  Сохранить как ваш профиль?", default=False):
            name = Prompt.ask("  Имя профиля", default="My Profile")
            profiles = load_profiles()
            profiles["my_profile"] = {
                "name": name,
                "public_key": str(pub),
                "private_key": str(priv),
            }
            save_profiles(profiles)
            console.print("  [green]✓ Профиль сохранён![/green]")

    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")


# ── Вкладка 4: Profiles ──

def interactive_profiles():
    while True:
        profiles = load_profiles()
        console.print("\n[bold cyan]═══ 👤 УПРАВЛЕНИЕ ПРОФИЛЯМИ ═══[/bold cyan]\n")

        show_profiles_summary(profiles)

        console.print()
        menu = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        menu.add_column(style="bold yellow", width=4)
        menu.add_column()
        menu.add_row("[1]", "👤  Настроить мой профиль")
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


# ── Главный цикл ──

def run_interactive_mode():
    show_banner()
    show_info()

    while True:
        console.print()
        render_nav()
        choice = Prompt.ask(
            "  Вкладка",
            choices=["0", "1", "2", "3", "4"],
            default="1",
        )

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
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", "-V",
            help="Show version",
            callback=version_callback,
            is_eager=True,
        ),
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
        t0 = time.perf_counter()
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), transient=True
        ) as progress:
            progress.add_task("Hybrid Encrypting (ML-KEM + AES)…", total=None)
            encrypted_data = encrypt_data(raw_data, public_key, filename, extension)
            final_path = save_to_png(encrypted_data, output)
        dt = time.perf_counter() - t0

        console.print(Panel(
            f"[green]Success![/green]\n"
            f"Saved to: {final_path}\n"
            f"Size: {human_size(len(raw_data))} → "
            f"{human_size(final_path.stat().st_size)}\n"
            f"Time: {dt:.2f}s",
            title="Encryption Report",
        ))
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
        t0 = time.perf_counter()
        raw_bytes = load_from_png(image)
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), transient=True
        ) as progress:
            progress.add_task(
                "Decapsulating Kyber and Verifying Integrity…", total=None
            )
            payload = decrypt_data(raw_bytes, private_key)
        dt = time.perf_counter() - t0

        safe_name = sanitize_filename(payload.filename)
        target_path = output_dir / f"{safe_name}{payload.extension}"

        if target_path.exists() and not force:
            if not Confirm.ask(f"File {target_path.name} exists. Overwrite?"):
                raise typer.Exit(0)

        target_path.write_bytes(payload.data)
        console.print(Panel(
            f"[green]Decryption Successful![/green]\n"
            f"File saved: {target_path}\n"
            f"Size: {human_size(len(payload.data))}\n"
            f"Time: {dt:.2f}s",
            title="Success",
        ))
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
