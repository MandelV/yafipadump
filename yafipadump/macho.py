"""Helpers pour la manipulation de binaires Mach-O sur disque.

Utilise lief pour parser les headers Mach-O et accéder aux métadonnées
de chiffrement FairPlay (LC_ENCRYPTION_INFO[_64]).

Ce module opère sur les fichiers copiés du device (post-scp), pas
sur la mémoire du process — le dump mémoire est géré côté agent Frida.
"""
import hashlib
import os
import shutil
import tempfile

import lief

from .log import info, success
from .shared_types import BinaryInfo

lief.disable_leak_warning()

BUF_SIZE = 65536


# --- Hash ---


def sha256_of_file(path: str) -> str:
    """Calcule le SHA-256 d'un fichier en le lisant par blocs (mémoire constante)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(BUF_SIZE):
            h.update(chunk)
    return h.hexdigest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 d'un buffer en mémoire, retourné en hex."""
    return hashlib.sha256(data).hexdigest()


# --- Offsets encryption_info_command_64 (loader.h:1230) ---
# Miroir de EncryptionInfoCommandOffset dans agent/macho.ts

ENCRYPTION_INFO_CMD = 0x00
ENCRYPTION_INFO_CMDSIZE = 0x04
ENCRYPTION_INFO_CRYPTOFF = 0x08
ENCRYPTION_INFO_CRYPTSIZE = 0x0C
ENCRYPTION_INFO_CRYPTID = 0x10
ENCRYPTION_INFO_PAD = 0x14


# --- Parse ---


FRIDA_ARCH_TO_CPU_TYPE = {
    "arm64": lief.MachO.Header.CPU_TYPE.ARM64,
    "arm": lief.MachO.Header.CPU_TYPE.ARM,
    "x64": lief.MachO.Header.CPU_TYPE.X86_64,
    "ia32": lief.MachO.Header.CPU_TYPE.X86,
}


def parse_macho(path: str, arch: str):
    """Parse un binaire Mach-O et retourne la slice correspondant à l'architecture.

    Pour un FAT/Universal binary, sélectionne la slice via fat.get(CPU_TYPE)
    plutôt que de prendre aveuglément l'index 0.
    Pour un thin binary, fat.get() retourne l'unique slice.

    Args:
        path: chemin du fichier Mach-O
        arch: architecture Frida du process (ex: "arm64", "x64")

    Returns:
        (fat_binary, matching_slice)
    """
    cpu_type = FRIDA_ARCH_TO_CPU_TYPE.get(arch)
    if cpu_type is None:
        raise ValueError(f"Architecture inconnue : {arch!r}")

    fat = lief.MachO.parse(path)
    if fat is None or len(fat) == 0:
        raise ValueError("Impossible de lire le Mach-O")

    binary = fat.get(cpu_type)
    if binary is None:
        raise ValueError(f"Pas de slice {arch} ({cpu_type.name}) dans {path}")

    return fat, binary


def read_crypt_section(path: str, binary) -> bytes:
    """Lit les octets de la zone chiffrée directement depuis le fichier sur disque.

    Le seek additionne fat_offset (offset de la slice dans un FAT/Universal binary,
    0 pour un thin binary) et crypt_offset pour atteindre la zone chiffrée quelle
    que soit la structure du conteneur.
    """
    enc = binary.encryption_info
    with open(path, "rb") as f:
        f.seek(binary.fat_offset + enc.crypt_offset)
        return f.read(enc.crypt_size)


def get_binary_info(path: str, arch: str) -> BinaryInfo:
    """Extrait les métadonnées de chiffrement d'un binaire Mach-O sur disque.

    Calcule les hash du fichier complet et de la zone chiffrée
    pour permettre la vérification d'intégrité post-patch.
    """
    _, binary = parse_macho(path, arch)
    enc = binary.encryption_info
    crypt_data = read_crypt_section(path, binary)
    return BinaryInfo(
        file_hash=sha256_of_file(path),
        fat_offset= binary.fat_offset,
        crypt_hash=sha256_hex(crypt_data),
        cryptoff=enc.crypt_offset,
        cryptsize=enc.crypt_size,
        cryptid=enc.crypt_id,
    )


# --- Patch ---


def _patch_crypt_section(f, fat_offset: int, cryptoff: int, dump_bytes: bytes) -> int:
    """Écrase la zone chiffrée par les octets déchiffrés dans un file handle ouvert."""
    f.seek(fat_offset + cryptoff)
    nbw = f.write(dump_bytes)
    if nbw != len(dump_bytes):
        raise RuntimeError(f"Partial write: {nbw}/{len(dump_bytes)} bytes")
    return nbw


def _patch_cryptid(f, cryptid_offset: int):
    """Met cryptid à 0 dans un file handle ouvert."""
    f.seek(cryptid_offset)
    nbw = f.write((0).to_bytes(4, "little"))
    if nbw != 4:
        raise RuntimeError( f"Partial cryptid write: {nbw}/4 bytes")
    return True


def patch_binary(path: str, mem_dump: bytes | list, arch: str) -> tuple[str, BinaryInfo]:
    """Applique les deux patchs (crypt section + cryptid) en une seule transaction atomique.

    Les écritures sont faites sur une copie temporaire (mkstemp, même filesystem
    que l'original). L'original n'est remplacé (os.replace) que si les deux patchs
    et toutes les vérifications passent. En cas d'erreur, la copie est supprimée
    et l'original reste intact.

    Args:
        path: chemin du binaire sur disque
        mem_dump: octets déchiffrés lus depuis la mémoire du process (via Frida)
        arch: architecture Frida du process (ex: "arm64")

    Returns:
        (hash_du_dump, infos_après_patch)
    """
    bi = get_binary_info(path, arch)
    
    if len(mem_dump) != bi.cryptsize:
        raise ValueError(
            f"Invalid dump size: {len(mem_dump)} != {bi.cryptsize}"
        )
    dump_bytes = bytes(mem_dump) if not isinstance(mem_dump, (bytes, bytearray)) else mem_dump
    mem_hash = sha256_hex(dump_bytes)

    _, binary = parse_macho(path, arch)
    enc = binary.encryption_info
    if enc is None:
        raise ValueError("Pas de LC_ENCRYPTION_INFO[_64]")

    

    cryptid_offset = binary.fat_offset + enc.command_offset + ENCRYPTION_INFO_CRYPTID

    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        os.close(fd)
        shutil.copy2(path, tmp_path)

        with open(tmp_path, "r+b") as f:
            nbw = _patch_crypt_section(f, bi.fat_offset, bi.cryptoff, dump_bytes)
            _patch_cryptid(f, cryptid_offset)
            f.flush()
            os.fsync(f.fileno())

        after = get_binary_info(tmp_path, arch)

        if after.crypt_hash != mem_hash:
            raise RuntimeError(
                f"Integrity check failed!\n"
                f"  file crypt section: {after.crypt_hash}\n"
                f"  memory dump:        {mem_hash}"
            )
        if after.cryptid != 0:
            raise RuntimeError(f"cryptid should be 0 after patch, got {after.cryptid}")

        os.replace(tmp_path, path)
    except:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    success(f"Patch applied @ [cyan]{bi.cryptoff:#010x}[/] — [yellow]{nbw}[/] bytes written")
    success("cryptid zeroed out")
    success("Integrity verified: file crypt section == memory dump")

    return mem_hash, after
