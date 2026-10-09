"""Helpers pour la manipulation de binaires Mach-O sur disque.

Utilise lief pour parser les headers Mach-O et accéder aux métadonnées
de chiffrement FairPlay (LC_ENCRYPTION_INFO[_64]).

Ce module opère sur les fichiers copiés du device (post-scp), pas
sur la mémoire du process — le dump mémoire est géré côté agent Frida.
"""
import hashlib

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


# --- Parse ---


def parse_macho(path: str):
    """Parse un binaire Mach-O (potentiellement FAT/Universal) et retourne la première slice.

    Un FAT binary contient plusieurs slices (une par architecture).
    On prend la première (index 0), qui est généralement arm64 sur iOS.

    Returns:
        (fat_binary, first_slice) — le FatBinary et le Binary lief de la slice 0
    """
    fat = lief.MachO.parse(path)
    if fat is None or len(fat) == 0:
        raise ValueError("Impossible de lire le Mach-O")
    return fat, fat.at(0)


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


def get_binary_info(path: str) -> BinaryInfo:
    """Extrait les métadonnées de chiffrement d'un binaire Mach-O sur disque.

    Calcule les hash du fichier complet et de la zone chiffrée
    pour permettre la vérification d'intégrité post-patch.
    """
    _, binary = parse_macho(path)
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


def patch_cryptid(path: str) -> BinaryInfo:
    """Met à zéro le champ cryptid dans le fichier Mach-O.

    Après le dump, le binaire contient du code en clair mais cryptid indique
    encore qu'il est chiffré. Si on ne le met pas à 0, le kernel essaiera
    de déchiffrer un binaire déjà en clair → crash au lancement.

    Le champ cryptid est à l'offset +0x10 dans la struct encryption_info_command_64
    (après cmd, cmdsize, cryptoff, cryptsize — chacun 4 octets).
    """
    _, binary = parse_macho(path)
    enc = binary.encryption_info
    if enc is None:
        raise ValueError("Pas de LC_ENCRYPTION_INFO[_64]")

    # command_offset = position de la LC dans le fichier (relatif à la slice)
    # +0x10 = offset du champ cryptid dans la struct
    offset = binary.fat_offset + enc.command_offset + 0x10
    with open(path, "r+b") as f:
        f.seek(offset)
        # Écrit 0 en little-endian sur 4 octets (uint32_t cryptid = 0)
        f.write((0).to_bytes(4, "little"))

    after = get_binary_info(path)
    assert after.cryptid == 0, f"cryptid should be 0 after patch, got {after.cryptid}"
    success("cryptid zeroed out")
    return after


def patch_crypt_section(path: str, mem_dump: bytes | list) -> tuple[str, BinaryInfo]:
    """Écrase la zone chiffrée du fichier par les octets déchiffrés du dump mémoire.

    L'offset d'écriture est calculé depuis les headers Mach-O du fichier lui-même
    (fat_offset + cryptoff), sans dépendre d'une valeur externe.
    L'intégrité est vérifiée post-écriture en comparant les hash SHA-256.

    Args:
        path: chemin du binaire sur disque
        mem_dump: octets déchiffrés lus depuis la mémoire du process (via Frida)

    Returns:
        (hash_du_dump, infos_après_patch)
    """
    bi = get_binary_info(path)
    dump_bytes = bytes(mem_dump) if not isinstance(mem_dump, (bytes, bytearray)) else mem_dump
    mem_hash = sha256_hex(dump_bytes)

    with open(path, "r+b") as f:
        f.seek(bi.fat_offset + bi.cryptoff)
        nbw = f.write(dump_bytes)
        success(f"Patch applied @ [cyan]{bi.cryptoff:#010x}[/] — [yellow]{nbw}[/] bytes written")

    # Vérification d'intégrité : relit la zone patchée et compare avec le dump
    after = get_binary_info(path)
    assert after.crypt_hash == mem_hash, (
        f"Integrity check failed!\n"
        f"  file crypt section: {after.crypt_hash}\n"
        f"  memory dump:        {mem_hash}"
    )
    success("Integrity verified: file crypt section == memory dump")

    return mem_hash, after
