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


def patch_cryptid(path: str, arch: str) -> BinaryInfo:
    """Met à zéro le champ cryptid dans le fichier Mach-O.

    Après le dump, le binaire contient du code en clair mais cryptid indique
    encore qu'il est chiffré. Si on ne le met pas à 0, le kernel essaiera
    de déchiffrer un binaire déjà en clair → crash au lancement.

    Le champ cryptid est à l'offset +0x10 dans la struct encryption_info_command_64
    (après cmd, cmdsize, cryptoff, cryptsize — chacun 4 octets).
    """
    _, binary = parse_macho(path, arch)
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

    after = get_binary_info(path, arch)
    if after.cryptid != 0:
        raise RuntimeError(f"cryptid should be 0 after patch, got {after.cryptid}")
    success("cryptid zeroed out")
    return after


def patch_crypt_section(path: str, mem_dump: bytes | list, arch: str) -> tuple[str, BinaryInfo]:
    """Écrase la zone chiffrée du fichier par les octets déchiffrés du dump mémoire.

    Les checks de cohérence (cryptoff, taille) doivent être faits par l'appelant
    avant d'arriver ici. Cette fonction écrit puis vérifie l'intégrité post-écriture
    via SHA-256.

    Args:
        path: chemin du binaire sur disque
        mem_dump: octets déchiffrés lus depuis la mémoire du process (via Frida)
        arch: architecture Frida du process (ex: "arm64")

    Returns:
        (hash_du_dump, infos_après_patch)
    """
    bi = get_binary_info(path, arch)
    dump_bytes = bytes(mem_dump) if not isinstance(mem_dump, (bytes, bytearray)) else mem_dump
    mem_hash = sha256_hex(dump_bytes)

    with open(path, "r+b") as f:
        f.seek(bi.fat_offset + bi.cryptoff)
        nbw = f.write(dump_bytes)
        success(f"Patch applied @ [cyan]{bi.cryptoff:#010x}[/] — [yellow]{nbw}[/] bytes written")

    after = get_binary_info(path, arch)
    if after.crypt_hash != mem_hash:
        raise RuntimeError(
            f"Integrity check failed!\n"
            f"  file crypt section: {after.crypt_hash}\n"
            f"  memory dump:        {mem_hash}"
        )
    success("Integrity verified: file crypt section == memory dump")

    return mem_hash, after
