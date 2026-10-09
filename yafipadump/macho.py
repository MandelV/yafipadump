"""Helpers pour la manipulation de binaires Mach-O sur disque.

Utilise lief pour parser les headers Mach-O et accéder aux métadonnées
de chiffrement FairPlay (LC_ENCRYPTION_INFO[_64]).

Ce module opère sur les fichiers copiés du device (post-scp), pas
sur la mémoire du process -- le dump mémoire est géré côté agent Frida.

Architecture du patching :
    1. L'appelant (yafi.py) fait les pré-validations (cryptoff match, taille match)
    2. patch_binary() orchestre la transaction atomique :
       - mkstemp crée un fichier temp sur le même filesystem (requis pour os.replace atomique)
       - shutil.copy2 copie l'original (contenu + métadonnées)
       - _patch_crypt_section() écrit les octets déchiffrés dans le temp
       - _patch_cryptid() met cryptid à 0 dans le temp
       - fsync force l'écriture sur disque avant vérification
       - get_binary_info() relit le temp pour vérifier SHA-256 + cryptid
       - os.replace() remplace l'original atomiquement (rename POSIX)
       - finally: supprime le temp dans tous les cas
    3. Si quoi que ce soit échoue, l'original reste intact
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


# Mapping des noms d'architecture Frida (Process.arch) vers les CPU_TYPE lief.
# Frida utilise ses propres noms ("arm64", "x64", "ia32", "arm"),
# tandis que lief utilise les constantes Mach-O du kernel (CPU_TYPE_ARM64, etc.).
FRIDA_ARCH_TO_CPU_TYPE: dict[str, lief.MachO.Header.CPU_TYPE] = {
    "arm64": lief.MachO.Header.CPU_TYPE.ARM64,
    "arm": lief.MachO.Header.CPU_TYPE.ARM,
    "x64": lief.MachO.Header.CPU_TYPE.X86_64,
    "ia32": lief.MachO.Header.CPU_TYPE.X86,
}


def parse_macho(path: str, arch: str) -> tuple[lief.MachO.FatBinary, lief.MachO.Binary]:
    """Parse un binaire Mach-O et retourne la slice correspondant à l'architecture.

    lief.MachO.parse() retourne toujours un FatBinary, même pour un thin binary
    (dans ce cas il contient une seule slice). fat.get(CPU_TYPE) sélectionne
    la bonne slice par architecture au lieu de fat.at(0) qui prendrait
    aveuglément la première -- important pour les Universal binaries
    (ex: arm64 + arm64e, ou arm64 + x86_64 dans les simulateurs).

    Args:
        path: chemin du fichier Mach-O sur disque
        arch: architecture Frida du process (Process.arch côté JS,
              ex: "arm64", "arm", "x64", "ia32")

    Returns:
        (fat_binary, matching_slice) -- le FatBinary complet et le Binary
        de la slice correspondant à l'architecture demandée
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


def read_crypt_section(path: str, binary: lief.MachO.Binary) -> bytes:
    """Lit les octets de la zone chiffrée directement depuis le fichier sur disque.

    Position dans le fichier = fat_offset + crypt_offset :
      - fat_offset : offset de la slice dans le conteneur FAT (0 pour un thin binary)
      - crypt_offset : offset de la zone chiffrée dans la slice (champ de LC_ENCRYPTION_INFO)

    On lit depuis le fichier sur disque (pas la mémoire du process) -- ces octets
    sont encore chiffrés à ce stade. Sert à calculer le hash pré-patch et
    vérifier l'intégrité post-patch.
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
    """Écrase la zone chiffrée par les octets déchiffrés dans un file handle ouvert.

    Écrit à la position fat_offset + cryptoff -- c'est l'adresse absolue dans
    le fichier, que ce soit un thin ou un FAT binary.
    Vérifie que tous les octets ont été écrits (protection contre écriture partielle).

    Args:
        f: file handle ouvert en mode "r+b"
        fat_offset: offset de la slice dans le FAT (0 pour thin binary)
        cryptoff: offset de la zone chiffrée dans la slice
        dump_bytes: octets déchiffrés à écrire (lus depuis la mémoire du process via Frida)

    Returns:
        Nombre d'octets écrits
    """
    f.seek(fat_offset + cryptoff)
    nbw = f.write(dump_bytes)
    if nbw != len(dump_bytes):
        raise RuntimeError(f"Partial write: {nbw}/{len(dump_bytes)} bytes")
    return nbw


def _patch_cryptid(f, cryptid_offset: int):
    """Met le champ cryptid à 0 dans un file handle ouvert.

    cryptid indique au kernel si le binaire est chiffré :
      - cryptid > 0 → le kernel appelle FairPlay pour déchiffrer au chargement
      - cryptid == 0 → le kernel charge le code tel quel

    Après avoir écrit les octets en clair dans la zone chiffrée, il FAUT
    mettre cryptid à 0, sinon le kernel tenterait de "déchiffrer" du code
    déjà en clair → corruption + crash au lancement.

    Args:
        f: file handle ouvert en mode "r+b"
        cryptid_offset: position absolue du champ cryptid dans le fichier
                        (fat_offset + command_offset + ENCRYPTION_INFO_CRYPTID)
    """
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
        raise
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    success(f"Patch applied @ [cyan]{bi.cryptoff:#010x}[/] -- [yellow]{nbw}[/] bytes written")
    success("cryptid zeroed out")
    success("Integrity verified: file crypt section == memory dump")

    return mem_hash, after
