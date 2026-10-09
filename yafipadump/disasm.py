"""Désassemblage ARM64 et écriture des dumps sur disque.

Utilise Capstone pour désassembler les octets déchiffrés en instructions
ARM64 lisibles. Produit deux fichiers par module dumpé :
  - dump.bin  — octets bruts déchiffrés
  - dump.asm  — désassemblage texte (adresse + mnémonique + opérandes)
"""
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from .log import success


def reassemble(output_dir: Path, data: bytes, base_address: int = 0x0):
    """Désassemble un buffer ARM64 et écrit le résultat en fichier texte.

    Le base_address correspond à l'adresse mémoire d'origine du code sur le device
    (decrypted_meta.address) — les adresses dans le .asm seront donc celles
    du binaire en mémoire, pas des offsets relatifs.

    Args:
        output_dir: répertoire où écrire dump.asm
        data: octets ARM64 à désassembler
        base_address: adresse de base pour le listing (typiquement base + cryptoff)
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    with open(output_dir / "dump.asm", "w") as f:
        for insn in md.disasm(data, base_address):
            f.write(f"{insn.address:#010x}  {insn.mnemonic:<7} {insn.op_str}\n")


def write_dump(
    namespace: str,
    module_name: str,
    address: str,
    cryptsize: int,
    data: bytes,
):
    """Écrit le dump mémoire (binaire + désassemblage) sur disque.

    Args:
        namespace: sous-répertoire dans ./dump/ (typiquement bundle_id/module_name)
        module_name: nom du module pour le message de log
        address: adresse mémoire hex string du début de la zone déchiffrée
        cryptsize: taille de la zone (pour le log)
        data: octets déchiffrés à écrire
    """
    dump_dir = Path(f"./dump/{namespace}")
    dump_dir.mkdir(parents=True, exist_ok=True)

    bin_path = dump_dir / "dump.bin"
    with open(bin_path, "wb") as f:
        f.write(data)

    reassemble(dump_dir, data, int(address, 16))
    success(
        f"Decrypted dump written for [yellow]{module_name}[/] "
        f"— [cyan]{cryptsize:,}[/] bytes → [dim]{dump_dir}[/]"
    )
