"""Reporting Rich pour les étapes de patching.

Affiche un rapport structuré avant/après chaque opération de patch
pour permettre le suivi visuel et la vérification d'intégrité.
"""
from log import console
from shared_types import BinaryInfo


def print_report(
    title: str,
    color: str,
    bi: BinaryInfo,
    mem_cryptoff: int,
    mem_hash: str | None = None,
):
    """Affiche un rapport d'état d'un binaire avec les infos de chiffrement.

    Appelé avant patch, après patch cryptid, et après patch de la zone chiffrée.
    Compare optionnellement le hash du dump mémoire avec celui du fichier patché.

    Args:
        title: titre du rapport (ex: "Before Patch", "After Patch CryptID")
        color: couleur Rich pour le titre
        bi: infos du binaire sur disque (hash, cryptoff, cryptid)
        mem_cryptoff: cryptoff tel que vu en mémoire par l'agent
        mem_hash: hash SHA-256 du dump mémoire (pour vérification post-patch)
    """
    console.rule(f"[bold {color}]{title}")
    lines = (
        f"    [bold]Memory cryptoff:[/]  [cyan]{mem_cryptoff:#010x}[/]\n"
        f"    [bold]File cryptoff:[/]    [cyan]{bi.cryptoff:#010x}[/]\n"
        f"    [bold]Binary hash:[/]      [dim]{bi.file_hash}[/]\n"
        f"    [bold]Crypt hash:[/]       [dim]{bi.crypt_hash}[/]\n"
    )
    if mem_hash is not None:
        match = bi.crypt_hash == mem_hash
        tag = "[bold green]MATCH[/]" if match else "[bold red]MISMATCH[/]"
        lines += f"    [bold]Mem dump hash:[/]    [dim]{mem_hash}[/] {tag}\n"
    lines += f"    [bold]CryptID:[/]          [yellow]{bi.cryptid}[/]"
    console.print(lines)
