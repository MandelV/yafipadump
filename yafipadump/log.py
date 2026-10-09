"""Fonctions de logging coloré via Rich.

Fournit des niveaux de log avec des marqueurs visuels distinctifs
et des helpers de mise en page pour structurer la sortie en phases
(setup, puis dump par module).
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def info(msg: str):
    """Message informatif (bleu) -- étape en cours."""
    console.print(f"  [bold blue]\\[\\*][/] {msg}")


def success(msg: str):
    """Message de succès (vert) -- étape terminée."""
    console.print(f"  [bold green]\\[+][/] {msg}")


def error(msg: str):
    """Message d'erreur (rouge) -- quelque chose a échoué."""
    console.print(f"  [bold red]\\[-][/] {msg}")


def phase(title: str, style: str = "bold cyan"):
    """Affiche un header de phase majeure (Setup, Dump, etc.)."""
    console.print()
    console.rule(f"[{style}]{title}", style=style)
    console.print()


def module_banner(index: int, total: int, name: str, is_main: bool):
    """Affiche un header de module avec son index et son rôle."""
    kind = "main binary" if is_main else "framework"
    console.print()
    console.rule(
        f"[bold yellow]Module {index + 1}/{total}[/] -- [bold white]{name}[/] [dim]({kind})[/]",
        style="yellow",
    )
    console.print()


def module_info(meta: dict):
    """Affiche un résumé structuré des métadonnées d'un module."""
    table = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    table.add_column("key", style="bold", min_width=14)
    table.add_column("value")

    table.add_row("Path", f"[cyan]{meta['modulePath']}[/]")
    table.add_row("Arch", f"[magenta]{meta['moduleArch']}[/]")
    table.add_row("Platform", meta["modulePlatform"])
    table.add_row("Size", f"{meta['moduleSize']:,} bytes")
    table.add_row("Load commands", str(meta["nlcmds"]))

    enc_info = meta.get("LcEncryptionInfo")
    if meta.get("isEncrypted") and enc_info:
        table.add_row(
            "Encrypted",
            f"[bold red]Yes[/] (cryptid={enc_info['cryptid']})",
        )
        table.add_row(
            "Crypt zone",
            f"[cyan]{enc_info['cryptoff']:#010x}[/] -- "
            f"[yellow]{enc_info['cryptsize']:,}[/] bytes",
        )
    else:
        table.add_row("Encrypted", "[bold green]No[/]")

    console.print(table)
    console.print()


def summary_panel(bundle_id: str, module_count: int, module_path: str, dump_dir: str):
    """Affiche un panneau récapitulatif avant de lancer le dump."""
    table = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    table.add_column("key", style="bold", min_width=14)
    table.add_column("value")
    table.add_row("Bundle ID", f"[yellow]{bundle_id}[/]")
    table.add_row("Main binary", f"[cyan]{module_path}[/]")
    table.add_row("Modules found", f"[bold yellow]{module_count}[/]")
    table.add_row("Output dir", f"[dim]{dump_dir}[/]")

    console.print(Panel(table, title="[bold]Extraction Summary", border_style="green"))
    console.print()
