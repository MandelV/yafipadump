"""Classe Yafi — orchestrateur du dump FairPlay iOS.

Yafi gère le cycle de vie complet d'une extraction :
  1. Connexion USB au device jailbreaké
  2. Spawn + attach au process cible via Frida
  3. Injection de l'agent JS qui parse les headers Mach-O en mémoire
  4. Discovery des modules du .app bundle (mainModule + frameworks)
  5. Copie du .app bundle depuis le device (scp)
  6. Pour chaque module : dump des octets déchiffrés + patch du binaire sur disque

Le résultat est un .app bundle avec tous les binaires décryptés,
prêt pour l'analyse statique (class-dump, Hopper, Ghidra, etc.)
"""
import subprocess
from pathlib import Path, PurePosixPath

import frida

from log import (
    console, info, success, error,
    phase, module_banner, module_info, summary_panel,
)
from shared_types import ModuleMetaDataDict
from frida_api import FridaAgentAPI
from macho import get_binary_info, patch_cryptid, patch_crypt_section
from disasm import write_dump
from report import print_report


class Yafi:
    """Orchestrateur de dump FairPlay pour un bundle iOS.

    Args:
        bundle_id: identifiant du bundle iOS (ex: "com.example.MyApp")
        agent_path: chemin vers le script JS compilé de l'agent Frida
    """

    def __init__(self, bundle_id: str, agent_path: str):
        self.bundle_id = bundle_id
        self.agent_path = agent_path

        # État Frida — initialisé par connect() et spawn_and_attach()
        self.device: frida.Device = None
        self.session: frida.Session = None
        self.api: FridaAgentAPI | None = None

        # Infos du module principal — initialisées par get_module_path()
        self.module_path: PurePosixPath | None = None
        self.module_name: str | None = None

        # Compteur de modules trouvés par prepare_extraction()
        self.module_count: int = 0

        # Répertoire de dump local — initialisé par dump_all_modules()
        self.dump_dir: Path | None = None

    # --- Connexion et lifecycle Frida ---

    def connect(self):
        """Se connecte au premier device USB Frida disponible."""
        info("Connecting to USB device...")
        self.device = frida.get_usb_device()
        success(f"Connected to [cyan]{self.device.name}[/] [dim](id={self.device.id})[/]")

    def spawn_and_attach(self):
        """Spawn le process cible et s'y attache via Frida.

        Le process est créé en mode suspendu (Frida le retient avant main()),
        ce qui laisse le temps d'injecter l'agent avant que le code ne s'exécute.
        """
        info(f"Spawning [yellow]{self.bundle_id}[/]...")
        pid = self.device.spawn([self.bundle_id])
        success(f"Process spawned [dim](pid={pid})[/]")

        info(f"Attaching to process...")
        self.session = self.device.attach(pid)
        success(f"Attached to [yellow]{self.bundle_id}[/] [dim](pid={pid})[/]")

    def kill(self):
        """Tue le process cible sur le device."""
        if self.session and self.device:
            console.print()
            info(f"Killing target [dim](pid={self.session.pid})[/]...")
            self.device.kill(self.session.pid)
            success("Target killed")

    # --- Agent JS ---

    def run_agent(self) -> frida.Script:
        """Charge et injecte le script agent JS dans le process cible.

        Le script est lu depuis agent_path (fichier JS compilé par le build TS),
        injecté via create_script(), puis ses exports RPC deviennent accessibles
        via self.api (FridaAgentAPI).
        """
        info(f"Loading agent [dim]{self.agent_path}[/]...")
        with open(self.agent_path, "r") as f:
            script = self.session.create_script(f.read())
        script.on("message", self._on_message)
        script.load()
        self.api = FridaAgentAPI(script)
        success("Agent loaded and ready")
        return script

    # --- Discovery ---

    def get_module_path(self) -> PurePosixPath:
        """Récupère le chemin du binaire principal sur le device via RPC.

        Stocke aussi le nom du module (ex: "MyApp") pour construire
        les chemins de dump locaux.
        """
        self.module_path = PurePosixPath(self.api.get_module_path())
        self.module_name = self.module_path.name
        success(f"Main binary: [cyan]{self.module_path}[/]")
        return self.module_path

    def prepare_extraction(self) -> int:
        """Phase 1 : fait lister les modules du .app bundle par l'agent.

        L'agent énumère les modules chargés par dyld, filtre ceux du bundle,
        et les stocke en mémoire (sans copier de données binaires).
        """
        self.module_count = self.api.prepare_the_extraction()
        success(f"Discovered [yellow]{self.module_count}[/] module(s) in bundle")
        return self.module_count

    # --- Dump & Patch ---

    def _dump_module(self, index: int) -> tuple[ModuleMetaDataDict, bytes] | None:
        """Dump un seul module par son index via RPC.

        L'agent parse le header Mach-O et, si le module est chiffré FairPlay,
        lit les octets déchiffrés depuis la mémoire (readByteArray).
        C'est l'étape coûteuse en mémoire — un seul module à la fois.
        """
        result = self.api.dump_module(index)
        if result is None:
            error(f"Module at index {index} could not be parsed")
            return None

        meta, data = result
        module_info(meta)

        enc_info = meta.get("LcEncryptionInfo")
        decrypted_meta = meta.get("DecryptedSectionMeta")
        if enc_info and decrypted_meta:
            write_dump(
                f"{self.bundle_id}/{meta['moduleName']}",
                meta["moduleName"],
                decrypted_meta["address"],
                decrypted_meta["size"],
                data,
            )

        return meta, data

    def _patch_fs_module(self, meta: ModuleMetaDataDict, data: bytes):
        """Patche un binaire sur disque : écrase la zone chiffrée + met cryptid à 0.

        Opère sur le fichier copié localement (dans self.dump_dir), pas sur le device.
        Skip les modules non chiffrés (dev builds, modules système, etc.).
        """
        enc_info = meta.get("LcEncryptionInfo")
        if not meta.get("isEncrypted") or enc_info is None:
            info(f"Not encrypted — skipping patch")
            return

        binary_path = str(self.dump_dir / meta["moduleName"])
        mem_cryptoff = enc_info["cryptoff"]

        bi = get_binary_info(binary_path)
        print_report("Before Patch", "blue", bi, mem_cryptoff)

        # Étape 1 : met cryptid à 0 pour que le kernel ne tente pas de déchiffrer
        bi = patch_cryptid(binary_path)
        print_report("After Patch CryptID", "green", bi, mem_cryptoff)

        # Étape 2 : écrase la zone chiffrée par les octets en clair du dump mémoire
        mem_hash, bi = patch_crypt_section(binary_path, data, mem_cryptoff)
        print_report("After Patch Crypt Section", "orange1", bi, mem_cryptoff, mem_hash)

        # Validation rapide via `file` — doit afficher "Mach-O 64-bit executable arm64"
        result = subprocess.run(["file", binary_path], capture_output=True, text=True)
        console.rule("[bold cyan]Validation")
        console.print(f"  {result.stdout.strip()}")

    def dump_all_modules(self):
        """Orchestre le dump complet de tous les modules du .app bundle.

        Pipeline :
          1. Setup — connexion, injection agent, discovery
          2. Transfer — copie du .app bundle depuis le device
          3. Dump — pour chaque module : extraction mémoire + patch fichier
        """
        # --- Phase 1 : Setup ---
        phase("Setup", "bold cyan")
        self.run_agent()
        path = self.get_module_path()
        n_modules = self.prepare_extraction()

        # Prépare le répertoire de dump local (./dump/NomDeLApp.app/)
        self.dump_dir = Path(f"./dump/{path.parent.name}")
        self.dump_dir.mkdir(parents=True, exist_ok=True)

        summary_panel(self.bundle_id, n_modules, str(path), str(self.dump_dir))

        # --- Phase 2 : Transfer du bundle ---
        phase("Transfer", "bold magenta")
        info(f"Copying .app bundle from device...")
        info(f"[dim]scp -r 6s:{path.parent}/. → {self.dump_dir}[/]")
        subprocess.run(
            ["scp", "-q", "-r", f"6s:{path.parent}/.", str(self.dump_dir)],
            check=True,
        )
        success(f"Bundle copied to [cyan]{self.dump_dir}[/]")

        # --- Phase 3 : Dump & Patch par module ---
        phase(f"Dump & Patch ({n_modules} module{'s' if n_modules > 1 else ''})", "bold yellow")

        for i in range(n_modules):
            result = self._dump_module(i)
            if result is not None:
                meta, data = result
                module_banner(i, n_modules, meta["moduleName"], meta["isMainModule"])
                self._patch_fs_module(meta, data)

        # --- Résumé final ---
        phase("Done", "bold green")
        success(f"All {n_modules} module(s) processed → [cyan]{self.dump_dir}[/]")

    # --- Callbacks Frida ---

    def _on_message(self, message: dict, _data: bytes | None):
        """Callback pour les messages envoyés par l'agent JS via console.log() ou send().

        Les messages de type "log" sont les console.log() de l'agent.
        Les messages de type "error" sont des exceptions non catchées côté JS.
        """
        if message["type"] == "log":
            console.print(f"  [dim]\\[js][/] {message['payload']}")
        elif message["type"] == "error":
            error(f"Script error: {message.get('stack', message.get('description', ''))}")
