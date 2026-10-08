import frida
from pathlib import Path, PurePosixPath
from rich.console import Console
import subprocess
import lief
import hashlib
from dataclasses import dataclass
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


lief.disable_leak_warning()
c = Console()
BUF_SIZE = 65536


def info(msg: str):
    c.print(f"[bold blue]\\[\\*][/] {msg}")


def success(msg: str):
    c.print(f"[bold green]\\[+][/] {msg}")


def error(msg: str):
    c.print(f"[bold red]\\[-][/] {msg}")


# --- Data ---

@dataclass
class BinaryInfo:
    file_hash: str
    crypt_hash: str
    cryptoff: int
    cryptsize: int
    cryptid: int


# --- Mach-O helpers ---

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(BUF_SIZE):
            h.update(chunk)
    return h.hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_macho(path: str):
    fat = lief.MachO.parse(path)
    if fat is None or len(fat) == 0:
        raise ValueError("Impossible de lire le Mach-O")
    return fat, fat.at(0)


def read_crypt_section(path: str, binary) -> bytes:
    enc = binary.encryption_info
    with open(path, "rb") as f:
        f.seek(binary.fat_offset + enc.crypt_offset)
        return f.read(enc.crypt_size)


def get_binary_info(path: str) -> BinaryInfo:
    _, binary = parse_macho(path)
    enc = binary.encryption_info
    crypt_data = read_crypt_section(path, binary)
    return BinaryInfo(
        file_hash=sha256_of_file(path),
        crypt_hash=sha256_hex(crypt_data),
        cryptoff=enc.crypt_offset,
        cryptsize=enc.crypt_size,
        cryptid=enc.crypt_id,
    )


# --- Patch operations ---

def patch_cryptid(path: str) -> BinaryInfo:
    _, binary = parse_macho(path)
    enc = binary.encryption_info
    if enc is None:
        raise ValueError("Pas de LC_ENCRYPTION_INFO[_64]")

    offset = binary.fat_offset + enc.command_offset + 0x10
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write((0).to_bytes(4, "little"))

    after = get_binary_info(path)
    assert after.cryptid == 0, f"cryptid should be 0 after patch, got {after.cryptid}"
    success("cryptid zeroed out")
    return after


def patch_crypt_section(path: str, mem_dump: bytes | list, expected_cryptoff: int) -> tuple[str, BinaryInfo]:
    bi = get_binary_info(path)
    dump_bytes = bytes(mem_dump) if not isinstance(mem_dump, (bytes, bytearray)) else mem_dump
    mem_hash = sha256_hex(dump_bytes)

    if bi.cryptoff != expected_cryptoff:
        raise ValueError(
            f"cryptoff mismatch: memory={expected_cryptoff:#010x} file={bi.cryptoff:#010x}"
        )

    with open(path, "r+b") as f:
        f.seek(bi.cryptoff)
        nbw = f.write(dump_bytes)
        success(f"Patch applied @ [cyan]{bi.cryptoff:#010x}[/] — [yellow]{nbw}[/] bytes written")

    after = get_binary_info(path)
    assert after.crypt_hash == mem_hash, (
        f"Integrity check failed!\n"
        f"  file crypt section: {after.crypt_hash}\n"
        f"  memory dump:        {mem_hash}"
    )
    success("Integrity verified: file crypt section == memory dump")

    return mem_hash, after


# --- Reporting ---

def print_report(title: str, color: str, bi: BinaryInfo, mem_cryptoff: int, mem_hash: str | None = None):
    c.rule(f"[bold {color}]{title}")
    lines = (
        f"  [bold]Memory cryptoff:[/]  [cyan]{mem_cryptoff:#010x}[/]\n"
        f"  [bold]File cryptoff:[/]    [cyan]{bi.cryptoff:#010x}[/]\n"
        f"  [bold]Binary hash:[/]      [dim]{bi.file_hash}[/]\n"
        f"  [bold]Crypt hash:[/]       [dim]{bi.crypt_hash}[/]\n"
    )
    if mem_hash is not None:
        match = bi.crypt_hash == mem_hash
        tag = "[bold green]MATCH[/]" if match else "[bold red]MISMATCH[/]"
        lines += f"  [bold]Mem dump hash:[/]    [dim]{mem_hash}[/] {tag}\n"
    lines += f"  [bold]CryptID:[/]          [yellow]{bi.cryptid}[/]"
    c.print(lines)


# --- Disassembly ---

def reassemble(data: bytes, base_address: int = 0x0):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    with open("dump.asm", "w") as f:
        for i in md.disasm(data, base_address):
            f.write(f"{i.address:#010x}  {i.mnemonic:<7} {i.op_str}\n")


def write_dump(address: str, cryptsize: int, data: bytes):
    with open("dump.bin", "wb") as f:
        f.write(data)
    reassemble(data, int(address, 16))
    success(f"Dump écrit ({cryptsize} octets)")


# --- Yafi ---

class Yafi:

    def __init__(self, bundle_id: str, agent_path: str):
        self.bundle_id = bundle_id
        self.agent_path = agent_path
        self.device: frida.Device | None = None
        self.session: frida.Session | None = None
        self.module_path: PurePosixPath | None = None
        self.module_name: str | None = None
        self.cryptoff: int | None = None
        self.binaryDump: bytes | None = None

    def connect(self):
        info("Connecting to USB device...")
        self.device = frida.get_usb_device()
        success(f"USB device acquired: [cyan]{self.device.name}[/] (id=[dim]{self.device.id}[/])")

    def spawn_and_attach(self):
        info(f"Spawning [yellow]{self.bundle_id}[/]...")
        pid = self.device.spawn([self.bundle_id])
        success(f"Spawned [yellow]{self.bundle_id}[/] (pid=[magenta]{pid}[/])")
        
        info(f"Attaching to pid [magenta]{pid}[/]...")
        self.session = self.device.attach(pid)
        success(f"Attached to [yellow]{self.bundle_id}[/]")

    def resume(self):
        self.session.resume()

        self.device.kill()


    def kill(self):
        if self.session and self.device:
            info(f"Killing pid [magenta]{self.session.pid}[/]...")
            self.device.kill(self.session.pid)
            success("Target killed")

    def run_agent(self):
        info(f"Loading agent [yellow]{self.agent_path}[/]...")
        with open(self.agent_path, "r") as f:
            script = self.session.create_script(f.read())
        script.on("message", self._on_message)
        script.load()
        self.api = script.exports
        success("Agent loaded")
        return script

    def dump(self):
        meta, data = self.api.dumpModule(self.bundle_id)
        self.cryptoff = meta["cryptoff"]
        self.binaryDump = data
        write_dump(meta["address"], meta["cryptsize"], data)

    def get_module_path(self) -> PurePosixPath:
        self.module_path = PurePosixPath(self.api.getModulePath())
        self.module_name = self.module_path.name
        success(f"Module path: [cyan]{self.module_path}[/]")
        return self.module_path

    def prepareTheExtraction(self):

        self.api.prepareTheExtraction()

    def _on_message(self, message: dict, data: bytes | None):
        if message["type"] == "log":
            c.print(f"[dim]\\[js][/] {message['payload']}")
        elif message["type"] == "error":
            error(f"Script error: {message.get('stack', message.get('description', ''))}")


# --- Main ---

if __name__ == "__main__":
    yafi = Yafi("com.Echo.Back", "_agent.js")

    try:
        yafi.connect()
        yafi.spawn_and_attach()
        yafi.run_agent()
        yafi.dump()

        yafi.prepareTheExtraction()
        path = yafi.get_module_path()

        dump_dir = Path(f"./dump/{path.parent.name}")
        dump_dir.mkdir(parents=True, exist_ok=True)

        subprocess.run(
            ["scp", "-q", "-r", f"6s:{path.parent}/.", str(dump_dir)],
            check=True,
        )

        binary_path = str(dump_dir / yafi.module_name)

        bi = get_binary_info(binary_path)
        print_report("Before Patch", "blue", bi, yafi.cryptoff)

        bi = patch_cryptid(binary_path)
        print_report("After Patch CryptID", "green", bi, yafi.cryptoff)

        mem_hash, bi = patch_crypt_section(binary_path, yafi.binaryDump, yafi.cryptoff)
        print_report("After Patch Crypt Section", "orange1", bi, yafi.cryptoff, mem_hash)

        result = subprocess.run(["file", binary_path], capture_output=True, text=True)
        c.rule("[bold cyan]Validation")
        c.print(f"  {result.stdout.strip()}")

    finally:
        yafi.kill()

