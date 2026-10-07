import frida
from rich.console import Console
import threading
from capstone import *
c = Console()

target = "com.Echo.Back"


def info(msg: str):
    c.print(f"[bold blue]\\[\\*][/] {msg}")


def success(msg: str):
    c.print(f"[bold green]\\[+][/] {msg}")


def error(msg: str):
    c.print(f"[bold red]\\[-][/] {msg}")


def connect_usb_device():
    info("Connecting to USB device...")
    try:
        usb_device = frida.get_usb_device()
        success(f"USB device acquired: [cyan]{usb_device.name}[/] (id=[dim]{usb_device.id}[/])")
        return usb_device
    except:
        error("Unable to connect to the device")
        raise



def spawn_and_attach_to_target(usb_device: frida.Device, bundleID: str) -> frida.Session:
    info(f"Spawning [yellow]{bundleID}[/]...")
    pid = usb_device.spawn([target])
    success(f"Spawned [yellow]{bundleID}[/] (pid=[magenta]{pid}[/])")

    info(f"Attaching to pid [magenta]{pid}[/]...")
    session = frida.get_usb_device().attach(pid)
    success(f"Attached to [yellow]{bundleID}[/]")

    return session


def kill_session(usb_device: frida.Device, session: frida.Session):
    info(f"Killing pid [magenta]{session.pid}[/]...")
    usb_device.kill(session.pid)
    success("Target killed")


def run_script_into_session(session: frida.Session, path_to_script: str, on_message=None) -> frida.Script:
    info(f"Load script {path_to_script}")

    with open(path_to_script, 'r') as script_file:
        script = session.create_script(script_file.read())

    if on_message is not None:
        # IMPORTANT : enregistrer le listener AVANT load(), sinon les messages envoyés
        # dès le top-level du script JS (console.log/send synchrones au chargement) sont perdus
        script.on('message', on_message)

    script.load()
    success(f"Script [yellow]{path_to_script}[/] loaded")

    return script


dump_done = threading.Event()


def reassemble(data, base_address: int = 0x0):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    with open("dump.asm", 'w') as file:

        for i in md.disasm(data, base_address):
            file.write(f'{i.address:#010x}  {i.mnemonic:<7} {i.op_str}\n')




def on_message(message, data):
    try:
        if message['type'] == 'send':
            payload = message['payload']
            event = payload.get('event')

            if event == 'dump':
                size = payload.get('size', len(data) if data else 0)
                base_address = int(payload['address'], 16)
                with open('dump.bin', 'wb') as f:
                    f.write(data)
                reassemble(data, base_address)
                success(f"Dump écrit ({size} octets) @ {payload['address']}")
                dump_done.set()
            else:
                c.print(f"[bold cyan][msg][/] {payload}")

        elif message['type'] == 'log':
            c.print(f"[dim][js][/] {message['payload']}")

        elif message['type'] == 'error':
            error(f"Script error: {message['stack']}")
    except Exception as exc:
        error(f"on_message handler a crashé: {exc}")


try:
    device = connect_usb_device()

    session = spawn_and_attach_to_target(device, target)

    script = run_script_into_session(session, "_agent.js", on_message)

    if not dump_done.wait(timeout=10):
        error("Timeout: aucun dump reçu après 10s")


    kill_session(device, session)
finally:
    print("done.")