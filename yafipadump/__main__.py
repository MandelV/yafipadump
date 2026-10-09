"""yafipadump -- Yet Another Frida IPA Dump tool.

Point d'entrée principal. Connecte un device iOS jailbreaké via USB,
injecte l'agent Frida, et dump les binaires chiffrés FairPlay
en les remplaçant par leur version déchiffrée depuis la mémoire.

Le process cible est toujours tué en finally (même si le dump crashe)
pour ne pas laisser un process zombie sur le device.

Utilisation :
    python -m yafipadump --host iphone com.example.MyApp
"""
import argparse

from .yafi import Yafi


def main():
    parser = argparse.ArgumentParser(
        prog="yafipadump",
        description="Dump FairPlay-encrypted iOS binaries from memory via Frida",
    )
    parser.add_argument(
        "bundle_id",
        help="iOS bundle identifier to dump (e.g. com.example.MyApp)",
    )
    parser.add_argument(
        "--agent", "-a",
        default="_agent.js",
        help="path to the compiled Frida agent script (default: _agent.js)",
    )
    parser.add_argument(
        "--host",
        required=True,
        help="SSH hostname of the iOS device, as configured in ~/.ssh/config",
    )
    args = parser.parse_args()

    yafi = Yafi(args.bundle_id, args.agent, ssh_host=args.host)

    try:
        yafi.connect()
        yafi.spawn_and_attach()
        yafi.dump_all_modules()
    finally:
        yafi.kill()


if __name__ == "__main__":
    main()
