"""yafipadump — Yet Another Frida IPA Dump tool.

Point d'entrée principal. Connecte un device iOS jailbreaké via USB,
injecte l'agent Frida, et dump les binaires chiffrés FairPlay
en les remplaçant par leur version déchiffrée depuis la mémoire.
"""
from yafi import Yafi

if __name__ == "__main__":
    yafi = Yafi("com.apple.weather", "_agent.js")

    try:
        yafi.connect()
        yafi.spawn_and_attach()
        yafi.dump_all_modules()
    finally:
        yafi.kill()
