"""Types Python miroirs des interfaces TypeScript (agent/shared.ts).

Frida sérialise les objets JS en JSON lors du transfert RPC.
Côté Python on reçoit donc des dicts — ces TypedDict documentent
la structure exacte et permettent l'autocomplétion + la vérification
statique (mypy / pyright).

Les noms de clés sont en camelCase pour correspondre au JSON reçu
(Frida ne transforme pas les clés d'objets, seulement les noms de méthodes RPC).
"""
from dataclasses import dataclass
from typing import TypedDict


# --- Miroirs des interfaces TypeScript ---


class LcEncryptionInfoDict(TypedDict):
    """Miroir de LcEncryptionInfo (agent/shared.ts).

    Champs de la load command encryption_info_command_64.
    Décrit la zone du binaire chiffrée par FairPlay DRM.
    """
    cryptoff: int   # offset dans le fichier Mach-O où commence la zone chiffrée
    cryptsize: int  # taille de la zone chiffrée (octets)
    cryptid: int    # système de chiffrement : 0=clair, 1=FairPlay app, 2=FairPlay ML model
    pad: int        # padding d'alignement pour la version 64-bit de la struct


class DecryptedSectionMetaDict(TypedDict):
    """Miroir de DecryptedSectionMeta (agent/shared.ts).

    Métadonnées de la zone déchiffrée lue en mémoire du process.
    Les octets eux-mêmes sont transmis séparément en tant que bytes (ArrayBuffer côté JS).
    """
    address: str    # adresse mémoire (NativePointer sérialisé en string "0x..." par Frida)
    size: int       # taille effective des octets lus (== cryptsize sauf erreur)


class LoadCommandDict(TypedDict):
    """Miroir de LoadCommand (agent/macho.ts).

    Représentation d'une load command parsée depuis le header Mach-O.
    """
    cmdType: int        # valeur numérique (ex: 0x19 = LC_SEGMENT_64, 0x2C = LC_ENCRYPTION_INFO_64)
    cmdName: str        # nom lisible via getLcName() (ex: "LC_SEGMENT_64")
    cmdSize: int        # taille totale de la commande en octets (header cmd/cmdsize inclus)
    cmdAddress: str     # adresse mémoire dans le process (NativePointer → string hex)


class ModuleMetaDataDict(TypedDict):
    """Miroir de ModuleMetaData (agent/shared.ts).

    Métadonnées complètes d'un module Mach-O tel que chargé en mémoire par dyld.
    Retourné par l'appel RPC dumpModules(index).
    """
    moduleBase: str                                         # début du mach_header_64 en mémoire
    isMainModule: bool                                      # True si c'est Process.mainModule
    moduleName: str                                         # nom court du binaire (ex: "MyApp")
    modulePath: str                                         # chemin complet sur le device iOS
    moduleParentPath: str                                   # répertoire parent (le .app bundle)
    moduleSize: int                                         # taille du module mappé en mémoire
    moduleArch: str                                         # architecture CPU (ex: "arm64")
    modulePlatform: str                                     # plateforme (ex: "darwin")
    nlcmds: int                                             # nombre de load commands dans le header
    LoadCommands: list[LoadCommandDict]                     # table complète des load commands
    LcEncryptionInfo: LcEncryptionInfoDict | None           # infos FairPlay, None si pas de LC_ENCRYPTION_INFO
    isEncrypted: bool                                       # True si cryptid > 0
    DecryptedSectionMeta: DecryptedSectionMetaDict | None   # rempli côté agent après le dump mémoire


# --- Types internes Python ---


@dataclass
class BinaryInfo:
    """Infos extraites d'un binaire Mach-O sur disque (via lief).

    Utilisé pour vérifier l'intégrité avant/après patching :
    on compare les hash de la zone chiffrée entre le fichier et le dump mémoire.
    """
    file_hash: str      # SHA-256 du fichier complet
    crypt_hash: str     # SHA-256 de la zone [cryptoff, cryptoff+cryptsize]
    cryptoff: int       # offset de la zone chiffrée dans le fichier
    cryptsize: int      # taille de la zone chiffrée
    cryptid: int        # 0 après patch, >0 avant
