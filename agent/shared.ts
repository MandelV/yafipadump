import { LoadCommand } from "./macho";

/**
 * Métadonnées complètes d'un module Mach-O tel que chargé en mémoire par dyld.
 * Regroupe les infos du Module Frida, les load commands parsées, et l'état
 * de chiffrement FairPlay pour permettre le dump ultérieur.
 */
export interface ModuleMetaData {
    /** Adresse de base du module en mémoire (début du mach_header_64). */
    moduleBase: NativePointer;

    /** true si ce module est le binaire principal du process (Process.mainModule). */
    isMainModule: boolean;
    /** Nom court du binaire (ex: "MyApp"). */
    moduleName: string;
    /** Chemin complet sur le filesystem de l'appareil. */
    modulePath: string;
    /** Nom du répertoire du module principal */
    moduleAppDir: string;
    /** nom du répertoire parent sur le filesystem de l'appareil. */
    moduleParentPath: string;
    /** Taille totale du module mappé en mémoire (en octets). */
    moduleSize: number;
    /** Architecture CPU du process (ex: "arm64"). */
    moduleArch: string;
    /** Plateforme cible (ex: "darwin"). */
    modulePlatform: string;
    /** Nombre de load commands (champ ncmds du mach_header_64). */
    nlcmds: number;
    /** Table complète des load commands parsées depuis le header. */
    LoadCommands: Array<LoadCommand>;
    /** Infos de chiffrement FairPlay extraites de LC_ENCRYPTION_INFO[_64], null si absent. */
    LcEncryptionInfo: LcEncryptionInfo | null;
    /** true si cryptid > 0, i.e. le binaire est (ou était) chiffré par FairPlay. */
    isEncrypted: boolean;
    /** Métadonnées de la zone déchiffrée lue en mémoire, null tant que le dump n'est pas fait. */
    DecryptedSectionMeta: DecryptedSectionMeta | null;
}

/**
 * Métadonnées de la zone déchiffrée extraite de la mémoire du process.
 * Les octets eux-mêmes sont transportés séparément dans un ArrayBuffer.
 */
export interface DecryptedSectionMeta {
    /** Adresse mémoire du début de la zone déchiffrée (base + cryptoff). */
    address: NativePointer;
    /** Taille effective des octets lus (== cryptsize sauf erreur de lecture). */
    size: number;
}

/**
 * Champs extraits de la load command encryption_info_command_64 (ou 32-bit).
 * Décrit la zone du binaire chiffrée par FairPlay DRM.
 *
 * @see EXTERNAL_HEADERS/mach-o/loader.h -- struct encryption_info_command_64
 */
export interface LcEncryptionInfo {
    /** Offset dans le fichier Mach-O où commence la zone chiffrée. */
    cryptoff: number;
    /** Taille de la zone chiffrée (en octets). */
    cryptsize: number;
    /** Identifiant du système de chiffrement : 0 = non chiffré, >0 = chiffré (FairPlay). */
    cryptid: number;
    /** Padding d'alignement (8 octets) pour la version 64-bit de la struct. */
    pad: number;
}

/**
 * Couple métadonnées + octets déchiffrés d'un module, stocké en mémoire
 * par dumpModules() pour être récupéré un par un via getModule(index).
 * Frida RPC ne peut transférer qu'un seul ArrayBuffer par appel.
 */
export interface DumpedModule {
    moduleMetaData: ModuleMetaData;
    data: ArrayBuffer;
}
