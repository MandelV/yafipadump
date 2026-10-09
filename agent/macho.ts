/**
 * Constantes et types issus du format Mach-O.
 * Toutes les valeurs viennent de xnu/EXTERNAL_HEADERS/mach-o/loader.h.
 *
 * @see https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
 */

// --- Magic numbers ---
// Identifient l'architecture du binaire dès les 4 premiers octets du fichier.

export const MH_MAGIC = 0xfeedface; // Mach-O 32-bit (big-endian natif)
export const MH_MAGIC_64 = 0xfeedfacf; // Mach-O 64-bit (tous les binaires iOS modernes)

// --- mach_header_64 layout ---

/**
 * Offsets des champs de la struct mach_header_64 (loader.h:72).
 *
 * Le header est la toute première structure du fichier Mach-O.
 * En mémoire, module.base pointe sur le premier octet (magic).
 * Les load commands suivent immédiatement après, à base + SIZE_64 (0x20).
 *
 * struct mach_header_64 {
 *     uint32_t       magic;        // 0x00 -- identifie l'archi (0xfeedfacf = 64-bit)
 *     cpu_type_t     cputype;      // 0x04 -- type CPU (ex: CPU_TYPE_ARM64 = 0x100000C)
 *     cpu_subtype_t  cpusubtype;   // 0x08 -- sous-type CPU
 *     uint32_t       filetype;     // 0x0C -- type de fichier (MH_EXECUTE, MH_DYLIB, …)
 *     uint32_t       ncmds;        // 0x10 -- nombre de load commands qui suivent
 *     uint32_t       sizeofcmds;   // 0x14 -- taille totale de toutes les load commands
 *     uint32_t       flags;        // 0x18 -- flags (PIE, TWOLEVEL, …)
 *     uint32_t       reserved;     // 0x1C -- réservé (absent en 32-bit)
 * };
 * sizeof(mach_header_64) == 0x20 (32 octets)
 */
export const MACH_HEADER = {
    MAGIC_OFFSET: 0x00,
    CPU_TYPE_OFFSET: 0x04,
    CPUSUBTYPE_OFFSET: 0x08,
    FILETYPE_OFFSET: 0x0c,
    NCMDS_OFFSET: 0x10,
    SIZEOFCMDS_OFFSET: 0x14,
    FLAGS_OFFSET: 0x18,
    RESERVED_OFFSET: 0x1c,
    SIZE_64: 0x20, // Taille totale du header -- les load commands commencent juste après
} as const;

// --- Load command constants (loader.h:252+) ---

/**
 * Bit haut ORé dans le champ cmd d'une load command.
 * Signifie "dyld DOIT comprendre cette commande, sinon il refuse de charger le binaire".
 * Les commandes sans ce bit sont ignorées silencieusement par un dyld qui ne les connaît pas.
 */
export const LC_REQ_DYLD = 0x80000000;

export const LC = {
    LC_SEGMENT: 0x1,
    LC_SYMTAB: 0x2,
    LC_SYMSEG: 0x3,
    LC_THREAD: 0x4,
    LC_UNIXTHREAD: 0x5,
    LC_LOADFVMLIB: 0x6,
    LC_IDFVMLIB: 0x7,
    LC_IDENT: 0x8,
    LC_FVMFILE: 0x9,
    LC_PREPAGE: 0xa,
    LC_DYSYMTAB: 0xb,
    LC_LOAD_DYLIB: 0xc,
    LC_ID_DYLIB: 0xd,
    LC_LOAD_DYLINKER: 0xe,
    LC_ID_DYLINKER: 0xf,
    LC_PREBOUND_DYLIB: 0x10,
    LC_ROUTINES: 0x11,
    LC_SUB_FRAMEWORK: 0x12,
    LC_SUB_UMBRELLA: 0x13,
    LC_SUB_CLIENT: 0x14,
    LC_SUB_LIBRARY: 0x15,
    LC_TWOLEVEL_HINTS: 0x16,
    LC_PREBIND_CKSUM: 0x17,
    LC_LOAD_WEAK_DYLIB: 0x18 | LC_REQ_DYLD,
    LC_SEGMENT_64: 0x19,
    LC_ROUTINES_64: 0x1a,
    LC_UUID: 0x1b,
    LC_RPATH: 0x1c | LC_REQ_DYLD,
    LC_CODE_SIGNATURE: 0x1d,
    LC_SEGMENT_SPLIT_INFO: 0x1e,
    LC_REEXPORT_DYLIB: 0x1f | LC_REQ_DYLD,
    LC_LAZY_LOAD_DYLIB: 0x20,
    LC_ENCRYPTION_INFO: 0x21, // FairPlay 32-bit
    LC_DYLD_INFO: 0x22,
    LC_DYLD_INFO_ONLY: 0x22 | LC_REQ_DYLD,
    LC_LOAD_UPWARD_DYLIB: 0x23 | LC_REQ_DYLD,
    LC_VERSION_MIN_MACOSX: 0x24,
    LC_VERSION_MIN_IPHONEOS: 0x25,
    LC_FUNCTION_STARTS: 0x26,
    LC_DYLD_ENVIRONMENT: 0x27,
    LC_MAIN: 0x28 | LC_REQ_DYLD,
    LC_DATA_IN_CODE: 0x29,
    LC_SOURCE_VERSION: 0x2a,
    LC_DYLIB_CODE_SIGN_DRS: 0x2b,
    LC_ENCRYPTION_INFO_64: 0x2c, // FairPlay 64-bit -- la commande qu'on cherche pour le dump
    LC_LINKER_OPTION: 0x2d,
    LC_LINKER_OPTIMIZATION_HINT: 0x2e,
    LC_VERSION_MIN_TVOS: 0x2f,
    LC_VERSION_MIN_WATCHOS: 0x30,
    LC_NOTE: 0x31,
    LC_BUILD_VERSION: 0x32,
    LC_DYLD_EXPORTS_TRIE: 0x33 | LC_REQ_DYLD,
    LC_DYLD_CHAINED_FIXUPS: 0x34 | LC_REQ_DYLD,
    LC_FILESET_ENTRY: 0x35 | LC_REQ_DYLD,
} as const;

/** Lookup inversé : valeur numérique → nom de la constante LC_*. */
export const LC_NAMES: Record<number, string> = Object.fromEntries(Object.entries(LC).map(([name, value]) => [value, name]));

/** Retourne le nom lisible d'un type de load command, ou "UNKNOWN(0x...)" si inconnu. */
export function getLcName(cmdType: number): string {
    return LC_NAMES[cmdType] ?? `UNKNOWN(0x${cmdType.toString(16)})`;
}

// --- Interfaces ---

/**
 * Représentation d'une load command parsée depuis le header Mach-O.
 * Chaque load command commence par { uint32 cmd; uint32 cmdsize; } (loader.h:247).
 *
 * struct load_command {
 *     uint32_t cmd;		//type of load command
 *     uint32_t cmdsize;	// total size of command in bytes
 * };
 *
 */
export interface LoadCommand {
    /** Type de commande (valeur numérique, ex: LC.LC_SEGMENT_64 = 0x19). */
    cmdType: number;
    /** Nom lisible du type (ex: "LC_SEGMENT_64"). */
    cmdName: string;
    /** Taille totale de la commande en octets (header cmd/cmdsize inclus). */
    cmdSize: number;
    /** Adresse mémoire du début de cette load command dans le process. */
    cmdAddress: NativePointer;
}

export interface MachOHeader {
    headerAddr: NativePointer;
    arch: "x86" | "x64";
}

/**
 * Offsets des champs de la struct encryption_info_command_64 (loader.h:1230).
 *
 * Cette load command décrit la zone du binaire chiffrée par FairPlay DRM.
 * Au lancement, le kernel lit cryptid pour décider s'il faut déchiffrer :
 *   - cryptid == 0 (CRYPTID_NO_ENCRYPTION) : pas de chiffrement
 *   - cryptid == 1 (CRYPTID_APP_ENCRYPTION) : binaire App Store chiffré
 *   - cryptid == 2 (CRYPTID_MODEL_ENCRYPTION) : modèle ML chiffré
 *
 * Si cryptid > 0, le kernel appelle vm_map_apple_protected() qui met en place
 * un apple_protect_pager pour déchiffrer les pages à la demande via le daemon
 * fairplayd (HOST_FAIRPLAYD_PORT). C'est pourquoi en mémoire, à ce stade,
 * les octets à base+cryptoff sont déjà en clair.
 *
 * @see xnu/bsd/sys/mman.h -- CRYPTID_NO_ENCRYPTION / CRYPTID_APP_ENCRYPTION
 * @see xnu/osfmk/vm/vm_protos.h -- vm_map_apple_protected()
 * @see xnu/osfmk/kern/page_decrypt.h -- text_crypter_create_hook_t
 *
 * struct encryption_info_command_64 {
 *     uint32_t cmd;       // 0x00 -- LC_ENCRYPTION_INFO_64
 *     uint32_t cmdsize;   // 0x04 -- sizeof(struct) = 24
 *     uint32_t cryptoff;  // 0x08 -- offset fichier du début de la zone chiffrée
 *     uint32_t cryptsize; // 0x0C -- taille de la zone chiffrée
 *     uint32_t cryptid;   // 0x10 -- système de chiffrement (0 = non chiffré)
 *     uint32_t pad;       // 0x14 -- alignement 8 octets (64-bit seulement)
 * };
 */
export const EncryptionInfoCommandOffset = {
    cmd: 0x00,
    cmdsize: 0x04,
    cryptoff: 0x08,
    cryptsize: 0x0c,
    cryptid: 0x10,
    pad: 0x14,
} as const;

/** Représentation parsée d'une encryption_info_command_64. */
export interface EncryptionInfoCommand {
    /** La load command source dont on a extrait ces champs. */
    cmd: LoadCommand;
    /** Offset dans le fichier Mach-O où commence la zone chiffrée. */
    cryptoff: number;
    /** Taille de la zone chiffrée (en octets). */
    cryptsize: number;
    /** ID du système de chiffrement : 0=clair, 1=FairPlay app, 2=FairPlay ML model. */
    cryptid: number;
    /** Padding d'alignement (64-bit). */
    pad: number;
    toString(): string;
}

/**
 * Représentation d'un segment_command_64 (loader.h -- LC_SEGMENT_64).
 *
 * Décrit un segment du binaire à mapper dans l'espace d'adressage 64-bit.
 * Le segment __TEXT contient le code exécutable (et la zone chiffrée FairPlay).
 * Si le segment contient des sections, les struct section_64 suivent immédiatement
 * dans le fichier et leur taille est incluse dans cmdsize.
 */
export interface SegmentCommand64 {
    cmd: number; /* LC_SEGMENT_64 (0x19) */
    cmdsize: number; /* taille totale incluant les section_64 qui suivent */
    segname: string; /* nom du segment, 16 chars fixe (ex: "__TEXT", "__DATA") */
    vmaddr: bigint; /* adresse virtuelle de début du segment en mémoire */
    vmsize: bigint; /* taille du segment en mémoire */
    fileoff: bigint; /* offset dans le fichier Mach-O */
    filesize: bigint; /* taille dans le fichier */
    maxprot: number; /* protection VM maximale (rwx) */
    initprot: number; /* protection VM initiale */
    nsects: number; /* nombre de sections dans ce segment */
    flags: number; /* flags du segment */
}
