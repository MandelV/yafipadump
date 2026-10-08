/**
 * Constantes et types issus du format Mach-O (loader.h)
 * @see https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
 */

// --- Magic numbers ---

export const MH_MAGIC = 0xfeedface; // 32-bit
export const MH_MAGIC_64 = 0xfeedfacf; // 64-bit

// --- mach_header_64 layout ---

/**
 * struct mach_header_64 {
 *     uint32_t       magic;        // 0x00 - mach magic number identifier
 *     cpu_type_t     cputype;      // 0x04 - cpu specifier
 *     cpu_subtype_t  cpusubtype;   // 0x08 - machine specifier
 *     uint32_t       filetype;     // 0x0C - type of file
 *     uint32_t       ncmds;        // 0x10 - number of load commands
 *     uint32_t       sizeofcmds;   // 0x14 - size of all the load commands
 *     uint32_t       flags;        // 0x18 - flags
 *     uint32_t       reserved;     // 0x1C - reserved (absent en 32-bit)
 * };
 * sizeof(mach_header_64) == 0x20
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
    SIZE_64: 0x20,
} as const;

// --- Load command constants ---

/**
 * un LC_REQ_DYLD ORé dans la valeur signifie
 * "dyld doit comprendre cette commande, sinon il refuse de charger le binaire"
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
    LC_ENCRYPTION_INFO: 0x21,
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
    LC_ENCRYPTION_INFO_64: 0x2c,
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

export const LC_NAMES: Record<number, string> = Object.fromEntries(Object.entries(LC).map(([name, value]) => [value, name]));

export function getLcName(cmdType: number): string {
    return LC_NAMES[cmdType] ?? `UNKNOWN(0x${cmdType.toString(16)})`;
}

// --- Interfaces ---

export interface LoadCommand {
    cmdType: number;
    cmdName: string;
    cmdSize: number;
    cmdAddress: NativePointer;
}

export interface MachOHeader {
    headerAddr: NativePointer;
    arch: "x86" | "x64";
}

/**
 * struct encryption_info_command_64 {
 *     uint32_t cmd;       // 0x00 - LC_ENCRYPTION_INFO_64
 *     uint32_t cmdsize;   // 0x04
 *     uint32_t cryptoff;  // 0x08 - file offset of encrypted range
 *     uint32_t cryptsize; // 0x0C - file size of encrypted range
 *     uint32_t cryptid;   // 0x10 - which encryption system, 0 means not-encrypted yet
 *     uint32_t pad;       // 0x14 - padding to make this struct's size a multiple of 8 bytes
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
/**
 * struct encryption_info_command_64 {
 *     uint32_t cmd;       // 0x00 - LC_ENCRYPTION_INFO_64
 *     uint32_t cmdsize;   // 0x04
 *     uint32_t cryptoff;  // 0x08 - file offset of encrypted range
 *     uint32_t cryptsize; // 0x0C - file size of encrypted range
 *     uint32_t cryptid;   // 0x10 - which encryption system, 0 means not-encrypted yet
 *     uint32_t pad;       // 0x14 - padding to make this struct's size a multiple of 8 bytes
 * };
 */
export interface EncryptionInfoCommand {
    cmd: LoadCommand;
    cryptoff: number;
    cryptsize: number;
    cryptid: number;
    pad: number;
    toString(): string;
}

export interface DecryptedSection {
    address: NativePointer;
    bytes: ArrayBuffer | null;
}

/*
 * The 64-bit segment load command indicates that a part of this file is to be
 * mapped into a 64-bit task's address space.  If the 64-bit segment has
 * sections then section_64 structures directly follow the 64-bit segment
 * command and their size is reflected in cmdsize.
 */
export interface SegmentCommand64 {
    cmd: number; /* LC_SEGMENT_64 */
    cmdsize: number; /* includes sizeof section_64 structs */
    segname: string; /* segment name (fixed-size 16 chars) */
    vmaddr: bigint; /* memory address of this segment */
    vmsize: bigint; /* memory size of this segment */
    fileoff: bigint; /* file offset of this segment */
    filesize: bigint; /* amount to map from the file */
    maxprot: number; /* maximum VM protection */
    initprot: number; /* initial VM protection */
    nsects: number; /* number of sections in segment */
    flags: number; /* flags */
}
