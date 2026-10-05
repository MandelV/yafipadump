console.log("DUMPER AGENT LOADED");

// magic number
const MH_MAGIC = 0xfeedface; // 32-bit
const MH_MAGIC_64 = 0xfeedfacf; // 64-bit

/**
 * mach_header_64 - from https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
 * Note uint32_t unsigned int 32 bit donc 4 octets
 * struct mach_header_64 {
 *     uint32_t       magic;        // 0x00 - mach magic number identifier
 *     cpu_type_t     cputype;      // 0x04 - cpu specifier
 *     cpu_subtype_t  cpusubtype;   // 0x08 - machine specifier
 *     uint32_t       filetype;     // 0x0C - type of file
 *     uint32_t       ncmds;        // 0x10 - number of load commands        ⚠️ TRÈS IMPORTANT
 *     uint32_t       sizeofcmds;   // 0x14 - size of all the load commands  ⚠️ TRÈS IMPORTANT
 *     uint32_t       flags;        // 0x18 - flags
 *     uint32_t       reserved;     // 0x1C - reserved (absent en 32-bit, mach_header s'arrête à 0x1C)
 * };
 * // sizeof(mach_header_64) == 0x20 -> les load commands commencent juste après le header
 */

const MAC_HEAD_MAGIC_OFFSET = 0x00;
const MAC_HEAD_CPU_TYPE_OFFSET = 0x04;
const MAC_HEAD_CPUSUBTYPE_OFFSET = 0x08;
const MAC_HEAD_FILETYPE_OFFSET = 0x0c;
const MAC_HEAD_NCMDS_OFFSET = 0x10;
const MAC_HEAD_SIZEOFCMDS_OFFSET = 0x14;
const MAC_HEAD_FLAGS_OFFSET = 0x18;
const MAC_HEAD_RESERVED_OFFSET = 0x1c;

// taille totale du mach_header_64 -> point de départ des load commands
const MAC_HEAD_SIZE_64 = 0x20;

/**
 * from https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
 * un LC_REQ_DYLD ORé dans la valeur signifie "dyld doit comprendre cette commande, sinon il refuse de charger le binaire"
 */
const LC_REQ_DYLD = 0x80000000;

/** Table des constantes `cmd` des load commands Mach-O (voir loader.h) */
const LC = {
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
};

/** @type {Object<number, string>} reverse lookup valeur -> nom de la commande */
const LC_NAMES = Object.fromEntries(Object.entries(LC).map(([name, value]) => [value, name]));

/**
 * Extrait un message lisible d'une valeur catchée dans un `catch`, qui peut ne pas être une `Error`.
 *
 * @param {unknown} err - valeur catchée (typée `unknown` en strict mode)
 * @returns {string} message d'erreur lisible
 */
function getErrorMessage(err) {
    return err instanceof Error ? err.message : String(err);
}

/**
 * Résout le nom lisible d'une load command à partir de sa valeur numérique (`cmd`).
 *
 * @param {number} cmdType - valeur brute du champ `cmd` d'une load command
 * @returns {string} nom de la load command (ex: "LC_SEGMENT_64"), ou "UNKNOWN(0x..)" si non référencée dans {@link LC}
 */
function getCmdName(cmdType) {
    return LC_NAMES[cmdType] ?? `UNKNOWN(0x${cmdType.toString(16)})`;
}

/**
 * Parcourt une liste de ranges mémoire exécutables à la recherche d'un header Mach-O
 * (reconnu via son magic number en tout début de range).
 *
 * @param {RangeDetails[]} ranges - ranges mémoire à inspecter (ex: issues de `Module#enumerateRanges("r-x")`)
 * @returns {{headerAddr: NativePointer, arch: "x86"|"x64"}|null} l'adresse du header trouvé et l'architecture détectée, ou `null` si aucun header Mach-O n'a été trouvé
 */
function findMachoHeaderAddress(ranges) {
    for (const range of ranges) {
        let magic;

        try {
            magic = range.base.readU32();
        } catch (err) {
            // certaines ranges listées peuvent ne plus être mappées/lisibles au moment de la lecture
            // (race condition, guard page, etc.) : on les ignore plutôt que de faire planter toute la recherche
            console.log(`[-] Impossible de lire la range ${range.base}, ignorée (${getErrorMessage(err)})`);
            continue;
        }

        if (magic === MH_MAGIC_64) {
            return { headerAddr: range.base, arch: "x64" };
        }

        if (magic === MH_MAGIC) {
            return { headerAddr: range.base, arch: "x86" };
        }
    }

    return null;
}

/**
 * Recherche un module chargé dans le process courant par son nom exact.
 *
 * @param {string} moduleName - nom du module à trouver (ex: "EchoBack")
 * @returns {Module|null} le module trouvé, ou `null` si aucun module ne correspond
 */
function findModuleByName(moduleName) {
    let modules;

    try {
        modules = Process.enumerateModules();
    } catch (err) {
        console.log(`[-] Impossible d'énumérer les modules du process (${getErrorMessage(err)})`);
        return null;
    }

    for (const module of modules) {
        if (module.name === moduleName) {
            return module;
        }
    }

    return null;
}

/**
 * Mach-O load commands are instructions in the Mach-O file
 * format that tell the operating system loader (dyld) how to set up, map, and run a binary.
 *
 * @param {NativePointer} headerAddress - adresse du mach_header_64 (début du binaire en mémoire)
 * @param {number} ncmds - nombre de load commands à lire (champ `ncmds` du header)
 * @returns {{cmdType: number, cmdName: string, cmdSize: number, cmdAddress: NativePointer}[]} la liste des load commands lues, dans l'ordre
 * @throws {Error} si une load command est corrompue (cmdSize nul, ce qui empêcherait d'avancer) ou si une lecture mémoire échoue
 */
function readLoadCommands(headerAddress, ncmds) {
    // on place le curseur au début de la section des load commands (juste après le header, offset 0x20)
    let cmdCursor = headerAddress.add(MAC_HEAD_SIZE_64);
    const cmds = [];

    for (let i = 0; i < ncmds; i++) {
        let cmdType, cmdSize;

        try {
            cmdType = cmdCursor.readU32(); // champ `cmd`
            cmdSize = cmdCursor.add(0x04).readU32(); // champ `cmdsize`
        } catch (err) {
            throw new Error(`Lecture impossible pour la load command #${i} à l'adresse ${cmdCursor}: ${getErrorMessage(err)}`);
        }

        if (cmdSize === 0) {
            // un cmdSize nul ne ferait pas avancer le curseur -> on relirait la même commande en boucle
            throw new Error(`Load command #${i} à ${cmdCursor} a un cmdSize de 0, table de load commands corrompue`);
        }

        cmds.push({
            cmdType: cmdType,
            cmdName: getCmdName(cmdType),
            cmdSize: cmdSize,
            cmdAddress: cmdCursor,
        });

        // on avance jusqu'à la prochaine load command
        cmdCursor = cmdCursor.add(cmdSize);
    }

    return cmds;
}

/**
 * struct encryption_info_command_64 {
 *     uint32_t cmd;       // 0x00 - LC_ENCRYPTION_INFO_64
 *     uint32_t cmdsize;   // 0x04 - sizeof(struct encryption_info_command_64)
 *     uint32_t cryptoff;  // 0x08 - file offset of encrypted range
 *     uint32_t cryptsize; // 0x0C - file size of encrypted range
 *     uint32_t cryptid;   // 0x10 - which encryption system, 0 means not-encrypted yet
 *     uint32_t pad;       // 0x14 - padding to make this struct's size a multiple of 8 bytes
 * };
 *
 * @param {{cmdType: number, cmdName: string, cmdSize: number, cmdAddress: NativePointer}} loadCommand - entrée issue de {@link readLoadCommands}, doit être de type LC_ENCRYPTION_INFO_64
 * @returns {{cmd: {cmdType: number, cmdName: string, cmdSize: number, cmdAddress: NativePointer}, cryptoff: number, cryptsize: number, cryptid: number, pad: number, toString: Function}} le contenu parsé de la commande
 * @throws {Error} si `loadCommand` n'est pas une LC_ENCRYPTION_INFO_64, ou si la lecture mémoire échoue
 */
function readEncryptionInfoCommand(loadCommand) {
    if (loadCommand.cmdType !== LC.LC_ENCRYPTION_INFO_64) {
        throw new Error(`Load command attendue: LC_ENCRYPTION_INFO_64 (0x${LC.LC_ENCRYPTION_INFO_64.toString(16)}), reçue: ${loadCommand.cmdName} (0x${loadCommand.cmdType.toString(16)})`);
    }

    const baseAddress = loadCommand.cmdAddress;

    let cryptoff, cryptsize, cryptid, pad;
    try {
        cryptoff = baseAddress.add(0x08).readU32();
        cryptsize = baseAddress.add(0x0c).readU32();
        cryptid = baseAddress.add(0x10).readU32();
        pad = baseAddress.add(0x14).readU32();
    } catch (err) {
        throw new Error(`Lecture impossible de encryption_info_command_64 à ${baseAddress}: ${getErrorMessage(err)}`);
    }

    const encryptionInfoCommand = {
        cmd: loadCommand,
        cryptoff: cryptoff,
        cryptsize: cryptsize,
        cryptid: cryptid,
        pad: pad,
        toString: function () {
            return JSON.stringify(this);
        },
    };

    return encryptionInfoCommand;
}

/**
 * @param {NativePointer} baseAddress
 * @param {number} cryptOffset
 * @param {number} cryptsize
 * @returns {{address: NativePointer, bytes: ArrayBuffer|null}} l'adresse mémoire réelle du chunk lu, et son contenu déchiffré (`null` si la lecture échoue)
 */
function readDecryptedTextSectionInTextSection(baseAddress, cryptOffset, cryptsize) {
    const decryptedCodeAddress = baseAddress.add(cryptOffset);
    const plainBytes = decryptedCodeAddress.readByteArray(cryptsize);

    return { address: decryptedCodeAddress, bytes: plainBytes };
}

/**
 * @param {NativePointer} address - adresse mémoire réelle du chunk (pour permettre à Capstone de calculer
 *                                  correctement les cibles des instructions PC-relatives: bl/b/adrp/...)
 * @param {ArrayBuffer} bytes
 * @param {number} size
 */
function sendBackDataToWrapper(address, bytes, size) {
    console.log(`[i] Send data back to python ${size} bytes @ ${address}`);
    send({ event: "dump", address: address.toString(), size: size }, bytes);
}

try {
    const TARGET_MODULE_NAME = "EchoBack";

    const module = findModuleByName(TARGET_MODULE_NAME);
    if (!module) {
        throw new Error(`Module "${TARGET_MODULE_NAME}" introuvable dans le process`);
    }

    // const ranges = module.enumerateRanges("r-x");
    // const headerInfo = findMachoHeaderAddress(ranges);
    // if (!headerInfo) {
    //     throw new Error(`Aucun header Mach-O trouvé dans les ranges exécutables de "${TARGET_MODULE_NAME}"`);
    // }

    const baseAddress = module.base;
    console.log(`[+] Header Mach-o find at (addr): ${baseAddress}`);

    const ncmds = baseAddress.add(MAC_HEAD_NCMDS_OFFSET).readU32();
    console.log(`[i] Nombre de load commandes 0x${ncmds.toString(16)}`);

    const loadCmds = readLoadCommands(baseAddress, ncmds);

    const encryptCmds = loadCmds.find((cmd) => {
        if (cmd.cmdType === LC.LC_ENCRYPTION_INFO_64) {
            return cmd;
        }
    });

    if (encryptCmds) {
        console.log(`[+] LC_ENCRYPTION_INFO_64 CMD found  ${encryptCmds.cmdName} (0x${encryptCmds.cmdType.toString(16)}) at ${encryptCmds.cmdAddress} - size:${encryptCmds.cmdSize}`);
        const encryptionInfoCommand = readEncryptionInfoCommand(encryptCmds);
        console.log(`[+] output encryption_info_command :`);
        console.log(encryptionInfoCommand.toString());

        console.log(`[i] Read Plain section :`);

        const plainSection = readDecryptedTextSectionInTextSection(baseAddress, encryptionInfoCommand.cryptoff, encryptionInfoCommand.cryptsize);
        if (plainSection.bytes) sendBackDataToWrapper(plainSection.address, plainSection.bytes, encryptionInfoCommand.cryptsize);
    }
} catch (err) {
    console.log(`[-] ${getErrorMessage(err)}`);
    if (err instanceof Error) {
        console.log(err.stack);
    }
}
