import {
    MH_MAGIC,
    MH_MAGIC_64,
    MACH_HEADER,
    LC,
    getLcName,
    type LoadCommand,
    type MachOHeader,
    type EncryptionInfoCommand,
    type DecryptedSection,
} from "./macho";

console.log("DUMPER AGENT LOADED");

function getErrorMessage(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
}

/**
 * Parcourt une liste de ranges mémoire exécutables à la recherche d'un header Mach-O
 * (reconnu via son magic number en tout début de range).
 */
function findMachoHeaderAddress(ranges: RangeDetails[]): MachOHeader | null {
    for (const range of ranges) {
        let magic: number;

        try {
            magic = range.base.readU32();
        } catch (err) {
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

function findModuleByName(moduleName: string): Module | null {
    let modules: Module[];

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
 */
function readLoadCommands(headerAddress: NativePointer, ncmds: number): LoadCommand[] {
    let cmdCursor = headerAddress.add(MACH_HEADER.SIZE_64);
    const cmds: LoadCommand[] = [];

    for (let i = 0; i < ncmds; i++) {
        let cmdType: number;
        let cmdSize: number;

        try {
            cmdType = cmdCursor.readU32();
            cmdSize = cmdCursor.add(0x04).readU32();
        } catch (err) {
            throw new Error(`Lecture impossible pour la load command #${i} à l'adresse ${cmdCursor}: ${getErrorMessage(err)}`);
        }

        if (cmdSize === 0) {
            throw new Error(`Load command #${i} à ${cmdCursor} a un cmdSize de 0, table de load commands corrompue`);
        }

        cmds.push({
            cmdType,
            cmdName: getLcName(cmdType),
            cmdSize,
            cmdAddress: cmdCursor,
        });

        cmdCursor = cmdCursor.add(cmdSize);
    }

    return cmds;
}

function readEncryptionInfoCommand(loadCommand: LoadCommand): EncryptionInfoCommand {
    if (loadCommand.cmdType !== LC.LC_ENCRYPTION_INFO_64) {
        throw new Error(`Load command attendue: LC_ENCRYPTION_INFO_64 (0x${LC.LC_ENCRYPTION_INFO_64.toString(16)}), reçue: ${loadCommand.cmdName} (0x${loadCommand.cmdType.toString(16)})`);
    }

    const baseAddress = loadCommand.cmdAddress;

    let cryptoff: number;
    let cryptsize: number;
    let cryptid: number;
    let pad: number;

    try {
        cryptoff = baseAddress.add(0x08).readU32();
        cryptsize = baseAddress.add(0x0c).readU32();
        cryptid = baseAddress.add(0x10).readU32();
        pad = baseAddress.add(0x14).readU32();
    } catch (err) {
        throw new Error(`Lecture impossible de encryption_info_command_64 à ${baseAddress}: ${getErrorMessage(err)}`);
    }

    return {
        cmd: loadCommand,
        cryptoff,
        cryptsize,
        cryptid,
        pad,
        toString() {
            return JSON.stringify(this);
        },
    };
}

function readDecryptedTextSectionInTextSection(
    baseAddress: NativePointer,
    cryptOffset: number,
    cryptsize: number,
): DecryptedSection {
    const decryptedCodeAddress = baseAddress.add(cryptOffset);
    const plainBytes = decryptedCodeAddress.readByteArray(cryptsize);

    return { address: decryptedCodeAddress, bytes: plainBytes };
}

function sendBackDataToWrapper(address: NativePointer, bytes: ArrayBuffer, size: number): void {
    console.log(`[i] Send data back to python ${size} bytes @ ${address}`);
    send({ event: "dump", address: address.toString(), size }, bytes);
}



//DUMPER ENCRYPTED code in __TEXT 
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

    const ncmds = baseAddress.add(MACH_HEADER.NCMDS_OFFSET).readU32();
    console.log(`[i] Nombre de load commandes 0x${ncmds.toString(16)}`);

    const loadCmds = readLoadCommands(baseAddress, ncmds);

    const encryptCmds = loadCmds.find(
        (cmd) => cmd.cmdType === LC.LC_ENCRYPTION_INFO_64,
    );

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
