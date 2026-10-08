import { MH_MAGIC, MH_MAGIC_64, MACH_HEADER, LC, getLcName, type LoadCommand, type MachOHeader, type EncryptionInfoCommand, type DecryptedSection, EncryptionInfoCommandOffset } from "./macho";
import ObjC from "frida-objc-bridge";
import { ModuleDumpMetadata } from "./shared";
import { getErrorMessage } from "./helpers";

/**
 * Parse la table des load commands à partir du header Mach-O.
 * Chaque load command est lue séquentiellement : son type et sa taille déterminent
 * le curseur vers la suivante. Une taille nulle indique une table corrompue.
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

/**
 * Extrait les champs de chiffrement (cryptoff, cryptsize, cryptid) depuis une
 * load command LC_ENCRYPTION_INFO ou LC_ENCRYPTION_INFO_64.
 * Ces champs délimitent la zone chiffrée par FairPlay dans le binaire.
 */
function readEncryptionInfoCommand(loadCommand: LoadCommand): EncryptionInfoCommand {
    if (loadCommand.cmdType === LC.LC_ENCRYPTION_INFO || loadCommand.cmdType === LC.LC_ENCRYPTION_INFO_64) {
        const baseAddress = loadCommand.cmdAddress;

        let cryptoff: number;
        let cryptsize: number;
        let cryptid: number;
        let pad: number;

        try {
            cryptoff = baseAddress.add(EncryptionInfoCommandOffset.cryptoff).readU32();
            cryptsize = baseAddress.add(EncryptionInfoCommandOffset.cryptsize).readU32();
            cryptid = baseAddress.add(EncryptionInfoCommandOffset.cryptid).readU32();
            pad = baseAddress.add(EncryptionInfoCommandOffset.pad).readU32();
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
    } else {
        throw new Error(`expect LC_ENCRYPTION_INFO_64 or LC_ENCRYPTION_INFO cmd - ${loadCommand.cmdName}:${loadCommand.cmdType} given.`);
    }
}

/**
 * Lit la section __TEXT déchiffrée en mémoire. À ce stade, dyld a déjà déchiffré
 * le binaire FairPlay : on lit donc directement les octets en clair depuis
 * l'espace mémoire du processus, à l'offset indiqué par la load command.
 */
function readDecryptedTextSectionInTextSection(baseAddress: NativePointer, cryptOffset: number, cryptsize: number): DecryptedSection {
    const decryptedCodeAddress = baseAddress.add(cryptOffset);
    const plainBytes = decryptedCodeAddress.readByteArray(cryptsize);
    return { address: decryptedCodeAddress, bytes: plainBytes };
}

/** Lit le champ ncmds du header Mach-O pour connaître le nombre de load commands. */
function readTheNumberOfLoadCommand(module: Module): number {
    const baseAddress = module.base;
    const ncmds = baseAddress.add(MACH_HEADER.NCMDS_OFFSET).readU32();

    return ncmds;
}

/**
 * Orchestre le dump du module principal : parse les load commands, localise la
 * section chiffrée FairPlay, et retourne les octets déchiffrés avec les métadonnées
 * associées. Retourne null si le binaire n'a pas de section chiffrée.
 */
function dumpEncryptedDataText(module: Module): [ModuleDumpMetadata, ArrayBuffer] | null {
    if (!module) {
        throw new Error(`Module introuvable dans le process`);
    }

    const baseAddress = module.base;

    const ncmds = readTheNumberOfLoadCommand(module);

    const loadCmds = readLoadCommands(baseAddress, ncmds);

    const encryptCmds = loadCmds.find((cmd) => cmd.cmdType === LC.LC_ENCRYPTION_INFO_64 || cmd.cmdType === LC.LC_ENCRYPTION_INFO);

    if (encryptCmds) {
        const encryptionInfoCommand = readEncryptionInfoCommand(encryptCmds);

        const plainSection = readDecryptedTextSectionInTextSection(baseAddress, encryptionInfoCommand.cryptoff, encryptionInfoCommand.cryptsize);

        return [
            {
                moduleBase: module.base,
                moduleName: module.name,
                modulePath: module.path,
                moduleSize: module.size,
                address: plainSection.address,
                cryptoff: encryptionInfoCommand.cryptoff,
                cryptsize: encryptionInfoCommand.cryptsize,
                cryptid: encryptionInfoCommand.cryptid,
            },
            plainSection.bytes ?? new ArrayBuffer(0),
        ];
    }
    return null;
}

/** Points d'entrée RPC exposés au host Python via Frida. */
rpc.exports = {
    /** Liste les modules chargés dont le path contient "Echo" (debug). */
    prepareTheExtraction() {
        const modules = Process.enumerateModules();

        for (const module of modules) {
            if (module.path.includes("Echo")) console.log(`[i] Module found : ${module.name} at ${module.path}`);
        }
    },

    /** Retourne le chemin filesystem du binaire principal sur l'appareil. */
    getModulePath(): string {
        const mainModule = Process.mainModule;
        const mainModulePath = mainModule.path;
        return mainModulePath;
    },
    /** Dump la section chiffrée FairPlay du module principal, déjà déchiffrée en mémoire par dyld. */
    dumpModule() {
        try {
            const mainModule = Process.mainModule;

            return dumpEncryptedDataText(mainModule);
        } catch (err) {
            console.log(`[-] ${getErrorMessage(err)}`);
        }
    },
};

// recv("config", (message) => {
//     try {
//         dumpModule(message.payload as AgentConfig);
//     } catch (err) {
//         console.log(`[-] ${getErrorMessage(err)}`);
//         if (err instanceof Error) {
//             console.log(err.stack);
//         }
//     }
// });
