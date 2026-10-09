import { MACH_HEADER, LC, getLcName, type LoadCommand, type EncryptionInfoCommand, EncryptionInfoCommandOffset } from "./macho";
import { DecryptedSectionMeta, DumpedModule, LcEncryptionInfo, ModuleMetaData } from "./shared";
import { dirname, getErrorMessage, nullData } from "./helpers";

/**
 * Parse la table des load commands à partir du header Mach-O.
 *
 * En mémoire le layout est :
 *   [mach_header_64 (0x20 octets)] [LC #0] [LC #1] ... [LC #ncmds-1]
 *
 * Chaque load command commence par { uint32 cmd; uint32 cmdsize; } --
 * cmdsize donne la taille totale de la commande (header inclus), donc
 * le curseur avance de cmdsize pour passer à la suivante.
 *
 * @see EXTERNAL_HEADERS/mach-o/loader.h -- struct load_command
 */
function readLoadCommands(headerAddress: NativePointer, ncmds: number): LoadCommand[] {
    // La première load command suit immédiatement le header (sizeof(mach_header_64) = 0x20)
    let cmdCursor = headerAddress.add(MACH_HEADER.SIZE_64);
    const cmds: LoadCommand[] = [];

    for (let i = 0; i < ncmds; i++) {
        let cmdType: number;
        let cmdSize: number;

        try {
            // Toute load command commence par 2 uint32 : cmd (le type) puis cmdsize (taille totale)
            // C'est le contrat de base de struct load_command dans loader.h
            cmdType = cmdCursor.readU32();
            cmdSize = cmdCursor.add(0x04).readU32();
        } catch (err) {
            throw new Error(`Lecture impossible pour la load command #${i} à l'adresse ${cmdCursor}: ${getErrorMessage(err)}`);
        }

        // cmdSize == 0 casserait la boucle (curseur qui n'avance plus) → table corrompue
        if (cmdSize === 0) {
            throw new Error(`Load command #${i} à ${cmdCursor} a un cmdSize de 0, table de load commands corrompue`);
        }

        cmds.push({
            cmdType,
            cmdName: getLcName(cmdType),
            cmdSize,
            cmdAddress: cmdCursor,
        });

        // Le curseur saute de cmdSize octets pour atteindre la LC suivante
        cmdCursor = cmdCursor.add(cmdSize);
    }

    return cmds;
}

/**
 * Lit les champs de la struct encryption_info_command_64 en mémoire.
 *
 * Layout de la struct (24 octets) :
 *   +0x00  cmd        -- LC_ENCRYPTION_INFO ou LC_ENCRYPTION_INFO_64
 *   +0x04  cmdsize    -- taille totale de la commande
 *   +0x08  cryptoff   -- offset dans le fichier où commence la zone chiffrée
 *   +0x0C  cryptsize  -- taille de la zone chiffrée
 *   +0x10  cryptid    -- 0 = pas encore chiffré, >0 = identifiant FairPlay
 *   +0x14  pad        -- alignement 8 octets (64-bit uniquement)
 *
 * @see EXTERNAL_HEADERS/mach-o/loader.h -- struct encryption_info_command_64
 */
function readEncryptionInfoCommand(loadCommand: LoadCommand): EncryptionInfoCommand {
    if (loadCommand.cmdType === LC.LC_ENCRYPTION_INFO || loadCommand.cmdType === LC.LC_ENCRYPTION_INFO_64) {
        // On lit à partir de l'adresse de la load command elle-même :
        // les champs cmd et cmdsize occupent les 8 premiers octets,
        // puis cryptoff/cryptsize/cryptid/pad suivent aux offsets définis dans EncryptionInfoCommandOffset
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
 * Lit en mémoire les octets déchiffrés de la zone FairPlay.
 *
 * Quand une app chiffrée est lancée, dyld détecte cryptid > 0 et demande au
 * kernel de déchiffrer la zone [cryptoff, cryptoff+cryptsize] avant de mapper
 * le segment __TEXT. À ce stade (Frida attaché au process vivant), les octets
 * en mémoire à base+cryptoff sont déjà en clair -- on les lit directement.
 *
 * Côté kernel (xnu) le mécanisme est :
 *   1. Le kernel lit LC_ENCRYPTION_INFO_64 depuis le Mach-O
 *   2. Si cryptid > 0, il appelle vm_map_apple_protected() qui crée un apple_protect_pager
 *   3. Ce pager utilise le hook text_crypter_create (enregistré par FairPlay kext)
 *      pour déchiffrer les pages à la demande via le daemon fairplayd (HOST_FAIRPLAYD_PORT)
 *   4. Résultat : quand le code s'exécute, les pages mémoire sont en clair
 *
 * @see xnu/osfmk/vm/vm_protos.h -- vm_map_apple_protected()
 * @see xnu/osfmk/kern/page_decrypt.h -- text_crypter_create_hook_t
 */
function readDecryptedDataInMemory(baseAddress: NativePointer, cryptOffset: number, cryptsize: number): [DecryptedSectionMeta, ArrayBuffer] {
    // base + cryptoff = adresse mémoire du début de la zone qui était chiffrée sur disque
    // mais qui est maintenant en clair grâce au déchiffrement par le kernel au chargement
    const decryptedCodeAddress = baseAddress.add(cryptOffset);

    // readByteArray peut retourner null si la taille est 0 -- on fallback sur un buffer vide
    const plainBytes = decryptedCodeAddress.readByteArray(cryptsize) || nullData;

    return [{ address: decryptedCodeAddress, size: plainBytes.byteLength }, plainBytes];
}

/**
 * Lit le nombre de load commands depuis le champ ncmds du mach_header_64.
 * Le champ ncmds est à l'offset 0x10 du début du header (voir MACH_HEADER.NCMDS_OFFSET).
 */
function readTheNumberOfLoadCommand(module: Module): number {
    const baseAddress = module.base;
    // module.base pointe sur le mach_header_64, ncmds est le 5ème uint32
    const ncmds = baseAddress.add(MACH_HEADER.NCMDS_OFFSET).readU32();

    return ncmds;
}

/**
 * Cherche la load command LC_ENCRYPTION_INFO[_64] parmi les load commands
 * du module et en extrait les champs de chiffrement.
 *
 * On cherche d'abord la version 64-bit (0x2C) puis la 32-bit (0x21).
 * En pratique sur iOS moderne, c'est toujours LC_ENCRYPTION_INFO_64.
 *
 * Retourne null si aucune commande de chiffrement n'est présente
 * (cas d'un binaire non distribué via l'App Store, ou déjà strippé).
 */
function extractLcEncryptionInfo(loadsCommands: LoadCommand[]): LcEncryptionInfo | null {
    if (!loadsCommands) {
        throw new Error(`load commands null`);
    }
    if (loadsCommands.length == 0) {
        throw new Error("no load command in your load commands array");
    }

    // Cherche la première LC qui correspond à une encryption info (64 ou 32-bit)
    const encryptCmd = loadsCommands.find((cmd) => cmd.cmdType === LC.LC_ENCRYPTION_INFO_64 || cmd.cmdType === LC.LC_ENCRYPTION_INFO);

    if (encryptCmd) {
        const encryptionInfoCommand = readEncryptionInfoCommand(encryptCmd);
        return {
            cryptoff: encryptionInfoCommand.cryptoff,
            cryptsize: encryptionInfoCommand.cryptsize,
            cryptid: encryptionInfoCommand.cryptid,
            pad: encryptionInfoCommand.pad,
        };
    } else {
        // Pas de LC_ENCRYPTION_INFO → binaire non chiffré (dev build, jailbreak, etc.)
        return null;
    }
}

/**
 * Extrait les octets déchiffrés du module si celui-ci est protégé par FairPlay.
 * Vérifie isEncrypted (cryptid > 0) avant de tenter la lecture mémoire.
 * Retourne null si le module n'est pas chiffré -- le host recevra alors un nullData.
 */
function extractDecryptedData(moduleMeta: ModuleMetaData): [DecryptedSectionMeta, ArrayBuffer] | null {
    if (!moduleMeta) {
        throw new Error(`moduleMeta is null`);
    }

    // On ne lit la mémoire que si le binaire est réellement chiffré (cryptid > 0)
    // ET qu'on a bien trouvé la LC_ENCRYPTION_INFO avec les offsets
    if (moduleMeta.isEncrypted && moduleMeta.LcEncryptionInfo) {
        return readDecryptedDataInMemory(moduleMeta.moduleBase, moduleMeta.LcEncryptionInfo.cryptoff, moduleMeta.LcEncryptionInfo.cryptsize);
    }
    return null;
}

/**
 * Parse un module Mach-O et construit ses métadonnées complètes.
 *
 * Étapes :
 *  1. Lire ncmds dans le mach_header_64
 *  2. Parser toutes les load commands séquentiellement
 *  3. Chercher LC_ENCRYPTION_INFO[_64] pour déterminer si FairPlay est présent
 *  4. Assembler le tout dans un ModuleMetaData
 *
 * Note : le dump effectif des octets déchiffrés est fait séparément
 * par extractDecryptedData() -- parseModule ne touche pas à la mémoire chiffrée.
 */
function parseModule(appDir: string, module: Module): ModuleMetaData | null {
    if (!module) {
        throw new Error(`Module introuvable dans le process`);
    }

    const baseAddress = module.base;

    const nlcmds = readTheNumberOfLoadCommand(module);
    const loadCommands = readLoadCommands(baseAddress, nlcmds);
    const lcEncInfo = extractLcEncryptionInfo(loadCommands);

    const moduleMeta: ModuleMetaData = {
        moduleBase: module.base,
        // Compare les adresses de base pour identifier le module principal
        isMainModule: module.base === Process.mainModule.base,
        moduleName: module.name,
        modulePath: module.path,
        moduleParentPath: dirname(module.path),
        moduleAppDir: module.path.startsWith(appDir) ? module.path.slice(appDir.length) : module.name,
        moduleSize: module.size,
        moduleArch: Process.arch,
        modulePlatform: Process.platform,
        nlcmds: nlcmds,
        LoadCommands: loadCommands,
        LcEncryptionInfo: lcEncInfo,
        // cryptid > 0 → chiffré par FairPlay (1=app, 2=ML model -- cf. xnu/bsd/sys/mman.h)
        isEncrypted: (lcEncInfo?.cryptid ?? 0) > 0,
        // Sera rempli plus tard par extractDecryptedData() si le module est chiffré
        DecryptedSectionMeta: null,
    };

    return moduleMeta;
}

/**
 * Cache des objets Module Frida (légers -- juste name/path/base/size, pas de données binaires).
 * Rempli par prepareTheExtraction(), consommé par dumpModule(index).
 * On sépare le listing (pas de copie mémoire) du dump (readByteArray coûteux)
 * pour éviter de doubler la consommation mémoire sur le device.
 */
const inMemoryModules: Array<Module> = [];

/**
 * Points d'entrée RPC exposés au host Python via Frida.
 *
 * Le host Python appelle ces fonctions via session.create_script() + script.exports_sync,
 * et reçoit les valeurs de retour sérialisées en JSON (sauf les ArrayBuffer,
 * transmis en binaire via le protocole Frida).
 *
 * Workflow côté host :
 *   1. n = script.exports_sync.prepare_the_extraction()  → nombre de modules trouvés
 *   2. for i in range(n): script.exports_sync.dump_modules(i)  → [metadata, ArrayBuffer]
 *   3. Pour chaque module, le host écrit les octets déchiffrés par-dessus la zone
 *      chiffrée dans le fichier IPA sur disque → binaire décrypté
 *
 * Avantage de cette approche en 2 temps :
 *   - prepareTheExtraction() ne copie aucune donnée binaire, juste les refs Module Frida
 *   - dumpModules(i) ne copie que les octets du module demandé → pic mémoire = 1 module à la fois
 */
rpc.exports = {
    /** Retourne le chemin filesystem du binaire principal sur l'appareil. */
    getModulePath(): string {
        const mainModule = Process.mainModule;
        if (!mainModule) {
            throw new Error("Process.mainModule is null -- the process may not be fully loaded yet");
        }
        return mainModule.path;
    },

    /**
     * Phase 1 : découverte des modules à dumper (pas de copie mémoire).
     *
     * Énumère les modules chargés dans le process, filtre ceux qui appartiennent
     * au .app bundle (même répertoire parent que le mainModule), et les stocke
     * dans inMemoryModules[]. Le mainModule est toujours à l'index 0.
     *
     * @returns le nombre de modules trouvés -- le host itérera de 0 à n-1 via dumpModules(i)
     */
    prepareTheExtraction(): number {
        inMemoryModules.length = 0;
        const mainModule = Process.mainModule;
        if (!mainModule) {
            throw new Error("Process.mainModule is null -- the process may not be fully loaded yet");
        }

        // On filtre les modules chargés pour ne garder que ceux dont le path
        // est sous le répertoire du mainModule (= le .app bundle).
        // startsWith couvre les sous-dossiers (ex: Frameworks/Foo.framework/Foo)
        // tout en excluant les dylibs système (/usr/lib/, /System/, etc.)
        const appDir = dirname(mainModule.path) + "/";
        const modules = Process.enumerateModules().filter((module) => {
            return module.path.startsWith(appDir) && module.name !== mainModule.name;
        });

        // mainModule en premier (index 0) → le host sait que c'est toujours le binaire principal
        inMemoryModules.push(mainModule, ...modules);

        return inMemoryModules.length;
    },
    /**
     * Phase 2 : dump d'un module par son index.
     *
     * Parse le header Mach-O du module, et si celui-ci est chiffré par FairPlay,
     * lit les octets déchiffrés depuis la mémoire du process (readByteArray).
     * C'est ici que la copie mémoire a lieu -- un seul module à la fois pour
     * limiter le pic mémoire sur le device.
     *
     * @param index -- position dans inMemoryModules (0 = mainModule)
     * @returns [métadonnées, octets_déchiffrés] ou null si le module n'a pas pu être parsé
     */
    dumpModules(index: number): [ModuleMetaData, ArrayBuffer] | null {
        if (inMemoryModules.length === 0) {
            throw new Error("prepareTheExtraction() must be called before dumpModules()");
        }
        if (index < 0 || index >= inMemoryModules.length) {
            throw new Error(`index ${index} out of bounds (${inMemoryModules.length} modules available)`);
        }

        try {
            const mainModule = Process.mainModule;

            const appDir = dirname(mainModule.path) + "/";
            const module = inMemoryModules[index];

            const parsedModuleMetadata = parseModule(appDir, module);

            if (parsedModuleMetadata) {
                const decryptedData = extractDecryptedData(parsedModuleMetadata);
                if (decryptedData) {
                    const [meta, data] = decryptedData;

                    // On attache les métadonnées de la zone déchiffrée au module
                    // pour que le host sache à quel offset écrire dans le fichier
                    parsedModuleMetadata.DecryptedSectionMeta = meta;
                    return [parsedModuleMetadata, data];
                } else {
                    // Module parsé mais pas chiffré → on le retourne quand même
                    // avec un buffer vide pour que le host ait la liste complète
                    return [parsedModuleMetadata, nullData];
                }
            }
            return null;
        } catch (err) {
            console.log(`[-] ${getErrorMessage(err)}`);
            return null;
        }
    },
};
