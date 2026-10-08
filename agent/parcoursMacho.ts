import { getErrorMessage } from "./helpers";
import { MachOHeader, MH_MAGIC, MH_MAGIC_64 } from "./macho";

/**
 * Parcourt une liste de ranges mémoire exécutables à la recherche d'un header Mach-O
 * (reconnu via son magic number en tout début de range).
 * @deprecated Frida give us all the toolings thanks to Process
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

/**
 * Find a module by its name
 * @deprecated Frida give us all the toolings thanks to Process
 * @param moduleName 
 * @returns 
 */
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
