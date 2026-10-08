/** Extrait le message d'une erreur quelconque (Error, string, ou autre). */
export function getErrorMessage(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
}

/**
 * extrait le nom du répertoire parent d'un path
 * @param path
 * @returns
 */
export function dirname(path: string): string {
    return path.substring(0, path.lastIndexOf("/"));
}

/**
 *
 * @returns Void ArrayBuffer
 */
export const nullData: ArrayBuffer = new ArrayBuffer(0);
