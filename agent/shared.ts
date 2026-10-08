/**
 *
 */
export interface ModuleDumpMetadata {
    moduleBase: NativePointer;
    moduleName: string;
    modulePath: string;
    moduleSize: number;
    address: NativePointer;
    cryptoff: number;
    cryptsize: number;
    cryptid: number;
}
