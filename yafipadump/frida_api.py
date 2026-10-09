"""Wrapper typé autour de l'API RPC Frida.

Frida expose les exports JS du script agent via script.exports_sync.
Les noms de méthodes JS (camelCase) sont automatiquement convertis
en snake_case côté Python par Frida :
    JS: getModulePath()        → Python: get_module_path()
    JS: prepareTheExtraction() → Python: prepare_the_extraction()
    JS: dumpModules(i)         → Python: dump_modules(i)

Ce wrapper ajoute le typage Python (TypedDict + bytes) par-dessus
ces appels pour éviter les dict["magic_key"] partout dans le code.
"""
import frida

from .shared_types import ModuleMetaDataDict


class FridaAgentAPI:
    """API typée vers l'agent JS injecté dans le process iOS.

    Workflow en 2 phases (pour limiter le pic mémoire sur le device) :
        api = FridaAgentAPI(script)
        path = api.get_module_path()          # chemin du mainModule
        n = api.prepare_the_extraction()      # phase 1 : discovery (léger)
        for i in range(n):
            meta, data = api.dump_module(i)   # phase 2 : dump un par un (copie mémoire)
    """

    def __init__(self, script: frida.Script):
        self._exports = script.exports_sync

    def get_module_path(self) -> str:
        """Retourne le chemin filesystem du binaire principal sur le device.

        Correspond à Process.mainModule.path côté JS.
        Ex: "/var/containers/Bundle/Application/.../MyApp.app/MyApp"
        """
        return self._exports.get_module_path()

    def prepare_the_extraction(self) -> int:
        """Phase 1 : découvre les modules du .app bundle (pas de copie mémoire).

        Énumère les modules chargés par dyld et filtre ceux dont le répertoire
        parent correspond au mainModule (= le .app bundle). Le mainModule est
        toujours à l'index 0.

        Returns:
            Nombre de modules trouvés — le caller itérera de 0 à n-1 via dump_module(i).
        """
        return self._exports.prepare_the_extraction()

    def dump_module(self, index: int) -> tuple[ModuleMetaDataDict, bytes] | None:
        """Phase 2 : parse le header Mach-O et lit les octets déchiffrés pour un module.

        C'est ici que le readByteArray() a lieu côté device — un seul module
        à la fois pour ne pas exploser la mémoire.

        Frida transmet le tuple JS [Object, ArrayBuffer] en Python comme [dict, bytes].

        Args:
            index: position dans les modules découverts (0 = mainModule)

        Returns:
            (metadata_dict, decrypted_bytes) ou None si le module n'a pas pu être parsé.
        """
        result = self._exports.dump_modules(index)
        if result is None:
            return None
        # Frida retourne une liste [dict, bytes] — on unpack et on type
        meta: ModuleMetaDataDict = result[0]
        data: bytes = result[1]
        return meta, data
