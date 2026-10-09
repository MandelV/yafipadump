# Injection de gadget Frida dans un Mach-O

Comment insérer une load command custom (ex: `LC_LOAD_DYLIB` pour charger
le gadget Frida) dans un binaire Mach-O existant.

## Layout du header Mach-O

```
┌────────────────────────────────────────────────────────┐
│  mach_header_64 (32 octets / 0x20)                     │ ◄── Début du fichier (offset 0x00)
├────────────────────────────────────────────────────────┤
│  Load Command n°1 (LC_SEGMENT_64 __PAGEZERO)           │ ◄── Offset 0x20
│  Load Command n°2 (LC_SEGMENT_64 __TEXT)               │
│  ...                                                   │ ─── Zone mesurée exactement
│  Load Command n°N (la toute dernière existante)        │     par le champ "sizeofcmds"
├────────────────────────────────────────────────────────┤
│  ◄── POINT D'INSERTION (0x20 + sizeofcmds)             │
│                                                        │
│  ZONE DE ZÉROS (padding disponible)                    │ ─── C'est ici qu'on écrit notre LC custom
│                                                        │
├────────────────────────────────────────────────────────┤
│  DÉBUT DU CODE / DONNÉES DU SEGMENT __TEXT             │ ◄── Limite absolue = fileoff de __TEXT
│  (ex: à l'offset 0x4000)                               │     (aligné sur une page mémoire)
└────────────────────────────────────────────────────────┘
```

### Pourquoi cette zone de zéros existe

Le système impose que le segment `__TEXT` (le code exécutable) commence au début
d'une page mémoire. C'est une contrainte matérielle : dans les tables de pages du
processeur, chaque entrée porte l'adresse physique + des flags de permissions
(lecture, écriture, exécution -- ex: bit NX en position 63 sur x86_64).

Placer `__TEXT` sur une frontière de page permet au kernel d'appliquer les permissions
`r-x` (lecture + exécution, pas d'écriture) sur exactement les pages qui contiennent
du code, sans affecter les données du header.

Résultat : entre la fin des load commands et le début de `__TEXT`, il y a une zone
de padding remplie de `0x00` -- souvent plusieurs kilo-octets. C'est dans cet espace
qu'on peut insérer nos load commands custom.

## Structure du header

```c
// xnu/EXTERNAL_HEADERS/mach-o/loader.h

struct mach_header_64 {
    uint32_t      magic;       // 0x00 -- 0xFEEDFACF pour 64-bit
    cpu_type_t    cputype;     // 0x04 -- ex: CPU_TYPE_ARM64
    cpu_subtype_t cpusubtype;  // 0x08 -- ex: CPU_SUBTYPE_ARM64_ALL
    uint32_t      filetype;    // 0x0C -- MH_EXECUTE, MH_DYLIB, ...
    uint32_t      ncmds;       // 0x10 -- nombre de load commands
    uint32_t      sizeofcmds;  // 0x14 -- taille totale de toutes les LC (en octets)
    uint32_t      flags;       // 0x18 -- PIE, TWOLEVEL, ...
    uint32_t      reserved;    // 0x1C -- padding 64-bit (absent en 32-bit !)
};
// sizeof(mach_header_64) = 0x20 (32 octets)
// sizeof(mach_header)    = 0x1C (28 octets, pas de reserved)
```

Les deux champs importants pour nous :

- **`ncmds`** : combien de load commands sont déclarées
- **`sizeofcmds`** : la taille totale en octets de toutes ces commandes bout à bout

## Parcourir les load commands

Chaque load command commence par deux `uint32_t` :

```c
struct load_command {
    uint32_t cmd;      // type de commande (ex: LC_SEGMENT_64 = 0x19)
    uint32_t cmdsize;  // taille TOTALE de cette commande (header inclus)
};
```

`cmdsize` donne la taille de la commande entière (pas juste le header de 8 octets,
mais aussi les données spécifiques à chaque type de LC). Pour passer à la commande
suivante, on avance le curseur de `cmdsize` octets.

### Algorithme de parcours

```
curseur = baseAddress + 0x20               # juste après le mach_header_64

for i in range(ncmds):
    cmd     = curseur.readU32()            # +0x00 : type de la commande
    cmdsize = (curseur + 0x04).readU32()   # +0x04 : taille totale

    # ... traiter la commande ...

    curseur += cmdsize                     # saute à la commande suivante

# À la sortie : curseur pointe sur le premier octet APRÈS la dernière LC.
```

**Attention** : `cmdsize == 0` signifie une table corrompue (le curseur n'avancerait
plus → boucle infinie). Il faut vérifier ça à chaque itération.

### Implémentation dans l'agent yafipadump

```ts
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
```

## Trouver le point d'insertion exact

L'objectif : trouver la fin exacte des load commands pour savoir où commence
la zone de padding (= où on peut écrire notre LC custom).

Deux façons d'y arriver :

### Méthode 1 : calcul direct depuis le header

```
point_insertion = baseAddress + 0x20 + sizeofcmds
```

Simple, mais on fait confiance aveuglément au header sans valider la table.

### Méthode 2 : parcourir jusqu'à la dernière load command

On parcourt toutes les load commands une par une (comme `readLoadCommands` ci-dessus).
À la sortie de la boucle, le curseur a avancé de `cmdSize` pour chaque commande --
il pointe sur le premier octet APRÈS la dernière commande :

```
curseur = baseAddress + 0x20

for i in range(ncmds):
    cmdType = curseur.readU32()
    cmdSize = (curseur + 0x04).readU32()
    curseur += cmdSize

# Ici le curseur est sur le premier octet après la dernière LC.
# Normalement c'est exactement baseAddress + 0x20 + sizeofcmds.
# À partir de là → zone de zéros (padding d'alignement page).
```

L'avantage : on valide la table au passage (cmdSize == 0 → corruption,
lecture impossible → mémoire corrompue). Et on peut vérifier la cohérence :

```
assert curseur == baseAddress + 0x20 + sizeofcmds
```

Si ça ne matche pas → la table des load commands est incohérente avec le header.

### Visualisation du point d'insertion

```
┌─────────────────────────────────────────┐
│  ...                                    │
│  Dernière Load Command (n°N)            │
│    ├── cmd     (uint32)  ◄── curseur    │
│    ├── cmdsize (uint32)                 │
│    └── ... (données spécifiques à la LC)│
│         dernier octet de la LC ──►      │
├─────────────────────────────────────────┤ ◄── curseur final = baseAddress + 0x20 + sizeofcmds
│                                         │
│  ZONE DE ZÉROS (padding)                │     Vérifier que c'est bien des 0x00
│  Taille = fileoff(__TEXT) - curseur      │     avant d'écrire dedans.
│                                         │
├─────────────────────────────────────────┤ ◄── fileoff de __TEXT (aligné sur page)
│  Code du segment __TEXT                 │
└─────────────────────────────────────────┘
```

### Écrire notre load command custom

L'espace disponible = `fileoff(__TEXT) - (0x20 + sizeofcmds)`.

Si notre LC custom (ex: `LC_LOAD_DYLIB` pour le gadget Frida) tient dedans :

1. Écrire la LC au point d'insertion (`0x20 + sizeofcmds`)
2. Incrémenter `ncmds` de 1 dans le `mach_header_64`
3. Ajouter la taille de notre LC à `sizeofcmds` dans le `mach_header_64`

Si l'espace ne suffit pas → il faudrait déplacer des segments ou utiliser une
technique d'expansion du header, ce qui est nettement plus complexe.
