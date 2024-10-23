# Description

Cette règle sera levée en cas d'ajout ou modification d'un fichier dans des répertoires destinés à exécuter des programmes au démarrage.

# Criticité : **LOW**

# Outils

Sysmon

# Règle SPL

```
index=sysmon source="WinEventLog:Sysmon" 
EventCode=11 
(TargetFilename="*\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" 
OR TargetFilename="*\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
```

# Règle SIGMA

```
title: Détection de l'ajout ou de la modification de fichiers dans des répertoires Windows destinés à exécuter des programmes au démarrage
id: a45e95f6-dec4-43ab-b3ba-91471e993c9a
status: experimental
description: Cette règle détectera l'ajout ou modification d'un fichier dans des répertoires Windows destinés à exécuter des programmes au démarrage.
author: Thomas B.
date: 2024-09-16
tags:
    - attack.t1547.001
logsource:
    product: windows
    category: sysmon
detection:
    selection1:
        TargetFilename|contains: "\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    selection2:
        TargetFilename|contains: "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    condition: selection1 or selection2
falsepositives:
    - Lancement de logiciels légitimes au démarrage mis en place à l'installation d'un programme
level: low
```

# Explication

On vient vérifier si un fichier a été ajouté ou modifié dans des répertoires destinés à exécuter des programmes au démarrage en regardant les chemins des fichiers ajoutés ou modifiés à l'aide des journaux Sysmon.