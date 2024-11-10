# Description

Cette règle sera levée en cas de modification suspecte des clés de registre utilisées pour l'exécution automatique des programmes au démarrage du système. 

# Criticité : **HIGH**

# Outils

Sysmon

# Règle SPL

```
index="connectix" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*reg*" AND CommandLine="* ADD *" AND CommandLine="*Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
| table ComputerName, User, CommandLine, _time, Image
```

# Règle SIGMA

```
title: Détection de la modification des clés de registre de démarrage via reg.exe
id: a9b5ef4b-32d1-4876-9f3e-96f6be1a9db1
status: experimental
description: Cette règle détecte l'utilisation de `reg.exe` pour ajouter une clé dans la section "Run" du registre, ce qui est souvent utilisé pour établir une persistance sur un système.
author: Yasmine BRAHITI
date: 2024-11-10
tags:
    - attack.t1547.001
logsource:
    product: windows
    category: sysmon
detection:
    selection:
        CommandLine|contains: "reg" and CommandLine|contains: "ADD" and CommandLine|contains: "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition: selection
falsepositives:
    - Modification légitime des clés de démarrage par des administrateurs
level: high
```

# Explication

Cette règle surveille l'utilisation de l'outil `reg.exe` pour ajouter des clés de registre dans l'emplacement `Software\Microsoft\Windows\CurrentVersion\Run`, une technique utilisée par les attaquants pour maintenir leur persistance sur un système en ajoutant des programmes au démarrage de Windows. Ce type de modification du registre est fréquemment utilisé dans les attaques pour garantir qu'un programme malveillant soit lancé à chaque démarrage du système. La règle détecte toute tentative d'ajouter de nouvelles entrées dans cette section de registre, ce qui permet d'identifier les activités suspectes liées à la persistance malveillante.
