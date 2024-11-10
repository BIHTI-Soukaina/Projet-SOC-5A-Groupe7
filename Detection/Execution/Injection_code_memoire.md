# Description

Cette règle détecte l'injection de code en mémoire sur les appareils **Windows** via des techniques telles que **Cobalt Strike**, **Beacon**, **Reflective DLL Injection**, **Process Hollowing**, et **PowerShell Load Library (PLL)**, utilisées pour maintenir la persistance et exécuter du code malveillant de manière furtive.

# Criticité : **HIGH**

# Outils

Sysmon

# Règle SPL

```
index="connectix" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*Cobalt Strike*" OR CommandLine="*Beacon*" OR CommandLine="*ReflectiveDLLInjection*" OR CommandLine="*Process Hollowing*" OR CommandLine="*PLL*" OR CommandLine="*PowerShell Load Library*"
| table ComputerName, User, CommandLine, _time, Image
```

# Règle SIGMA

```
title: Injection en mémoire via Cobalt Strike, Beacon, Reflective DLL Injection, Process Hollowing et PowerShell Load Library
id: 6b96f4d2-10da-41c1-b6a2-4d10f59b4bb0
status: experimental
description: Cette règle détecte l'injection de code en mémoire via **Cobalt Strike**, **Beacon**, **Reflective DLL Injection**, **Process Hollowing**, et **PowerShell Load Library (PLL)**, utilisées pour maintenir la persistance et exécuter du code malveillant de manière furtive.
author: Thomas B.
date: 2024-11-10
tags:
    - attack.t1071
logsource:
    product: windows
    category: sysmon
detection:
    selection:
        CommandLine|contains: "Cobalt Strike"
        or CommandLine|contains: "Beacon"
        or CommandLine|contains: "ReflectiveDLLInjection"
        or CommandLine|contains: "Process Hollowing"
        or CommandLine|contains: "PLL"
        or CommandLine|contains: "PowerShell Load Library"
    condition: selection
falsepositives:
    - Utilisation légitime de ces outils dans des environnements de test ou des scripts PowerShell administratifs
level: high
```

# Explication

Cette règle surveille l'exécution de techniques avancées d'injection en mémoire utilisées pour maintenir un accès persistant et furtif sur un système. Ces techniques, telles que **Cobalt Strike**, **Beacon**, **Reflective DLL Injection**, **Process Hollowing**, et **PowerShell Load Library (PLL)**, permettent aux attaquants d'injecter du code malveillant directement dans la mémoire des processus légitimes, contournant ainsi les solutions de sécurité basées sur des fichiers et réduisant la probabilité de détection. Cette règle se concentre sur l'analyse des lignes de commande associées à ces techniques pour identifier les comportements suspects.