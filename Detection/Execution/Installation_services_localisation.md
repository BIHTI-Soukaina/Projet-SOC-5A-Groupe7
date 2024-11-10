# Description

Cette règle détecte l'installation de services en dehors des répertoires standards de Windows (tels que `System32`, `Program Files`, et `Windows Update`), ce qui peut indiquer une tentative d'installation de services malveillants ou non autorisés.

# Criticité : **MEDIUM**

# Outils

WinEventLog

# Règle SPL

```
index="connectix" source="WinEventLog:System" EventCode=4697
| eval is_not_system32 = if(NOT (Service_File_Name LIKE "C:\\Windows\\system32\\*" OR Service_File_Name LIKE "\\SystemRoot\\system32\\*"), 1, 0)
| eval is_not_program_files = if(NOT (Service_File_Name LIKE "C:\\Program Files\\*" OR Service_File_Name LIKE "\\SystemRoot\\Program Files\\*"), 1, 0)
| eval is_not_program_files_x86 = if(NOT (Service_File_Name LIKE "C:\\Program Files (x86)\\*" OR Service_File_Name LIKE "\\SystemRoot\\Program Files (x86)\\*"), 1, 0)
| eval is_not_windows_update = if(NOT (Service_File_Name LIKE "*\\Windows Defender\\Definition Updates\\*" OR Service_File_Name LIKE "C:\\Windows\\SoftwareDistribution\\*" OR Service_File_Name LIKE "C:\\Windows\\System32\\catroot2\\*"), 1, 0)
| where is_not_system32=1 AND is_not_program_files=1 AND is_not_program_files_x86=1 AND is_not_windows_update=1
| table ComputerName, Service_Name, Service_File_Name, User, _time
```

# Règle SIGMA

```
title: Détection de l'installation de services en dehors des répertoires standards
id: 9177e299-e18a-4c42-b6b5-c3ed2f57f829
status: experimental
description: Cette règle détecte l'installation de services en dehors des répertoires standards de Windows, ce qui peut indiquer une tentative d'installation de logiciels malveillants.
author: Thomas B.
date: 2024-11-10
tags:
    - attack.t1543.003
logsource:
    product: windows
    category: system
detection:
    selection:
        EventCode: 4697
    eval_action:
        not_standard:
            case(NOT(Service_File_Name LIKE "C:\\Windows\\System32\\*" OR Service_File_Name LIKE "C:\\Program Files\\*"), 1, 0)
    condition: selection
falsepositives:
    - Installation de logiciels légitimes dans des répertoires non standards
level: high
```

# Explication

Cette règle surveille l'installation de services qui ne se trouvent pas dans les répertoires standards de Windows, comme `System32`, `Program Files`, et `Windows Update`. Une installation de services en dehors de ces répertoires peut être une tentative d'obfuscation utilisée par les attaquants pour masquer des programmes malveillants ou pour éviter la détection par des solutions de sécurité.

Les répertoires tels que `System32` et `Program Files` sont des emplacements standards pour les services Windows légitimes. L'ajout de services dans des répertoires non standards peut être un indicateur de comportement malveillant. Cette règle permet d'identifier ces tentatives en analysant les événements Sysmon liés à l'installation de services.

