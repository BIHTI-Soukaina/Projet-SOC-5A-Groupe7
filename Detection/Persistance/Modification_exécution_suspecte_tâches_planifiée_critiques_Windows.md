# Description

Cette règle détecte la modification ou l'exécution suspecte de tâches planifiées critiques de Windows, telles que celles liées à Windows Defender, BitLocker, et Windows Update, pour repérer d'éventuelles tentatives d'altération des processus de sécurité du système.

# Criticité : **HIGH**

# Outils

WinEventLog:system

# Règle SPL

```
index="connectix" source="wineventlog:system" EventCode IN (4699, 4701)
| search Task_Name LIKE "*\\Windows\\SystemRestore\\SR*" OR Task_Name LIKE "*\\Windows\\Windows Defender\\*" OR Task_Name LIKE "*\\Windows\\BitLocker*" OR Task_Name LIKE "*\\Windows\\WindowsUpdate\\*" OR Task_Name LIKE "*\\Windows\\ExploitGuard*"
| where NOT (EventCode=4699 AND Account_Name LIKE "*$" AND Task_Name LIKE "*\\Windows\\Windows Defender\\*")
| stats count by ComputerName, TaskName, Account_Name, EventCode, _time
```

# Règle SIGMA

```
title: Détection de la modification ou exécution suspecte de tâches planifiées critiques de Windows
id: f5b40d1c-ff92-4b89-8c6d-9ab02d9a5f93
status: experimental
description: Cette règle détecte les modifications ou l'exécution de tâches planifiées critiques de Windows, comme celles liées à Windows Defender, BitLocker ou Windows Update.
author: Yasmine BRAHITI
date: 2024-11-10
tags:
    - attack.t1053.003
logsource:
    product: windows
    category: system
detection:
    selection:
        EventCode: [4699, 4701]
        Task_Name|contains:
            - "Windows\\SystemRestore\\SR"
            - "Windows\\Windows Defender\\"
            - "Windows\\BitLocker"
            - "Windows\\WindowsUpdate"
            - "Windows\\ExploitGuard"
    condition: selection
falsepositives:
    - Modifications légitimes effectuées par les administrateurs système
level: high
```

# Explication

Cette règle surveille les modifications ou l'exécution des tâches planifiées critiques de Windows, telles que celles associées à la restauration du système, à la protection par Windows Defender, à BitLocker et à Windows Update. Toute modification de ces tâches peut indiquer une tentative de manipulation des processus de sécurité du système. Les attaquants peuvent tenter de désactiver, de manipuler ou de contourner ces tâches pour maintenir leur accès à un système ou pour exécuter des actions malveillantes sans être détectés. La règle exclut toutefois les actions légitimes exécutées par des comptes d'administrateurs système, en particulier celles liées à Windows Defender.
