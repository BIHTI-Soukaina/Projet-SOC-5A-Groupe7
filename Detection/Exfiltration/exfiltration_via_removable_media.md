
# Description

Cette règle sera levée lors de toute tentative d'accès à un objet, qu'il s'agisse d'un accès en écriture ou en lecture, effectuée par des processus spécifiques tels que `explorer.exe`, `cmd.exe`, `powershell.exe` ou `robocopy.exe`.

# Criticité : **LOW**

# Outils

WinEventLog

# Règle SPL

```
index="connectix" EventCode=4663 eventtype=wineventlog_windows name="An attempt was made to access an object" 
(Process_Name="C:\Windows\explorer.exe" 
OR Process_Name="C:\Windows\System32\cmd.exe" 
OR Process_Name="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
OR Process_Name="C:\Windows\System32\robocopy.exe") 
(Accesses="WriteData (or AddFile)" 
OR Accesses="ReadData (or ListDirectory)") 
| table _time, host, ComputerName, EventCode, Account_Name, ObjectName, Accesses, Process_Name
```

# Règle SIGMA

```
title: Détection de tentative d'accès à un objet par des processus spécifiques
id: b9d5c2e8-cd91-4bff-85d6-cfae1b063f8a
status: experimental
description: Cette règle détecte les tentatives d'accès à un objet (écriture ou lecture) par des processus spécifiques, tels que explorer.exe, cmd.exe, powershell.exe ou robocopy.exe.
author: Soukaina BIHTI.
date: 2024-11-09
tags:
    - attack.T1052.001
    - attack.T1052
logsource:
    product: windows
    category: wineventlog
detection:
    selection:
        Process_Name:
            - "C:\Windows\explorer.exe"
            - "C:\Windows\System32\cmd.exe"
            - "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            - "C:\Windows\System32\robocopy.exe"
        Accesses:
            - "WriteData (or AddFile)"
            - "ReadData (or ListDirectory)"
    condition: selection
falsepositives:
    - Utilisation légitime de ces outils pour l'administration du système ou la gestion de fichiers.
level: low
```

# Explication

Cette règle permet de détecter les tentatives d'accès à des objets systèmes (en lecture ou en écriture) effectuées par des processus associés à l'explorateur de fichiers (`explorer.exe`), à la ligne de commande (`cmd.exe`), à PowerShell (`powershell.exe`) ou à l'outil de copie de fichiers (`robocopy.exe`). L'objectif est de repérer des comportements suspects impliquant ces processus dans l'accès à des objets sensibles ou des fichiers critiques.
