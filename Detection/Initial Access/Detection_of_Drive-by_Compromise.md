
# Detection of Drive-by Compromise via Suspicious Process Creation

## Description
Cette règle détecte la création de processus suspects qui pourraient indiquer un compromis de type "drive-by". Elle se concentre sur des processus comme PowerShell, WMIC et d'autres outils système qui peuvent être utilisés de manière malveillante pour exécuter des commandes ou scripts à distance.

## Criticité : **HIGH**

## Outils
Sysmon, Security Event Log

## Règle SPL

```spl
index=connectix sourcetype=WinEventLog:Security OR sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational 
| eval CommandLine=coalesce(CommandLine, ParentCommandLine)
| eval CommandLine=lower(CommandLine)
| search OriginalFileName IN ("wmic.exe", "powershell.exe", "wbemtool.exe", "wmiprvse.exe", "wmiadap.exe", "scrcons.exe")
| stats count by OriginalFileName, ComputerName, CommandLine, ParentCommandLine, Hashes 
| table OriginalFileName, ComputerName, CommandLine, ParentCommandLine, Hashes, count
```

## Règle SIGMA

```yaml
title: Détection de création de processus suspects pour Drive-by Compromise
id: c45e95f6-dec4-43ab-b3ba-91471e993c9b
status: experimental
description: Cette règle détecte la création de processus suspects qui pourraient indiquer une tentative de Drive-by Compromise.
author: Nurdini BINTI MOHAMAD
date: 2024-11-10
tags:
    - attack.t1203
logsource:
    product: windows
    category: sysmon
detection:
    selection:
        OriginalFileName:
            - "wmic.exe"
            - "powershell.exe"
            - "wbemtool.exe"
            - "wmiprvse.exe"
            - "wmiadap.exe"
            - "scrcons.exe"
    condition: selection
falsepositives:
    - Utilisation légitime de ces outils dans des scripts d'administration ou de maintenance
level: high
```

## Explication
Cette règle surveille les processus associés à des outils système couramment utilisés dans les attaques drive-by ou de compromis via WMI. Elle permet de repérer des tentatives d'exécution de commandes potentiellement malveillantes en analysant les noms de fichiers, les lignes de commande et les processus parents.
