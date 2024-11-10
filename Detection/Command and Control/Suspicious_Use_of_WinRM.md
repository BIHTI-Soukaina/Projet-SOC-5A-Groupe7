
# Suspicious Use of WinRM on Port 5985

## Description
Cette règle détecte l'utilisation suspecte de WinRM sur le port 5985 avec des processus potentiellement malveillants comme PowerShell et svchost, souvent utilisés pour établir des connexions Command and Control (C2).

## Criticité : **HIGH**

## Outils
Sysmon

## Règle SPL

```spl
index=connectix sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| search DestinationPort=5985 (Image="*powershell.exe*" OR Image="*svchost.exe*") Sid="S-1-5-18"
| stats count by Image, DestinationIp, DestinationPort, SourceIp, Sid, ComputerName
| where count > 5
| table Image, DestinationIp, DestinationPort, SourceIp, Sid, ComputerName, count
```

## Règle SIGMA

```yaml
title: Utilisation suspecte de WinRM sur le port 5985
id: f75e95f6-dec4-43ab-b3ba-91471e993c9f
status: experimental
description: Cette règle détecte l'utilisation suspecte de WinRM pour des connexions C2, identifiée par l'exécution de PowerShell ou svchost sur le port 5985.
author: Nurdini BINTI MOHAMAD
date: 2024-11-10
tags:
    - attack.t1021.006
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        DestinationPort: 5985
        Image|contains:
            - "powershell.exe"
            - "svchost.exe"
        Sid: "S-1-5-18"
    condition: selection
falsepositives:
    - Utilisation légitime de WinRM pour des tâches d'administration
level: high
```

## Explication
Cette règle détecte l'utilisation potentiellement malveillante de WinRM pour les connexions C2, en recherchant des processus spécifiques (PowerShell, svchost) exécutés sur le port 5985, souvent utilisés pour des communications de contrôle.
