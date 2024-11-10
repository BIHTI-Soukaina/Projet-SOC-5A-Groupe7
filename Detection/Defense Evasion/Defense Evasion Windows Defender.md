# Description

Cette règle sera levée en cas de désactivation de la protection en temps réel de Windows Defender, de l'ajout d'exclusions, ou de la modification des paramètres de surveillance de Defender.

# Criticité : **HIGH**

# Outils
Sysmon, Windows Event Log

# Règle SPL
```

index="connectix" 
(
    (sourcetype="WinEventLog" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational") 
    EventCode=4688 
    (
        "Set-MpPreference -DisableRealtimeMonitoring $true" 
        OR "Set-MpPreference -DisableBehaviourMonitoring $true"
        OR "Set-MpPreference -DisableBlockAtFirstSeen $true"
        OR "Add-MpPreference -ExclusionPath"
        OR "Get-MpComputerStatus"  
        OR "Add-MpPreference -ExclusionExtension" 
        OR "Add-MpPreference -ExclusionProcess"
    )
) 
OR 
(
    sourcetype="WinEventLog:Microsoft-Windows-Powershell/Operational" 
    (
        "Set-MpPreference -DisableRealtimeMonitoring $true" 
        OR "Set-MpPreference -DisableBehaviourMonitoring $true"
        OR "Set-MpPreference -DisableBlockAtFirstSeen $true"
        OR "Add-MpPreference -ExclusionPath"
        OR "Get-MpComputerStatus"  
        OR "Add-MpPreference -ExclusionExtension" 
        OR "Add-MpPreference -ExclusionProcess"
    )
)

# Règle SIGMA

```
title: Détection de la désactivation ou de la modification des paramètres de protection de Windows Defender
id: b76c4e1a-7a58-4b9f-8ae6-df4713c27d56
status: experimental
description: Cette règle détecte la désactivation de la surveillance en temps réel, des exclusions de fichiers, dossiers ou extensions dans Windows Defender, ce qui pourrait indiquer une tentative de contourner la sécurité.
author: Awa Dieye
date: 2024-11-09
tags:
    - attack.t1562.001
logsource:
    product: windows
    category: powershell
detection:
    selection:
        EventID: 4688
        CommandLine|contains:
            - "Set-MpPreference -DisableRealtimeMonitoring $true"
            - "Set-MpPreference -DisableBehaviourMonitoring $true"
            - "Set-MpPreference -DisableBlockAtFirstSeen $true"
            - "Add-MpPreference -ExclusionPath"
            - "Get-MpComputerStatus"
            - "Add-MpPreference -ExclusionExtension"
            - "Add-MpPreference -ExclusionProcess"
    condition: selection
falsepositives:
    - Modification légitime des paramètres de Windows Defender par un administrateur
level: high
```

# Explication
Cette règle permet de détecter des modifications dans les paramètres de Windows Defender, notamment :

La désactivation de la surveillance en temps réel (Set-MpPreference -DisableRealtimeMonitoring),
La désactivation de la surveillance comportementale (Set-MpPreference -DisableBehaviourMonitoring),
La désactivation du blocage à première vue (Set-MpPreference -DisableBlockAtFirstSeen),
L'ajout d'exclusions de chemins, d'extensions de fichiers ou de processus dans Windows Defender.
Ces actions peuvent être effectuées pour contourner la protection offerte par Defender et permettre à des programmes malveillants d'exécuter des actions sans être détectés. Cette règle est particulièrement utile pour détecter les activités malveillantes tentant de désactiver ou de réduire la sécurité du système.

