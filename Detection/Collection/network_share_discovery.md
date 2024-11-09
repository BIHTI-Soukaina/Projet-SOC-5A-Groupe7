
# Description

Cette règle détecte les accès à des répertoires partagés en lecture par des utilisateurs non-systèmes, provenant d'adresses IP externes au réseau interne spécifié (excluant ici la plage 192.168.10.0/24). Les événements surveillés incluent les codes d’événement Windows correspondant aux accès aux répertoires partagés.

# Criticité : **LOW**

# Outils

WinEventLog

# Règle SPL

```
index="connectix"
(sourcetype="WinEventLog"
 OR sourcetype="suricata"
 OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
 OR sourcetype="WinEventLog:Microsoft-Windows-Powershell/Operational")
 EventCode=5140 OR EventCode=5142 OR EventCode=5143 OR EventCode=5144
| where Accesses="ReadData (or ListDirectory)"
| where NOT cidrmatch("192.168.10.0/24", src_ip)
| where user!="SYSTEM" AND user!="LOCAL SERVICE" AND user!="NETWORK SERVICE"
| table _time src_ip src_port user Share_Name Accesses
| sort -_time
```

# Règle SIGMA

```
title: Détection des accès non-systèmes aux répertoires partagés depuis des IP externes
id: c8f6d3a4-f2de-42f7-9539-a2b0bc6a1f23
status: experimental
description: Cette règle détecte des accès à des répertoires partagés par des utilisateurs autres que les comptes systèmes standards, provenant d'adresses IP externes au réseau défini.
author: Soukaina BIHTI.
date: 2024-11-09
tags:
    - attack.T1039 
logsource:
    product: windows
    category: file_access
detection:
    selection:
        EventCode:
            - 5140
            - 5142
            - 5143
            - 5144
        Accesses: "ReadData (or ListDirectory)"
    filter:
        src_ip|cidr: "!192.168.10.0/24"
        user|contains: 
            - "!SYSTEM"
            - "!LOCAL SERVICE"
            - "!NETWORK SERVICE"
    condition: selection and filter
falsepositives:
    - Accès réseau légitime pour des opérations de maintenance ou de sauvegarde.
level: low
```

# Explication

Cette règle permet d’identifier des accès potentiellement suspects à des répertoires partagés en lecture, réalisés par des utilisateurs non-systèmes depuis des adresses IP externes au réseau interne spécifié (plage exclue : 192.168.10.0/24). Elle surveille des événements spécifiques (codes 5140, 5142, 5143, 5144) pour capturer ce type d'activité, afin de déceler des comportements d'accès inhabituels ou non autorisés sur les répertoires partagés.
