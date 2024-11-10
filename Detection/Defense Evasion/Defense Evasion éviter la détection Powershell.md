# Description

Cette règle permet de détecter des événements PowerShell potentiellement malveillants en recherchant des techniques d'obfuscation et de contournement de sécurité dans les commandes PowerShell. Elle se concentre sur l'exécution de commandes PowerShell suspectes et sur l'utilisation d'outils ou de paramètres courants pour masquer les intentions ou échapper à la détection. La requête cherche spécifiquement les termes associés à des techniques d'évasion et d'obfuscation dans les commandes PowerShell exécutées.

# Criticité : **High**

# Outils  
Sysmon, Windows Event Log, PowerShell

# Règle SPL
```spl
index=connectix source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
(EventCode=4104 OR EventCode=4103)
| search "Invoke-Obfuscation" OR "Bypass" OR "NoProfile" OR "EncodedCommand" OR "-nop"
```
# Règle SIGMA

```
title: Détection des techniques d'obfuscation et de contournement dans PowerShell
id: e1f8c345-6f4d-4729-bca9-b4e06f9c8e3e
status: experimental
description: Cette règle détecte l'exécution de commandes PowerShell contenant des termes associés à des techniques d'obfuscation et de contournement de sécurité, utilisées par des attaquants pour masquer leurs intentions ou contourner les mesures de sécurité.
author: Awa Dieye
date: 2024-11-09
tags:
    - attack.t1059.001
logsource:
    product: windows
    category: powershell
detection:
    selection:
        EventCode:
            - 4104
            - 4103
        CommandLine|contains:
            - "Invoke-Obfuscation"
            - "Bypass"
            - "NoProfile"
            - "EncodedCommand"
            - "-nop"
    condition: selection
falsepositives:
    - Exécution légitime de commandes PowerShell par des administrateurs système
level: high
```

# Explication
Cette règle est utilisée pour détecter l'exécution de commandes PowerShell suspectes qui contiennent des termes fréquemment associés à des techniques de contournement et d'obfuscation. Ces techniques sont couramment utilisées par des attaquants pour exécuter des scripts malveillants tout en échappant à la détection des systèmes de sécurité. Voici ce que chaque terme signifie :

"Invoke-Obfuscation" : Un outil PowerShell utilisé pour obfusquer des scripts afin de les rendre difficiles à analyser.
"Bypass" : Utilisé pour contourner les restrictions de sécurité, comme les restrictions d'exécution de scripts PowerShell.
"NoProfile" : Un paramètre qui permet d'exécuter des scripts sans charger les profils utilisateur, souvent utilisé pour éviter les configurations de sécurité.
"EncodedCommand" : Un paramètre qui permet d'exécuter des scripts PowerShell encodés en base64, permettant de masquer leur contenu réel.
"-nop" : Paramètre qui empêche l'exécution des profils PowerShell, souvent utilisé pour éviter l'application de configurations de sécurité.
