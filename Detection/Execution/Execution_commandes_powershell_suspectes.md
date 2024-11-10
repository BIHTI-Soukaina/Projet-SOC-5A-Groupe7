# Description

Cette règle sera levée en cas d'exécution de commandes PowerShell suspectes. Elle détecte l'utilisation de techniques courantes utilisées dans des attaques PowerShell, telles que l'exécution de commandes encodées, le contournement des politiques d'exécution, l'utilisation de `Invoke-Mimikatz`, ou l'injection de scripts via des commandes comme `Invoke-Expression` ou `IEX`. Ces techniques sont souvent utilisées pour exécuter du code malveillant à distance.

# Criticité : **HIGH**

# Outils

Sysmon

# Règle SPL

```
index="connectix" source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval suspicious_commands = if(
    CommandLine LIKE "%-enc%" OR 
    CommandLine LIKE "%-exec bypass%" OR 
    CommandLine LIKE "%Invoke-Mimikatz%" OR 
    CommandLine LIKE "%Invoke-Expression%" OR 
    CommandLine LIKE "%IEX%" OR 
    CommandLine LIKE "%New-Object Net.WebClient%" OR 
    CommandLine LIKE "%DownloadString%" OR 
    CommandLine LIKE "%Set-ExecutionPolicy%" OR 
    CommandLine LIKE "%EncodedCommand%" OR 
    CommandLine LIKE "%Add-MpPreference%" OR 
    CommandLine LIKE "%Out-File%" OR 
    CommandLine LIKE "%Out-String%", 1, 0)
| eval legitimate_command = if(CommandLine LIKE "%Get-Process%" OR CommandLine LIKE "%Get-Service%", 1, 0)
| where suspicious_commands=1 AND legitimate_command=0
| table ComputerName, User, CommandLine, _time, alert
```

# Règle SIGMA

```
title: Détection de l'exécution de commandes PowerShell suspectes
id: a3b5ef4b-8b7e-42d5-bb43-62b25b74f1e4
status: experimental
description: Cette règle détecte l'exécution de commandes PowerShell suspectes, telles que l'utilisation de `Invoke-Expression`, l'exécution de commandes encodées ou d'autres techniques malveillantes.
author: Thomas B.
date: 2024-11-10
tags:
    - attack.t1059.001
logsource:
    product: windows
    category: powershell
detection:
    selection:
        CommandLine|contains:
            - "-enc"
            - "-exec bypass"
            - "Invoke-Mimikatz"
            - "Invoke-Expression"
            - "IEX"
            - "New-Object Net.WebClient"
            - "DownloadString"
            - "Set-ExecutionPolicy"
            - "EncodedCommand"
            - "Add-MpPreference"
            - "Out-File"
            - "Out-String"
    condition: selection
falsepositives:
    - Commandes administratives PowerShell légitimes
level: high
```

# Explication

Cette règle détecte l'exécution de commandes PowerShell spécifiques qui sont couramment utilisées dans des attaques pour installer ou modifier des services. Voici ce que chaque condition vérifie :

- **Commandes encodées (`-enc`)** : Les commandes encodées sont utilisées pour masquer leur contenu. Elles sont fréquemment employées dans des attaques pour masquer des comportements malveillants.
- **Bypass de l'exécution (`-exec bypass`)** : Ce paramètre permet de contourner les politiques d'exécution de PowerShell, autorisant ainsi l'exécution de scripts non signés, ce qui est couramment utilisé pour exécuter du code malveillant.
- **Mimikatz (`Invoke-Mimikatz`)** : Mimikatz est un outil bien connu utilisé pour voler des informations sensibles comme des mots de passe dans la mémoire d'un système.
- **Exécution dynamique (`Invoke-Expression` / `IEX`)** : Ces commandes permettent d'exécuter des scripts ou des commandes externes de manière dynamique. Cela peut être utilisé pour exécuter des charges utiles téléchargées.
- **Téléchargement de fichiers (`New-Object Net.WebClient` / `DownloadString`)** : Ces commandes permettent de télécharger des fichiers à partir d'Internet, souvent utilisés par les attaquants pour récupérer des malwares.
- **Modification des politiques d'exécution (`Set-ExecutionPolicy`)** : Permet aux attaquants de contourner les restrictions de PowerShell et d'exécuter des scripts malveillants.
- **Commandes encodées ou exécutées à distance (`EncodedCommand`)** : Utilisé pour exécuter des commandes codées en base64 afin de masquer leur contenu et contourner les mécanismes de détection.
- **Exclusions de Windows Defender (`Add-MpPreference`)** : Permet d'ajouter des exclusions dans Windows Defender, ce qui peut aider à éviter la détection de malwares par l'antivirus.
- **Redirection de la sortie (`Out-File` / `Out-String`)** : Ces commandes sont utilisées pour rediriger la sortie de commandes PowerShell dans un fichier ou une chaîne de texte, souvent pour enregistrer des informations sensibles ou des données malveillantes.

En combinant ces conditions avec des exclusions pour les commandes PowerShell légitimes comme `Get-Process` et `Get-Service`, cette règle permet de détecter des comportements anormaux associés à l'installation ou à la modification de services non autorisés.