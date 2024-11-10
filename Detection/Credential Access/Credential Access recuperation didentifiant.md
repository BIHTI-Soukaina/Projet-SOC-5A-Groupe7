# Description

Cette règle détecte les tentatives d'extraction de mots de passe ou d'exploitation des services de gestion des identifiants Windows à l'aide d'outils tels que **Mimikatz**, **LsaDumper**, et d'autres techniques courantes d'attaque comme l'accès à **LSASS** (Local Security Authority Subsystem Service). Elle est déclenchée par la création de processus ou l'attribution de privilèges associés à des commandes spécifiques utilisées par ces outils.

# Criticité : **HIGH**

# Outils
Sysmon, Windows Event Log, Mimikatz

# Règle SPL
```spl

index="connectix" ( sourcetype="WinEventLog
/Operational" OR sourcetype="sysmon" OR sourcetype="WinEventLog" ) (EventCode=1 OR EventCode=4672) ( "sekurlsa::logonpasswords" OR "Mimikatz" OR "NTLM" OR "LSASS" OR "logonpasswords" OR "dump" OR "msv1_0" OR "kerberos" OR "NTDS" OR "LsaDumper" OR "Invoke-Mimikatz" OR "privilege::debug" )
```

# Règle SIGMA

```
title: Détection des tentatives d'extraction de mots de passe ou d'exploitation de LSASS via Mimikatz
id: 4d839c91-6f33-4f61-b1b4-3b348f7a9b85
status: experimental
description: Cette règle détecte l'exécution de commandes utilisées par des outils comme Mimikatz pour extraire des mots de passe ou interagir avec LSASS. Elle est activée par la création de processus ou l'attribution de privilèges spécifiques dans les événements Windows.
author: Awa Dieye
date: 2024-11-09
tags: - attack.t1003.002 - attack.t1071.001
logsource:
  product: windows
  category: sysmon
detection:
  selection:
    EventID: 1
CommandLine|contains: - "sekurlsa::logonpasswords" - "Mimikatz" - "NTLM" - "LSASS" - "logonpasswords" - "dump" - "msv1_0" - "kerberos" - "NTDS" - "LsaDumper" - "Invoke-Mimikatz" - "privilege::debug" condition: selection falsepositives: - Exécution légitime d'outils administratifs ou de dépannage pour la gestion des mots de passe. level: high

```

# Explication

Cette règle surveille des événements spécifiques dans les journaux Windows **Sysmon** et **Windows Event Log** pour détecter les actions liées à l'extraction de mots de passe et à l'exploitation des services de sécurité Windows. Plus précisément, elle surveille les événements de **création de processus (EventCode=1)** et les événements liés à **l'attribution de privilèges élevés (EventCode=4672)**. Les techniques et commandes spécifiques telles que **Mimikatz**, **Invoke-Mimikatz**, et les références à **LSASS** sont des indicateurs clairs d'une tentative d'attaque visant à récupérer des informations sensibles, comme des mots de passe.
