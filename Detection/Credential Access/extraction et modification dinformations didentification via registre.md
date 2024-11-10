# Description

Cette règle détecte les tentatives de modification des clés de registre critiques liées à la gestion de la sécurité des identifiants dans Windows, y compris les clés **Wdigest**, **LSA Protection**, et **SAM**. Ces modifications sont couramment utilisées pour contourner les protections de sécurité, notamment celles liées aux informations d'identification des utilisateurs, permettant ainsi l'extraction de mots de passe ou l'élévation de privilèges. La règle se déclenche lorsqu'un processus est créé avec des commandes spécifiques pour interroger ou modifier ces clés de registre.

# Criticité : **HIGH**

# Outils
Sysmon, Windows Event Log

# Règle SPL
```spl
index="connectix" 
(
    sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
    OR sourcetype="sysmon"
) 
(EventCode=1) // EventCode=1 pour la création de processus
(
    // Wdigest Key
    CommandLine="*reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest*" 
    OR CommandLine="*reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest /v UseLogonCredential /t REG_DWORD /d 1*"
    
    // LSA Protection Key
    OR CommandLine="*reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa*"
    OR CommandLine="*reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 0*"

    // SAM Key
    OR CommandLine="*reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\SamSs\\Parameters*"
    OR CommandLine="*reg save HKLM\\SAM*"
    OR CommandLine="*reg load HKLM\\SAM*"
)

```

# Règle SIGMA

```
title: Détection des modifications des clés de registre critiques pour la sécurité des identifiants Windows 
id: 0a1e4937-3fe2-4a5b-b053-9277a8497a21 
status: experimental 
description: Cette règle détecte les tentatives de modification des clés de registre liées à Wdigest, LSA Protection, et SAM, qui sont utilisées pour la gestion des identifiants et des mots de passe dans Windows. Ces actions peuvent être utilisées pour contourner les protections de sécurité et obtenir des informations sensibles.
author: Awa Dieye 
date: 2024-11-09
tags: - attack.t1071.001 - attack.t1003.003
logsource: 
  product: windows 
  category: sysmon 
detection: 
  selection:
    EventID: 1 
CommandLine|contains: - "reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" - "reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest /v UseLogonCredential" - "reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa" - "reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL" - "reg query HKLM\SYSTEM\CurrentControlSet\Services\SamSs\Parameters" - "reg save HKLM\SAM" - "reg load HKLM\SAM" 
condition: selection 
falsepositives: - Modification légitime des clés de registre pour la configuration des services Windows.
level: high
```
# Explication

Cette règle est conçue pour détecter des modifications spécifiques dans les clés de registre critiques de Windows qui sont liées à la gestion des informations d'identification des utilisateurs et à la sécurité du système. Les clés surveillées sont :

1. **Wdigest** : La modification de cette clé permet de contourner la protection des informations d'identification de connexion en clair. L'activation de la valeur `UseLogonCredential` est un indicateur qu'une tentative de récupération des mots de passe en texte clair a eu lieu.
   
2. **LSA (Local Security Authority)** : L'activation ou la modification de la clé **RunAsPPL** désactive la protection des processus critiques de la LSA. Cela peut faciliter l'accès à des informations sensibles telles que les mots de passe de l'utilisateur.

3. **SAM (Security Accounts Manager)** : Les tentatives de sauvegarde ou de chargement de la base de données des comptes de sécurité (**SAM**) sont souvent utilisées dans des attaques comme **Pass-the-Hash** pour contourner les mécanismes de sécurité.

La détection de ces événements est essentielle pour prévenir les attaques visant à récupérer des mots de passe ou à modifier des paramètres de sécurité critiques dans un système Windows. Les actions enregistrées dans les journaux de sécurité, telles que l'exécution de commandes pour interroger ou ajouter des valeurs à ces clés de registre, peuvent indiquer des tentatives d'escalade de privilèges ou de contournement de la sécurité.

