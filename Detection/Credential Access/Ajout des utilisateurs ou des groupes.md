# Description

Cette règle détecte les tentatives de création ou d'ajout d'utilisateurs à des groupes locaux ou des groupes de domaine via des commandes `net user`, `net localgroup`, ou `net group` dans l'environnement Windows. Cela peut indiquer une activité suspecte, telle qu'une tentative d'ajout d'un utilisateur malveillant à un groupe avec des privilèges spécifiques. Bien que ces actions puissent être légitimes dans un environnement administré, elles sont souvent associées à des actions d'escalade de privilèges ou à des actions malveillantes visant à compromettre la sécurité d'un système.

# Criticité : **LOW**

# Outils
Sysmon, Windows Event Log

# Règle SPL
```spl
index="connectix"
(
    sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
    OR sourcetype="sysmon"
) 
EventCode=1
(
    CommandLine="*net user*" 
    OR CommandLine="*net localgroup*" 
    OR CommandLine="*net group*"
)
| search CommandLine="* /add *"

```

# Règle SIGMA

```
title: Détection de la création ou de l'ajout d'un utilisateur dans un groupe via des commandes Net
id: 35f62cfd-4f42-43a0-b23c-94d9ec5d209b
status: experimental
description: Cette règle détecte l'utilisation de commandes pour ajouter un utilisateur dans un groupe local ou de domaine, ce qui peut indiquer une activité suspecte, comme une tentative d'escalade de privilèges ou un ajout malveillant d'un utilisateur dans un groupe à privilèges.
author: Awa Dieye
date: 2024-11-09
tags: - attack.t1078.003
logsource: 
  product: windows 
  category: sysmon
detection: 
  selection:
    EventID: 1 
CommandLine|contains: - "net user" - "net localgroup" - "net group" search: CommandLine|contains: "/add" 
condition: selection AND search 
falsepositives: - Modification légitime des groupes ou des utilisateurs par un administrateur.
level: low


# Explication

Cette règle vise à détecter les événements où des utilisateurs sont ajoutés à des groupes locaux ou à des groupes de domaine via les commandes `net user`, `net localgroup`, ou `net group`. Les commandes qui incluent le paramètre `/add` permettent d'ajouter des utilisateurs à des groupes, ce qui est souvent utilisé pour accorder des privilèges supplémentaires.

Les clés surveillées par cette règle sont les suivantes :

- **net user** : Utilisé pour ajouter ou modifier des utilisateurs.
- **net localgroup** : Utilisé pour gérer les groupes locaux.
- **net group** : Utilisé pour gérer les groupes dans un domaine.

Bien que cette action puisse être légitime dans un environnement administré, elle est souvent utilisée à des fins malveillantes, comme l'ajout d'un utilisateur malveillant dans un groupe d'administrateurs. La règle est donc utile pour surveiller les tentatives de modification des utilisateurs ou des groupes, en particulier dans le cadre de comportements suspects pouvant viser à accorder des privilèges élevés.

