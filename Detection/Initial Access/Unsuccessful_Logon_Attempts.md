
# Unsuccessful Logon Attempts

## Description
Cette règle détecte les tentatives de connexion échouées, ce qui peut indiquer des tentatives de brute-force ou des erreurs de configuration. Elle permet de repérer des activités suspectes sur les comptes utilisateur, en particulier si elles sont répétées sur une courte période.

## Criticité : **MEDIUM**

## Outils
Security Event Log

## Règle SPL

```spl
index=connectix source="WinEventLog:Security" EventCode="4625"
| eval Host=coalesce(Host, Source_Network_Address)
| table _time, Host, Account_Name, Logon_Type, Failure_Reason
| sort - _time
```

## Règle SIGMA

```yaml
title: Tentatives de connexion échouées
id: b45e95f6-dec4-43ab-b3ba-91471e993c9c
status: experimental
description: Cette règle détecte les tentatives de connexion échouées, ce qui peut être un signe d'attaques de brute-force ou de configurations incorrectes.
author: Nurdini BINTI MOHAMAD
date: 2024-11-10
tags:
    - attack.t1110
logsource:
    product: windows
    category: authentication
detection:
    selection:
        EventID: 4625
    condition: selection
falsepositives:
    - Erreurs de saisie d’utilisateur légitimes
    - Tests de connexion autorisés par des administrateurs
level: medium
```

## Explication
Cette règle identifie les tentatives de connexion échouées en se basant sur l’EventCode 4625, qui signale les erreurs d'authentification. Elle fournit des détails sur l'utilisateur, le type de connexion et la raison de l'échec, ce qui permet de distinguer les erreurs légitimes des activités malveillantes.
