# Description

Cette règle sera levée en cas de création ou modification d'une tâche planifiée sur un système, en se basant sur les événements de sécurité Windows (EventCode 4698 et 4699).

# Criticité : **LOW**

# Outils

WinEventLog

# Règle SPL

```
index="connectix" source="Wineventlog:Security" EventCode=4698 OR EventCode=4699
| eval task_action = case(EventCode==4698, "Création", EventCode==4699, "Modification")
| table ComputerName, Task_Name, Account_Name, task_action, _time
```

# Règle SIGMA

```
title: Détection de la création ou modification de tâches planifiées
id: 9876abcd-1234-5678-90ef-1234567890ab
status: experimental
description: Cette règle détecte la création ou modification de tâches planifiées sur un système à l'aide des événements de sécurité Windows (EventCode 4698 et 4699).
author: Yasmine BRAHITI
date: 2024-11-10
tags:
    - attack.t1053
logsource:
    product: windows
    category: security
detection:
    selection:
        EventCode: [4698, 4699]
    eval_action:
        task_action:
            case(EventCode==4698, "Création", EventCode==4699, "Modification")
    condition: selection
falsepositives:
    - Aucune création légitime de tâches planifiées
level: low
```

# Explication

Les événements **4698** et **4699** signalent respectivement la création et la modification de tâches planifiées, souvent utilisées par les attaquants pour la persistance. Ces logs sont rares dans Splunk actuellement, d'où l'importance d'une approche générale pour détecter toute activité suspecte, même si ces événements ne sont pas fréquemment enregistrés.

