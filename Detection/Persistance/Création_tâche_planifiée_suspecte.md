# Description

Cette règle sera levée en cas de création suspecte de tâches planifiées sur un système, en fonction de l'heure de création. Elle vérifie si des tâches ont été créées pendant des périodes inhabituelles, comme entre 18h et 22h ou entre 22h et 7h.

# Criticité : **MEDIUM**

# Outils

WinEventLog

# Règle SPL

```spl
index="connectix" source="Wineventlog:Security" EventCode=4698
| eval hour=strftime(_time, "%H")
| eval period=case(
    hour >= 18 AND hour < 22, "Tâche créée entre 18h et 22h",
    (hour >= 22 OR hour < 7), "Tâche créée entre 22h et 7h"
  )
| stats count by period, Task_Name, Account_Name, _time
```

# Règle SIGMA

```yaml
title: Détection de la création de tâche planifiée suspecte selon l'heure
id: 2bcd69ac-3a61-4d52-9c75-30b9bb6d5c3c
status: experimental
description: Cette règle détecte la création de tâches planifiées suspectes en fonction de l'heure de création, signalant les périodes où une activité suspecte pourrait se produire.
author: Yasmine BRAHITI
date: 2024-11-10
tags:
    - attack.t1053.003
logsource:
    product: windows
    category: security
detection:
    selection:
        EventCode: 4698
    eval_action:
        period:
            case:
                'strftime(_time, "%H") >= 18 and strftime(_time, "%H") < 22': "Tâche créée entre 18h et 22h"
                'strftime(_time, "%H") >= 22 or strftime(_time, "%H") < 7': "Tâche créée entre 22h et 7h"
    condition: selection
falsepositives:
    - Modification légitime de tâches planifiées par des administrateurs
level: medium
```

# Explication

Cette règle surveille la création de tâches planifiées durant des périodes inhabituelles, comme en dehors des heures de travail ou tard dans la soirée. Ces moments sont souvent choisis par les attaquants pour effectuer des actions malveillantes et éviter la détection. 
