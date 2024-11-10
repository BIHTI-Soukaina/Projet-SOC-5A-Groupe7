# Description

Cette règle sera levée en cas de détection d'un événement lié à l'arrêt, la désactivation ou la modification des paramètres du système de sécurité ou de la protection de Windows. Elle se déclenche pour les événements liés à des services ou actions du système qui affectent la sécurité, comme des changements dans les services de sécurité Windows.

# Criticité : **MEDIUM**

# Outils
Sysmon, Windows Event Log


# Règle SPL
```
index="connectix" 
(
    source="WinEventLog:System" 
    OR source="WinEventLog:Microsoft-Windows-Security-Mitigations/KernelMode"
)
EventCode=7024 
OR EventCode=7045 
OR EventCode=7036 
| search "Stopped" 
OR "Disabled"

```
# Règle SIGMA

```

title: Détection des arrêts ou des désactivations de services de sécurité sur Windows
id: d8c7f329-9be0-4d3d-93d5-8a08c57773bf
status: experimental
description: Cette règle détecte les événements signalant l'arrêt, la désactivation ou la modification des services liés à la sécurité du système Windows, ce qui pourrait indiquer une tentative de manipulation ou d'affaiblissement de la sécurité du système.
author: Awa Dieye
date: 2024-11-09
tags:
    - attack.t1071
    - attack.t1203
logsource:
    product: windows
    category: system
detection:
    selection:
        EventCode:
            - 7024
            - 7045
            - 7036
        Message|contains:
            - "Stopped"
            - "Disabled"
    condition: selection
falsepositives:
    - Modification légitime des services du système par un administrateur
level: medium
```

# Explication

Cette règle permet de détecter des événements qui signalent l'arrêt ou la désactivation de services essentiels pour la sécurité du système, notamment des services liés à la protection de Windows. Elle se base sur des codes d'événements spécifiques (7024, 7045, 7036) et recherche les messages indiquant que des services ont été "Stopped" (arrêtés) ou "Disabled" (désactivés).

Les services arrêtés ou désactivés peuvent indiquer une tentative de manipulation du système, potentiellement pour contourner des mécanismes de sécurité. Cette règle est donc utile pour détecter des actions qui pourraient affecter la protection du système et le rendre vulnérable à des attaques.

