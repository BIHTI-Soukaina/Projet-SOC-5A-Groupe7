# Description

Cette règle permet de détecter les événements de réinitialisation du journal de sécurité de Windows. L'événement **EventCode 1102** indique qu'un journal de sécurité a été réinitialisé, ce qui peut être un indicateur d'une tentative de manipulation ou de suppression des traces d'activités malveillantes. Cette règle est utilisée pour surveiller les réinitialisations du journal de sécurité, qui pourraient être un comportement suspect dans un environnement de sécurité.

# Criticité : **Medium**

# Outils  
Sysmon, Windows Event Log, Security Event Log

# Règle SPL
```spl
index=connectix source="WinEventLog:Security" EventCode=1102
```
# Règle SIGMA

```
title: Détection de la réinitialisation du journal de sécurité
id: 12345678-abcd-1234-abcd-1234567890ab
status: experimental
description: Cette règle détecte les événements indiquant qu'un journal de sécurité a été réinitialisé. Une réinitialisation des journaux de sécurité peut indiquer une tentative de suppression des traces d'activités malveillantes ou d'actions de manipulation du système.
author: Awa Dieye
date: 2024-11-09
tags:
    - attack.t1070.001
logsource:
    product: windows
    category: security
detection:
    selection:
        EventCode: 1102
    condition: selection
falsepositives:
    - Réinitialisation légitime du journal de sécurité par un administrateur
level: medium
```

# Explication
L'événement 1102 dans les journaux de sécurité de Windows est généré lorsqu'un administrateur ou un utilisateur réinitialise le journal de sécurité. Bien que la réinitialisation des journaux puisse être une action légitime réalisée par des administrateurs pour des raisons de gestion des journaux, elle peut aussi être utilisée par des attaquants pour effacer les traces de leurs activités malveillantes.

Surveiller cet événement est essentiel pour détecter des tentatives de suppression de preuves d'activités malveillantes, comme l'exécution de scripts malveillants ou l'accès non autorisé aux systèmes. La réinitialisation des journaux peut être un indicateur clé dans une investigation de sécurité, permettant aux analystes de détecter des comportements suspects et de prendre des mesures préventives pour sécuriser le système.

Criticité élevée : Ce type d'événement est jugé de haute criticité car il pourrait indiquer une tentative de couvrir une activité malveillante, par exemple, après l'exécution d'une attaque qui pourrait être enregistrée dans les journaux de sécurité.
