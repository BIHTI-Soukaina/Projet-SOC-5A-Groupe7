
# Detect Outbound Connections on Unusual Ports

## Description
Cette règle identifie les connexions sortantes vers des ports inhabituels, ce qui peut signaler un trafic de Command and Control (C2) ou d'autres activités suspectes.

## Criticité : **MEDIUM**

## Outils
Suricata

## Règle SPL

```spl
index=connectix sourcetype="suricata"
| search NOT dest_port IN (80, 443, 53)
| stats count by src_ip, dest_ip
| table src_ip, dest_ip, count
```

## Règle SIGMA

```yaml
title: Détection de connexions sortantes sur des ports inhabituels
id: e65e95f6-dec4-43ab-b3ba-91471e993c9e
status: experimental
description: Cette règle détecte des connexions sortantes vers des ports inhabituels, ce qui pourrait signaler une activité de Command and Control.
author: Votre Nom
date: 2024-11-10
tags:
    - attack.t1071
logsource:
    product: windows
    category: network_traffic
detection:
    selection:
        dest_port|not_in:
            - 80
            - 443
            - 53
    condition: selection
falsepositives:
    - Connexions légitimes vers des services sur des ports non standards
level: medium
```

## Explication
Cette règle surveille les connexions sortantes vers des ports non standards (autres que 80, 443, 53), ce qui peut signaler des canaux C2 non conventionnels ou des activités suspectes.
