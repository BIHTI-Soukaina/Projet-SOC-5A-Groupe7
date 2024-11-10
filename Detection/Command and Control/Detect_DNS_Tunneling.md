
# Detect DNS Tunneling

## Description
Cette règle détecte des activités de tunneling DNS potentielles, souvent utilisées dans les attaques de Command and Control (C2) pour exfiltrer des données ou maintenir une connexion avec un serveur de commande. Elle analyse les requêtes DNS de haute fréquence à des IPs externes.

## Criticité : **LOW**

## Outils
Suricata

## Règle SPL

```spl
index=connectix sourcetype=suricata
| search app_proto="dns" AND dest_ip="*" 
| stats count by host, src_ip, dest_ip
| table host, src_ip, dest_ip, count
```

## Règle SIGMA

```yaml
title: Détection de tunneling DNS
id: d55e95f6-dec4-43ab-b3ba-91471e993c9d
status: experimental
description: Cette règle détecte des activités de tunneling DNS qui pourraient signaler une connexion Command and Control.
author: Votre Nom
date: 2024-11-10
tags:
    - attack.t1071.004
logsource:
    product: windows
    category: network_traffic
detection:
    selection:
        app_proto: "dns"
    condition: selection
falsepositives:
    - Activité DNS légitime avec des domaines externes
level: high
```

## Explication
Cette règle surveille des requêtes DNS répétées et fréquentes vers des IPs externes, ce qui pourrait indiquer un tunneling DNS, souvent utilisé pour établir des connexions C2 dissimulées.
