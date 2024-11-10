
# Description

Cette règle détecte le trafic réseau impliquant certains ports couramment utilisés (par exemple, 53, 80, 443) entre une liste d'adresses IP locales et externes spécifiées, avec une quantité significative de données transférées (plus de 50 000 octets).

# Criticité : **LOW**

# Outils

Suricata

# Règle SPL

```
index="connectix" sourcetype="suricata"
(
    (dest_port IN (53, 80, 443, 8080, 8443, 21, 22, 25) OR src_port IN (53, 80, 443, 8080, 8443, 21, 22, 25))
    AND
    (src_ip IN ("192.168.10.23", "192.168.10.22", "192.168.10.21", "192.168.10.10")
    AND dest_ip IN ("199.232.214.172", "185.220.101.0", "185.220.101.25", "104.248.44.25", "185.53.179.74","1.1.1.1"))
    AND (bytes > 50000)
)
| table _time, src_ip, dest_ip, src_port, dest_port, protocol, event_type
```

# Règle SIGMA

```
title: Détection de transfert de données élevé entre IP internes et externes spécifiques sur des ports standards
id: e3b7c4d9-f95a-4aeb-9d38-9a9b29a7f85e
status: experimental
description: Cette règle détecte un trafic réseau significatif (plus de 50 000 octets) entre des adresses IP locales et externes spécifiées, sur des ports courants (53, 80, 443, etc.).
author: Soukaina BIHTI.
date: 2024-11-09
tags:
    - attack.t1071.001
    - network
logsource:
    product: network_traffic
    service: suricata
detection:
    selection:
        src_ip:
            - "192.168.10.23"
            - "192.168.10.22"
            - "192.168.10.21"
            - "192.168.10.10"
        dest_ip:
            - "199.232.214.172"
            - "185.220.101.0"
            - "185.220.101.25"
            - "104.248.44.25"
            - "185.53.179.74"
            - "1.1.1.1"
        dest_port|in:
            - 53
            - 80
            - 443
            - 8080
            - 8443
            - 21
            - 22
            - 25
        src_port|in:
            - 53
            - 80
            - 443
            - 8080
            - 8443
            - 21
            - 22
            - 25
        bytes|gt: 50000
    condition: selection
falsepositives:
    - Transferts de fichiers légitimes ou connexions réseau de haute intensité pour des services autorisés.
level: low
```

# Explication

Cette règle surveille les transferts de données importants (supérieurs à 50 000 octets) entre des adresses IP internes spécifiées et des IP externes potentiellement sensibles, en passant par des ports standards comme 53, 80, 443, etc. Elle est utile pour repérer des transferts inhabituels de données vers ou depuis des destinations externes spécifiques.