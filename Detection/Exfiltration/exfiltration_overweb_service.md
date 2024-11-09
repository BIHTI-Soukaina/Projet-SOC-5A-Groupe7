
# Description

Cette règle surveille le trafic réseau HTTP/HTTPS dirigé vers des serveurs spécifiés (`SRV-PRD-SHARE`, `SRV-PRD-DB`) avec des méthodes HTTP `POST`, en vérifiant que des données (octets) ont bien été envoyées dans la requête.

# Criticité : **LOW**

# Outils

 Suricata

# Règle SPL

```
index="connectix" sourcetype="suricata"
((dest_port IN (80, 443) OR src_port IN (80, 443)) 
AND (src_host IN ("SRV-PRD-SHARE", "SRV-PRD-DB"))) 
(method="POST") AND (bytes > 0)
```

# Règle SIGMA

```
title: Détection de requêtes HTTP/HTTPS POST vers des serveurs spécifiés avec transfert de données
id: d7a2f4b8-e567-4b9b-b9b2-38d9c593c5b2
status: experimental
description: Cette règle détecte les requêtes HTTP/HTTPS POST vers les serveurs `SRV-PRD-SHARE` et `SRV-PRD-DB` sur les ports 80 ou 443, où des données sont effectivement envoyées.
author: Soukaina BIHTI.
date: 2024-11-09
tags:
    - attack.T1567 
    - network
logsource:
    product: network_traffic
    service: suricata
detection:
    selection:
        dest_port:
            - 80
            - 443
        src_port:
            - 80
            - 443
        src_host:
            - "SRV-PRD-SHARE"
            - "SRV-PRD-DB"
        method: "POST"
        bytes|gt: 0
    condition: selection
falsepositives:
    - Transferts légitimes de fichiers ou de données vers les serveurs web internes.
level: low
```

# Explication

Cette règle cible les requêtes HTTP ou HTTPS utilisant la méthode `POST`, envoyées vers les serveurs désignés `SRV-PRD-SHARE` ou `SRV-PRD-DB`, sur les ports 80 ou 443, et avec des données transmises (taille en octets supérieure à 0). Cela permet de détecter des transferts de données vers des ressources web sensibles, et ainsi surveiller d'éventuels comportements suspects dans le trafic réseau.
