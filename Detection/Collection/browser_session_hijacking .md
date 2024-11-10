# Description

Cette règle détecte les requêtes HTTP qui incluent des en-têtes sensibles comme `Cookie`, `Authorization`, ou `Set-Cookie`, et qui contiennent des valeurs spécifiques telles que les tokens `Bearer` ou les identifiants de session (`session_id`). Cela permet de surveiller le passage de jetons d'authentification ou de sessions, souvent critiques pour la sécurité.

# Criticité : **MEDIUM**

# Outils

Suricata

# Règle SPL



```
index="connectix" sourcetype=suricata (http.request_headers{}.name="Cookie" OR http.request_headers{}.name="Authorization" OR http.request_headers{}.name="Set-Cookie") AND (http.request_headers{}.value="Bearer*" OR http.request_headers{}.value="session_id")
```

# Règle SIGMA

```
title: Détection d'en-têtes HTTP sensibles avec jetons d'authentification ou identifiants de session 
id: f5a3c7b6-a8e3-4fa1-92d5-d0d8b1d6f7ab 
status: experimental 
description: Cette règle détecte les requêtes HTTP avec en-têtes sensibles incluant des valeurs d'authentification ou de session, telles que les tokens Bearer ou session_id. 
author: Soukaina BIHTI. 
date: 2024-11-09 
tags: - attack.t1071.001 - 
logsource: 
	product: network_traffic 
	service: suricata detection: selection: http.request_headers{}: - name: "Cookie" - name: "Authorization" - name: "Set-Cookie" http.request_headers{}.value|contains: - "Bearer" - "session_id" condition: selection falsepositives: - Transmissions légitimes de jetons d'authentification ou de sessions pour des applications de confiance. 
level: medium
```



# Explication

Cette règle permet de détecter des requêtes HTTP contenant des en-têtes `Cookie`, `Authorization`, ou `Set-Cookie` avec des valeurs sensibles comme `Bearer` ou `session_id`. Elle est utile pour identifier d'éventuels risques de fuite d'informations d'authentification dans le trafic réseau.

