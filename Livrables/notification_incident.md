# Notification d'incident CL1_1
## Client impacté : **Client 1**

### Sévérité de l'incident : ****
### Type d'incident : **Accès non autorisé détecté**

### Date de début d'incident : **2024-11-10**
### Description de l'incident : Accès suspect à des ressources critiques

### Impacts potentiels : **Atteinte possible à la sécurité des données présentes sur les serveurs de fichiers critiques.**

# Synthèse des analyses
### Description
Lors de la détection de cet incident, plusieurs accès suspects ont été observés provenant d’un compte inconnu. La nature de l’incident laisse penser qu'il pourrait être lié à un accès non autorisé visant à exfiltrer ou altérer des données sensibles sur un serveur de fichiers critique.

### Liste des alertes :

| Horodatage          | Alerte / Activité observée      | Urgence | Détails / Contexte                                    | Actif impacté     | Utilisateur       |
|---------------------|---------------------------------|----------|------------------------------------------------------|--------------------|-------------------|
| 2024-11-10T16:00:39.121+00:00 | Detect DNS Tunneling | high | null |  |  |
| 2024-11-10T15:45:32.317+00:00 | Ajout des utilisateurs ou des groupes | medium | Cette requête détecte les commandes net user, net localgroup, et net group avec le paramètre /add, qui peuvent être utilisées pour ajouter des utilisateurs ou des groupes, ce qui peut indiquer une tentative d’élévation de privilèges. |  |  |
| 2024-11-10T15:00:30.479+00:00 | Suspicious Use of WinRM on Port 5985 | high | Detect potentially unauthorized use of WinRM (Windows Remote Management) over port 5985 |  |  |
| 2024-11-10T15:00:29.693+00:00 | Detect Outbound Connections on Unusual Ports | high | Potential C2 Communication via Non-Standard Port |  |  |
| 2024-11-09T20:16:00.512+00:00 | Network Share Discovery | medium | Reconnaissance d' une attaque, visant à collecter des informations ou à préparer l’accès à des ressources internes |  |  |
| 2024-11-09T20:08:24.566+00:00 | Detection of Drive-by Compromise via Suspicious Process Creation | medium | Identify potential drive-by download attacks where browsers initiate unexpected processes, possibly indicating exploitation through malicious websites. |  |  |
| 2024-11-09T11:45:32.805+00:00 | Création de tâche planifiée | low | null |  |  |
| 2024-11-09T09:40:43.355+00:00 | Defense Evasion arret ou desactivation de service | medium | Elle vise à surveiller les modifications critiques dans l'état des services système, ce qui pourrait indiquer une tentative de contournement de la sécurité (par désactivation ou arrêt des services clés) |  |  |
| 2024-11-09T09:40:41.329+00:00 | Defense Evasion éviter la détection Powershell | medium | Cette requête permet de surveiller les activités PowerShell suspectes pouvant indiquer des tentatives d'évasion via l'obfuscation ou le contournement des restrictions d'exécution de PowerShell. notamment l'exécution sans profil ou l'utilisation de commandes encodées : Pour dissimuler le contenu des commandes et échapper à la détection. |  |  |
| 2024-11-09T09:09:33.341+00:00 | Unsuccessful Logon Attempts | low | Alerts when an unsuccessful logon attempt is detected, indicating a potential unauthorized access or attack. |  |  |


# Plan d'action initial
## Actions à mener par le client
- [ ] Si la connexion suspecte est légitime : Informer le SOC pour une documentation de cet accès.
  - [ ] Vérifier les autorisations d’accès et l’adresse IP associée.
- [ ] Si la connexion suspecte n’est pas légitime : Informer immédiatement le SOC.
  - [ ] Bloquer les connexions en provenance de l’adresse IP suspecte.
  - [ ] Modifier les mots de passe des utilisateurs ayant accès au serveur impacté.
  - [ ] Isoler les fichiers sensibles jusqu’à nouvel ordre.

## Actions à mener par le SOC
- [ ] Si l’accès est légitime :
  - [ ] Valider les autorisations associées à l'utilisateur.
- [ ] Si l’accès est non légitime :
  - [ ] Identifier l'origine exacte de la connexion.
  - [ ] Analyser les logs pour détecter d'autres accès potentiels suspects.
  - [ ] Surveiller les serveurs de fichiers pour d'autres activités anormales.