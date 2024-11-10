# Notification d'incident CL1_1
## Client impacté : **Client 1**

### Sévérité de l'incident : **{{ jsout['results'][0]['severity'] }}**
### Type d'incident : **Accès non autorisé détecté**

### Date de début d'incident : **{{ jsout['results'][0]['_time'][:10] }}**
### Description de l'incident : Accès suspect à des ressources critiques

### Impacts potentiels : **Atteinte possible à la sécurité des données présentes sur les serveurs de fichiers critiques.**

# Synthèse des analyses
### Description
Lors de la détection de cet incident, plusieurs accès suspects ont été observés provenant d’un compte inconnu. La nature de l’incident laisse penser qu'il pourrait être lié à un accès non autorisé visant à exfiltrer ou altérer des données sensibles sur un serveur de fichiers critique.

### Liste des alertes :

| Horodatage          | Alerte / Activité observée      | Urgence | Détails / Contexte                                    | Actif impacté     | Utilisateur       |
|---------------------|---------------------------------|----------|------------------------------------------------------|--------------------|-------------------|
{% for result in jsout['results'] -%}
| {{ result['_time'] }} | {{ result['event.event_title'] }} | {{ result['event.urgency'] }} | {{ result['event.originQuery.description'] }} | {{ result['fields.Host'] }} | {{ result['fields.Account_Name'] }} |
{% endfor %}

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
