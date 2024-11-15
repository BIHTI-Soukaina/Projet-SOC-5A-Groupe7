# Description

Cette règle détecte l'ajout non autorisé d'utilisateurs à des groupes privilégiés (par exemple, les administrateurs) par des comptes non-administratifs. Une escalade de privilèges non autorisée peut accorder aux attaquants un accès administratif, augmentant le risque de compromission du système.

# Criticité : **HIGH**

# Outils

WinEventLog

# Règle SPL

```
index=connectix sourcetype=WinEventLog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| search NOT Account_Name IN ("frank", "olivia", "alice", "yara", "david", "katherine", "uma", "SRV-PRD-DC$", "SRV-PRD-WEB$", "SRV-PRD-DB$", "SRV-PRD-SHARE$")
| table _time host source sourcetype Account_Name Account_Domain member_dn member_nt_domain ComputerName
| sort -_time
```

# Règle SIGMA

```
title: Detection of Unauthorized User Addition to Privileged Groups
id: a9d12b80-21f3-4f9e-bad1-groupadd
status: experimental
description: This rule detects the unauthorized addition of users to privileged groups (e.g., Administrators) by non-administrative accounts. Unauthorized privilege escalation can grant attackers administrative access, increasing the risk of system compromise.
author: Generated by System
date: 2024-11-09
tags:
  - attack.privilege_escalation
  - attack.t1078
logsource:
  product: windows
  category: group_management
  service: security
detection:
  selection:
    EventID:
      - 4728
      - 4732
      - 4756
    Account_Name:
      - '!frank'
      - '!olivia'
      - '!alice'
      - '!yara'
      - '!david'
      - '!katherine'
      - '!uma'
      - '!SRV-PRD-DC$'
      - '!SRV-PRD-WEB$'
      - '!SRV-PRD-DB$'
      - '!SRV-PRD-SHARE$'
  condition: selection
falsepositives:
  - Legitimate addition of users to privileged groups by authorized personnel for administrative purposes.
level: high
```

# Explication

Cette règle détecte l'ajout non autorisé d'utilisateurs à des groupes privilégiés par des comptes non-administratifs, ce qui pourrait indiquer une tentative d'escalade de privilèges. En surveillant ces événements, cette règle aide à identifier les menaces potentielles et à prendre des mesures de remédiation appropriées.

