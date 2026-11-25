# SysAudit Pro — documentation

![SCHMOCK](assets/schmock.png)

Créé par **SCHMOCK** — <https://schmock.fr>

**Télécharger** (version portable ou installateur) : <https://github.com/schm0ck101/sysaudit-pro/releases/latest>

Diagnostic complet de **postes de travail et serveurs Windows**. SysAudit Pro
liste tout ce qui ne va pas **et tout ce qui risque de mal tourner** : disque
qui s'use, mémoire qui fuit, mises à jour bloquées, plantages qui se
multiplient, failles de configuration. Chaque problème est expliqué avec son
risque et l'action à mener. Le résultat est un **rapport PDF client**.

- **Portable** : un seul fichier sur clé USB, rien à installer chez le client.
- **Lecture seule** : l'analyse ne modifie rien sur le poste.
- **Rapide** : 15 secondes à 3 minutes selon le poste et les options.
- **Hors ligne** : aucune donnée n'est envoyée sur Internet. Les seuls accès
  réseau sont les tests optionnels (ping, DNS, heure) et la recherche de mises
  à jour Windows.

---

## 1. Installation
- **Portable** : `SysAuditPro-Portable.exe`, à copier sur la clé USB
  d'intervention. L'historique des clients est enregistré **à côté de l'exe**,
  dans `SysAuditPro-Donnees\`. Il voyage donc avec la clé.
- **Installateur** : `SysAuditPro-Setup-1.0.4.exe`. Les données sont alors
  dans `%APPDATA%\SysAuditPro\`.

Systèmes pris en charge : Windows 10, Windows 11, Windows Server 2016, 2019,
2022 et 2025 (64 bits).

### Droits administrateur
L'application fonctionne sans droits administrateur, mais certains contrôles
sont alors indiqués comme « non vérifiés ». Le bouton **Relancer en
administrateur** (invite Windows) donne accès à ces contrôles :
- usure et erreurs SMART des disques, et prédiction de panne ;
- chiffrement BitLocker et puce TPM ;
- stratégie de mots de passe et de verrouillage ;
- échecs de connexion (journal Sécurité) ;
- intégrité des fichiers Windows (DISM) ;
- durée de démarrage et ses causes ;
- températures.

---

## 2. Utilisation
1. **Analyse** : saisissez le client, le site et des notes (facultatif), puis
   cliquez sur **Lancer l'analyse**. Deux options sont proposées :
   - la recherche des mises à jour disponibles (Internet, jusqu'à 2 minutes) ;
   - les tests réseau.
2. **Résultats** :
   - une note globale sur 100 et une note par domaine ;
   - les constats classés par gravité : Critique, Majeur, Mineur, Information ;
   - les **risques à venir** (⚠) ;
   - des filtres et une recherche.

   Chaque constat détaille ce qui a été vu, pourquoi c'est important et
   **que faire**.
3. **Rapport PDF** : un document client avec :
   - une page de garde à votre nom et avec votre logo ;
   - une synthèse et les priorités d'intervention ;
   - les risques à venir et l'évolution depuis l'analyse précédente ;
   - le détail par domaine ;
   - les points conformes et les points non vérifiés ;
   - la fiche du poste ;
   - la méthodologie.
4. **Inventaire** : toutes les données relevées sur le poste : matériel,
   disques, volumes, logiciels, services, démarrage, tâches planifiées,
   réseau, processus, mises à jour et pilotes.
5. **Historique** : toutes les analyses, par client. Quand un même poste est
   analysé plusieurs fois, l'application compare automatiquement les résultats
   (problèmes résolus et nouveaux problèmes).

Le bouton **Ré-analyser** applique les règles d'une version plus récente de
l'application aux données d'une ancienne analyse, sans retourner sur place.
Le bouton **Exporter les données** produit un JSON (données brutes et
résultats) pour l'archivage ou le support.

Il existe aussi un mode sans interface, par exemple pour un script :
`SysAuditPro.exe --collect resultat.json`.

---

## 3. Ce qui est contrôlé

### Matériel et stabilité
- **Disques** :
  - état Windows et prédiction SMART ;
  - usure des SSD, erreurs non corrigées, température, âge des disques durs ;
  - secteurs défectueux et erreurs d'E/S répétées (journaux disk 7, 51, 153…) ;
  - réinitialisations du contrôleur et corruption NTFS ;
  - échecs de l'optimisation (TRIM).
- **Plantages** :
  - écrans bleus (journaux et fichiers de vidage sur 90 jours) ;
  - arrêts brutaux ;
  - services Windows qui s'arrêtent de façon inattendue.
- **Erreurs matérielles** (WHEA, corrigées ou non), bridage du processeur par
  surchauffe et températures.
- **Applications** qui plantent ou se figent, regroupées par application.
- **Indice de fiabilité Windows** et sa **tendance**.
- **Périphériques et matériel** :
  - périphériques en erreur et pilotes qui ne se chargent pas ;
  - usure de la batterie ;
  - âge du BIOS et du pilote graphique.

### Système et performances
- **Fin de support de Windows** : la version installée est comparée au cycle
  de vie Microsoft, avec une alerte 12 mois avant l'échéance.
- **Mises à jour** :
  - ancienneté du dernier correctif ;
  - échecs répétés, en distinguant mises à jour Windows et applications du
    Store ;
  - correctifs de sécurité en attente ;
  - Windows Update désactivé ou suspendu ;
  - redémarrage en attente ;
  - durée depuis le dernier redémarrage.
- **Espace disque** par volume, avec l'espace récupérable sur le disque
  système : Windows.old, fichiers temporaires, cache des mises à jour,
  corbeille, vidage mémoire.
- **Volume à vérifier** : bit « dirty » ou état dégradé.
- **Mémoire** :
  - saturation de la mémoire virtuelle ;
  - mémoire vive insuffisante ;
  - fichier d'échange trop petit ;
  - épuisements signalés par Windows ;
  - fuite de mémoire noyau (pilote) ou d'un processus.
- **Performances** : charge du processeur, latence des disques.
- **Démarrage** :
  - durée et **tendance** ;
  - programmes et pilotes qui le ralentissent ;
  - nombre de programmes lancés au démarrage.
- **Services** : services automatiques arrêtés, échecs de démarrage répétés.
- **Tâches planifiées** en échec (hors tâches Microsoft).
- **Réseau** :
  - erreurs sur les cartes réseau ;
  - liaison négociée à 100 Mb/s ;
  - adresse APIPA (169.254.x.x) ;
  - pertes et latence vers la passerelle ;
  - DNS en échec ou lent.
- **Domaine** : contrôleur injoignable, stratégies de groupe non appliquées.
- **Horloge** : décalage de l'heure (Kerberos), service de temps arrêté.
- **Journaux d'événements** trop petits pour garder un historique.
- **Intégrité de Windows** (DISM).
- **Serveurs** : mode d'alimentation inadapté.

### Sécurité
Contrôles inspirés de l'ANSSI et des recommandations Microsoft.

- **Antivirus** :
  - protection active et signatures à jour ;
  - antivirus tiers reconnu ;
  - protection contre les falsifications ;
  - menaces détectées sur 30 jours.
- **Protection du poste** :
  - pare-feu actif sur chaque profil ;
  - chiffrement BitLocker du disque système (exigence plus forte pour les
    portables) ;
  - Secure Boot, mode UEFI et TPM ;
  - protection de LSA.
- **Protocoles obsolètes ou dangereux** :
  - SMBv1 ;
  - signature SMB non exigée ;
  - WDigest (mots de passe en clair en mémoire) ;
  - LM et NTLMv1 ;
  - LLMNR et NetBIOS ;
  - SSL 3.0, TLS 1.0 et 1.1 sur les serveurs.
- **UAC** : désactivé ou en élévation silencieuse.
- **Accès** :
  - ouverture de session automatique avec mot de passe stocké ;
  - Bureau à distance sans NLA ;
  - exécution automatique des clés USB ;
  - absence de verrouillage de session.
- **Comptes** :
  - compte Invité activé ;
  - compte Administrateur intégré activé ;
  - comptes sans mot de passe obligatoire ;
  - nombre d'administrateurs et utilisateur administrateur ;
  - absence de LAPS (poste du domaine).
- **Mots de passe** : longueur minimale, verrouillage et chiffrement
  réversible. Le journal Sécurité est aussi analysé : échecs de connexion
  (force brute) avec leurs sources.
- **Partages** ouverts à « Tout le monde ».
- **Certificats** expirés ou qui expirent bientôt.
- **Logiciels** :
  - logiciels en fin de support (Office 2016/2019/2021, SQL Server,
    Exchange, Flash, Java 6/7, Python 2, Acrobat…) ;
  - versions vulnérables (WinRAR, 7-Zip, PuTTY) ;
  - logiciels de prise en main à distance.
- **Services et réseau** :
  - chemins de services sans guillemets ;
  - services non chiffrés à l'écoute (Telnet, FTP, VNC) ;
  - fichier hosts détourné ;
  - Registre à distance ;
  - Spouleur d'impression actif sur un contrôleur de domaine.

---

## 4. Notes et gravités
- **Critique** : intervention immédiate.
- **Majeur** : à corriger rapidement.
- **Mineur** : amélioration recommandée.
- **Information** : à valider avec le client.

La note sur 100 retire des pénalités plafonnées : jusqu'à 60 points pour les
critiques, 30 pour les majeurs et 12 pour les mineurs. Un seul problème
critique pèse donc lourd, et une accumulation de petits points ne fait pas
s'effondrer la note.

## 5. Limites
- Les risques à venir sont déduits des indicateurs d'usure et des tendances
  enregistrés par Windows. Ils indiquent une probabilité, pas une certitude.
  Seule une sauvegarde testée protège réellement les données.
- Les valeurs SMART détaillées des disques derrière un contrôleur RAID ne sont
  pas visibles depuis Windows.
- Les rôles serveur (Active Directory, Hyper-V, SQL Server…) ne font pas
  l'objet d'un audit spécialisé dans cette version.
- Les contrôles de sécurité portent sur la configuration du poste et ne
  remplacent pas un test d'intrusion.

---

## 6. Pour les développeurs
```
sysaudit/
  collect/  scripts.py (collecteurs PowerShell 5.1), runner.py (exécution parallèle, élévation)
  analyze/  model.py, context.py, eol.py (cycles de vie), rules_hw.py, rules_sys.py, rules_sec.py, engine.py (notes)
  store.py  historique SQLite (instantanés compressés)
  report.py rapport PDF et export JSON
  ui/       interface PySide6 (analyse, résultats, inventaire, historique, paramètres)
tests/
  test_rules.py  tests des règles sur des postes simulés (sains et défaillants)
  smoke_ui.py    test de bout en bout : vraie analyse du poste, captures, PDF
```

Conception :
- La collecte (PowerShell, sans texte dépendant de la langue de Windows) est
  séparée de l'analyse, qui est pure et testable.
- Chaque section de collecte est indépendante : une section en échec n'empêche
  pas les autres.
- La table des fins de support se trouve dans `analyze/eol.py`.

Compilation : `powershell -ExecutionPolicy Bypass -File build.ps1`. Le dossier
`dist\` reçoit la version portable, l'installateur et ce README.
