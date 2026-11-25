"""Règles « Rôles et sauvegardes » : contrôleur de domaine (services, réplication,
sauvegarde de l'annuaire, SYSVOL, heure, DNS du contrôleur, comptes du domaine),
serveur DNS, DHCP, Hyper-V, SQL Server, IIS et sauvegardes.

Les rôles ne sont évalués que s'ils sont présents sur la machine."""
from __future__ import annotations

import re
from datetime import date

from .context import DENIED, Ctx
from .model import CRIT, INFO, MAJOR, MINOR, OK, SEC, SVC, Finding, fr_date, human_bytes, parse_dt, sjoin

# logiciels de sauvegarde reconnus (logiciels installés, services, fournisseurs d'événements)
BACKUP_SW = re.compile(r"veeam|acronis|active backup|synology.*backup|datto|backup exec|arcserve|altaro|nakivo|cobian|uranium|"
                       r"macrium|iperius|bacula|commvault|rubrik|cohesity|shadowprotect|storagecraft|carbonite|ahsay|duplicati|"
                       r"aomei|todo backup|crashplan|backblaze|idrive|zerto|netbackup|data protector|avamar|areca|paragon.*backup|"
                       r"handy backup|msp360|cloudberry|bvckup|freefilesync|syncback|goodsync", re.I)
BACKUP_PROV = re.compile(r"veeam|acronis|backup exec|arcserve|altaro|nakivo|cobian|uranium|macrium|iperius|shadowprotect|datto|"
                         r"active backup|msp360|cloudberry", re.I)

# fins de support SQL Server (support étendu), par version majeure
SQL_EOL = {"9": ("SQL Server 2005", date(2016, 4, 12)), "10": ("SQL Server 2008", date(2019, 7, 9)),
           "10.50": ("SQL Server 2008 R2", date(2019, 7, 9)), "11": ("SQL Server 2012", date(2022, 7, 12)),
           "12": ("SQL Server 2014", date(2024, 7, 9)), "13": ("SQL Server 2016", date(2026, 7, 14)),
           "14": ("SQL Server 2017", date(2027, 10, 12)), "15": ("SQL Server 2019", date(2030, 1, 8)),
           "16": ("SQL Server 2022", date(2033, 1, 11))}
DC_SERVICES = {"NTDS": "Services de domaine Active Directory", "Netlogon": "Ouverture de session réseau (Netlogon)",
               "Kdc": "Centre de distribution de clés Kerberos", "DNS": "Serveur DNS", "DFSR": "Réplication DFS (SYSVOL)",
               "W32Time": "Temps Windows", "ADWS": "Services Web Active Directory", "IsmServ": "Messagerie intersites"}
LOOPBACK = {"127.0.0.1", "::1"}


def _age(c: Ctx, s) -> int | None:
    d = parse_dt(s)
    return (c.now - d).days if d and d.year > 2000 else None


def _svc(c: Ctx, name: str) -> dict | None:
    for s in c.lst("roles", "role_services"):
        if (s.get("name") or "").lower() == name.lower():
            return s
    return None


def _partner(dn: str) -> str:
    m = re.search(r"CN=NTDS Settings,CN=([^,]+)", dn or "", re.I)
    return m.group(1) if m else (dn or "?")


def _nc(dn: str) -> str:
    dn = dn or ""
    if dn.upper().startswith("CN=SCHEMA"):
        return "Schéma"
    if dn.upper().startswith("CN=CONFIGURATION"):
        return "Configuration"
    if dn.upper().startswith("DC=DOMAINDNSZONES"):
        return "Zones DNS du domaine"
    if dn.upper().startswith("DC=FORESTDNSZONES"):
        return "Zones DNS de la forêt"
    return "Domaine"


def _events_text(groups: list[dict], n: int = 3) -> list[str]:
    out = []
    for g in sorted(groups, key=lambda g: -int(g.get("count") or 0))[:n]:
        msg = re.sub(r"\s+", " ", g.get("message") or "").strip()
        out.append(f"ID {g.get('id')} ({g.get('count')}×, dernier le {fr_date(parse_dt(g.get('last')))}) : {msg[:180]}")
    return out


# ---------------------------------------------------------------- contrôleur de domaine
def domain_controller(c: Ctx):
    if not c.is_dc:
        return
    ad = c.get("roles", "ad")
    errs = c.errors()
    if not ad:
        why = errs.get("ad") or "Le module Active Directory n'a pas pu être interrogé."
        c.not_checked("nc.ad", SVC, "Santé de l'annuaire Active Directory",
                      why if not DENIED.search(why) else "Ce contrôle nécessite de lancer l'application en tant qu'administrateur.")
        return
    # services essentiels
    down = []
    for name, label in DC_SERVICES.items():
        s = _svc(c, name)
        if s and (s.get("start") or "").lower() == "auto" and s.get("state") != "Running":
            down.append(label)
    if down:
        c.add(Finding("dc.services", SVC, CRIT, "Service essentiel du contrôleur de domaine arrêté : " + ", ".join(down),
                      impact="Ouvertures de session, stratégies de groupe, résolution de noms ou réplication défaillantes pour tout le domaine.",
                      fix="Démarrer le service et lire l'erreur dans l'Observateur d'événements (journaux Système et Directory Service)."))
    dcs = ad.get("dcs") or []
    names = sjoin(", ", [d.get("name") for d in dcs])
    if len(dcs) == 1:
        c.add(Finding("dc.single", SVC, MAJOR, "Un seul contrôleur de domaine",
                      detail=f"Domaine {ad.get('domain')} : {names}.",
                      impact="Si ce serveur tombe en panne, plus personne ne peut ouvrir de session ni accéder aux ressources du domaine ; "
                             "sans sauvegarde récente de l'annuaire, le domaine entier est à reconstruire.",
                      fix="Ajouter un second contrôleur de domaine (une VM suffit), de préférence sur un autre hôte physique."))
    # FSMO (pour mémoire)
    fsmo = {"Émulateur PDC": ad.get("pdc"), "Maître RID": ad.get("rid"), "Maître d'infrastructure": ad.get("infra"),
            "Maître de schéma": ad.get("schema"), "Maître d'attribution de noms": ad.get("naming")}
    c.add(Finding("dc.info", SVC, INFO, f"Domaine {ad.get('domain')} : {len(dcs)} contrôleur(s)",
                  detail=f"Contrôleurs : {names}. Niveau fonctionnel du domaine : {ad.get('domain_mode')}, de la forêt : {ad.get('forest_mode')}.",
                  evidence=[f"{k} : {v}" for k, v in fsmo.items() if v]))
    # contrôleurs sous un Windows obsolète
    old = [f"{d.get('name')} ({d.get('os')})" for d in dcs if re.search(r"2003|2008|2012", d.get("os") or "")]
    soon = [f"{d.get('name')} ({d.get('os')})" for d in dcs if re.search(r"2016", d.get("os") or "")]
    if old:
        c.add(Finding("dc.os_eol", SVC, MAJOR, "Contrôleur(s) de domaine sous un Windows plus supporté",
                      detail=", ".join(old), impact="Plus aucun correctif de sécurité sur le cœur de l'authentification du réseau.",
                      fix="Promouvoir un nouveau contrôleur sous Windows Server récent, transférer les rôles puis rétrograder l'ancien."))
    elif soon and c.now.date() < date(2027, 1, 12):
        c.add(Finding("dc.os_soon", SVC, MINOR, "Contrôleur(s) de domaine sous Windows Server 2016 (fin de support le 12/01/2027)",
                      detail=", ".join(soon), fix="Planifier l'ajout d'un contrôleur sous Windows Server 2022/2025 et la rétrogradation de l'ancien.",
                      predictive=True))
    m = re.search(r"(\d{4})", ad.get("domain_mode") or "")
    if m and int(m.group(1)) < 2012:
        c.add(Finding("dc.level", SVC, MINOR, f"Niveau fonctionnel du domaine ancien ({ad.get('domain_mode')})",
                      impact="Fonctions de sécurité récentes indisponibles (protection des comptes, Kerberos renforcé, SYSVOL DFSR…).",
                      fix="Une fois tous les contrôleurs sous Windows Server 2016 ou plus, relever le niveau fonctionnel du domaine et de la forêt."))
    if ad.get("recycle_bin") is False:
        c.add(Finding("dc.recycle", SVC, MINOR, "Corbeille Active Directory désactivée",
                      impact="Un compte, un groupe ou une unité d'organisation supprimé par erreur ne peut être restauré qu'à partir d'une sauvegarde.",
                      fix="Activer la corbeille (Centre d'administration Active Directory › Activer la corbeille) ; l'opération est irréversible et sans risque."))
    # réplication
    repl = c.lst("roles", "ad_repl")
    bad = []
    for p in repl:
        if int(p.get("failures") or 0) > 0 or int(p.get("result") or 0) != 0:
            bad.append(p)
    if bad:
        oldest = max((_age(c, p.get("last_success")) or 9999) for p in bad)
        c.add(Finding("dc.repl", SVC, CRIT if oldest >= 1 else MAJOR, f"Réplication Active Directory en échec ({len(bad)} lien(s))",
                      detail="; ".join(f"{_partner(p.get('partner'))} / {_nc(p.get('partition'))} : {p.get('failures')} échec(s), code {p.get('result')}, "
                                       f"dernière réussite le {fr_date(parse_dt(p.get('last_success')))}" for p in bad[:6]),
                      impact="Les contrôleurs divergent : mots de passe, comptes et stratégies ne sont plus les mêmes partout ; au-delà de la durée "
                             "de vie des objets supprimés, le contrôleur doit être reconstruit.",
                      fix="Lancer « repadmin /replsummary » et « dcdiag /test:replications », corriger DNS, heure ou connectivité entre contrôleurs.",
                      predictive=True))
    elif repl:
        c.add(Finding("dc.repl.ok", SVC, OK, f"Réplication Active Directory sans erreur ({len({p.get('partner') for p in repl})} partenaire(s))"))
    # sauvegarde de l'annuaire
    age = _age(c, ad.get("last_backup"))
    tomb = int(ad.get("tombstone_days") or 180)
    if age is not None:
        if age > 7:
            c.add(Finding("dc.backup", SVC, CRIT if age > min(60, tomb) else MAJOR,
                          f"Annuaire Active Directory non sauvegardé depuis {age} jours",
                          detail=f"Date de la dernière sauvegarde de l'annuaire (tous contrôleurs confondus) : {fr_date(parse_dt(ad.get('last_backup')))}. "
                                 f"Durée de vie des objets supprimés : {tomb} jours.",
                          impact="En cas de corruption, de rançongiciel ou de suppression massive, l'annuaire (comptes, groupes, stratégies) "
                                 "ne peut pas être restauré" + (" : au-delà de la durée de vie des objets supprimés, une sauvegarde ne peut "
                                                                "même plus être restaurée." if age > tomb else "."),
                          fix="Sauvegarder l'état du système d'au moins un contrôleur chaque jour (Sauvegarde Windows Server « État du système » "
                              "ou logiciel de sauvegarde compatible Active Directory)."))
        else:
            c.add(Finding("dc.backup.ok", SVC, OK, f"Annuaire Active Directory sauvegardé il y a {age} jour(s)"))
    # erreurs du service d'annuaire
    ds = ad.get("ds_errors") or []
    n = sum(int(g.get("count") or 0) for g in ds)
    if n:
        c.add(Finding("dc.ds_errors", SVC, MAJOR if n >= 20 else MINOR, f"Erreurs du service d'annuaire sur 14 jours : {n}",
                      detail="Journal « Directory Service ».", evidence=_events_text(ds),
                      impact="Signe d'un problème de base de données, de réplication ou de configuration de l'annuaire.",
                      fix="Analyser les événements cités ; lancer « dcdiag /v » pour un diagnostic complet."))
    _sysvol(c)
    _dc_time(c, ad)
    _dc_dns_client(c, ad)
    _domain_accounts(c, ad)


def _sysvol(c: Ctx):
    s = c.get("roles", "sysvol")
    if not s:
        return
    if not s.get("sysvol_share") or not s.get("netlogon_share"):
        miss = [x for x, k in (("SYSVOL", "sysvol_share"), ("NETLOGON", "netlogon_share")) if not s.get(k)]
        c.add(Finding("dc.sysvol_share", SVC, CRIT, "Partage " + " et ".join(miss) + " absent",
                      impact="Les postes ne reçoivent plus les stratégies de groupe ni les scripts d'ouverture de session depuis ce contrôleur.",
                      fix="Vérifier la réplication du SYSVOL (DFSR) et la valeur SysvolReady ; voir les événements DFS Replication."))
    st = s.get("dfsr_state")
    if s.get("frs_state") == "Running" or (st is not None and int(st) < 3):
        c.add(Finding("dc.frs", SVC, MAJOR, "SYSVOL encore répliqué par FRS (technologie retirée)",
                      detail=f"Service FRS : {s.get('frs_state') or '—'} ; état de migration DFSR : {st if st is not None else 'non commencée'}.",
                      impact="FRS n'est plus pris en charge : impossible d'ajouter un contrôleur sous Windows Server 2019 ou plus, "
                             "réplication du SYSVOL peu fiable.",
                      fix="Migrer le SYSVOL vers DFSR avec dfsrmig (étapes Prepared, Redirected puis Eliminated)."))
    dfsr = s.get("dfsr_errors") or []
    ids = {int(g.get("id") or 0) for g in dfsr}
    n = sum(int(g.get("count") or 0) for g in dfsr)
    if ids & {2213, 4012, 2212}:
        c.add(Finding("dc.dfsr_stopped", SVC, CRIT, "Réplication du SYSVOL (DFSR) arrêtée",
                      detail="Événement " + ", ".join(str(i) for i in sorted(ids & {2213, 4012, 2212})) + " dans le journal « DFS Replication ».",
                      evidence=_events_text(dfsr),
                      impact="Les stratégies de groupe et scripts modifiés ne sont plus répliqués entre contrôleurs : comportements différents selon le "
                             "contrôleur utilisé par le poste.",
                      fix="Suivre la procédure indiquée dans l'événement (reprise après arrêt brutal 2213, ou resynchronisation faisant autorité / non "
                          "faisant autorité du SYSVOL pour 4012)."))
    elif n:
        c.add(Finding("dc.dfsr", SVC, MINOR, f"Erreurs de réplication DFS sur 14 jours : {n}", evidence=_events_text(dfsr),
                      fix="Analyser les événements ; vérifier la connectivité et l'espace disque entre contrôleurs."))


def _dc_time(c: Ctx, ad: dict):
    t = c.get("network", "time_sync") or {}
    typ = (t.get("type") or "").upper()
    if not typ:
        return
    this = (ad.get("this") or "").lower()
    pdc = (ad.get("pdc") or "").lower()
    if this and pdc and this.split(".")[0] == pdc.split(".")[0]:
        if typ in ("NT5DS", "NOSYNC"):
            c.add(Finding("dc.pdc_time", SVC, MAJOR, "Le contrôleur PDC n'a pas de source de temps externe",
                          detail=f"Ce serveur détient le rôle d'émulateur PDC et se synchronise en mode {typ}.",
                          impact="Toute l'heure du domaine dérive : au-delà de 5 minutes d'écart, Kerberos refuse les ouvertures de session.",
                          fix="w32tm /config /manualpeerlist:\"0.fr.pool.ntp.org,0x8 1.fr.pool.ntp.org,0x8\" /syncfromflags:manual /reliable:yes /update"
                              + (" ; sur une VM, désactiver la synchronisation de l'heure par l'hyperviseur." if c.is_vm else "")))
    elif typ == "NTP":
        c.add(Finding("dc.time_hierarchy", SVC, MINOR, "Contrôleur de domaine synchronisé sur une source externe",
                      detail=f"Seul l'émulateur PDC ({ad.get('pdc')}) devrait utiliser une source externe ; ce contrôleur utilise {t.get('server')}.",
                      impact="Plusieurs références de temps dans le domaine : écarts possibles entre contrôleurs.",
                      fix="w32tm /config /syncfromflags:domhier /update puis net stop w32time && net start w32time."))


def _dc_dns_client(c: Ctx, ad: dict):
    dc_ips = {d.get("ip") for d in ad.get("dcs") or [] if d.get("ip")}
    own = set()
    for i in c.lst("network", "ip"):
        own |= {a.split("/")[0] for a in i.get("ipv4") or [] if a}
    external, only_self = [], False
    for i in c.lst("network", "ip"):
        if not i.get("gateway"):
            continue
        dns = [d for d in i.get("dns") or [] if d]
        external += [d for d in dns if d not in dc_ips and d not in LOOPBACK and d not in own]
        if dns and all(d in LOOPBACK or d in own for d in dns) and len(dc_ips) > 1:
            only_self = True
    if external:
        c.add(Finding("dc.dns_external", SVC, MAJOR, "Le contrôleur de domaine utilise un serveur DNS hors du domaine",
                      detail="Serveurs DNS configurés sur la carte réseau : " + ", ".join(dict.fromkeys(external)) + ".",
                      impact="Enregistrements du domaine introuvables par intermittence : ouvertures de session lentes, réplication et "
                             "stratégies de groupe en échec.",
                      fix="Sur la carte réseau, n'indiquer que des contrôleurs de domaine (un autre contrôleur puis 127.0.0.1) ; "
                          "utiliser les redirecteurs du serveur DNS pour Internet."))
    elif only_self:
        c.add(Finding("dc.dns_self", SVC, MINOR, "Le contrôleur de domaine n'utilise que lui-même comme DNS",
                      impact="Au redémarrage, le contrôleur peut attendre son propre DNS (démarrage lent, « îlot DNS »).",
                      fix="Indiquer un autre contrôleur de domaine en DNS principal et 127.0.0.1 en secondaire."))


def _domain_accounts(c: Ctx, ad: dict):
    a = c.get("roles", "ad_accounts")
    pp = ad.get("pwd_policy") or {}
    if pp:
        ml = int(pp.get("min_length") or 0)
        if ml < 12:
            c.add(Finding("pwd.length", SEC, MAJOR if ml < 8 else MINOR, f"Longueur minimale des mots de passe du domaine : {ml} caractères",
                          impact="Des mots de passe courts se devinent ou se cassent rapidement.",
                          fix="Exiger au moins 12 caractères (recommandation ANSSI) dans la stratégie de mots de passe du domaine "
                              "(ou une stratégie affinée pour les comptes à privilèges)."))
        if int(pp.get("lockout") or 0) == 0:
            c.add(Finding("pwd.lockout", SEC, MAJOR, "Aucun verrouillage des comptes du domaine après des échecs de connexion",
                          impact="Les attaques par force brute sur les comptes ne sont pas freinées.",
                          fix="Configurer un verrouillage (par ex. 10 tentatives, 15 minutes) dans la Default Domain Policy."))
        if pp.get("reversible"):
            c.add(Finding("pwd.cleartext", SEC, CRIT, "Mots de passe du domaine stockés avec un chiffrement réversible",
                          fix="Désactiver « Enregistrer les mots de passe en utilisant un chiffrement réversible »."))
    if not a:
        return
    if int(a.get("inactive_count") or 0):
        n = int(a["inactive_count"])
        c.add(Finding("ad.inactive_users", SEC, MAJOR if n > 20 else MINOR, f"{n} compte(s) utilisateur actif(s) inutilisé(s) depuis 90 jours",
                      detail=", ".join(a.get("inactive") or []) + (" …" if n > 25 else ""),
                      impact="Comptes d'anciens salariés ou de prestataires encore utilisables : porte d'entrée discrète pour un attaquant.",
                      fix="Désactiver les comptes inutilisés après validation avec le client, puis les supprimer après un délai."))
    for key, fid, sev, title, impact, fix in (
        ("not_required", "ad.pwd_not_required", MAJOR, "Comptes autorisés à avoir un mot de passe vide",
         "Ces comptes peuvent avoir un mot de passe vide et donner accès au domaine sans authentification.",
         "Set-ADUser <compte> -PasswordNotRequired $false, puis définir un mot de passe robuste."),
        ("preauth", "ad.asrep", MAJOR, "Comptes sans pré-authentification Kerberos",
         "Un attaquant peut récupérer une empreinte de leur mot de passe sans aucun identifiant et la casser hors ligne (AS-REP roasting).",
         "Décocher « La pré-authentification Kerberos n'est pas nécessaire » sur ces comptes."),
        ("reversible", "ad.reversible", MAJOR, "Comptes avec mot de passe stocké de façon réversible",
         "Le mot de passe en clair peut être extrait de l'annuaire.", "Décocher l'option puis changer le mot de passe de ces comptes."),
        ("spn_admin", "ad.kerberoast", MAJOR, "Comptes à privilèges exposés au « Kerberoasting »",
         "Tout utilisateur du domaine peut obtenir une empreinte du mot de passe de ces comptes privilégiés et la casser hors ligne.",
         "Retirer les privilèges ou le SPN, ou utiliser des comptes de service gérés (gMSA) avec mot de passe long et aléatoire.")):
        lst = a.get(key) or []
        if lst:
            c.add(Finding(fid, SEC, sev, f"{title} ({len(lst)})", detail=", ".join(lst), impact=impact, fix=fix))
    age = _age(c, a.get("krbtgt_pwd"))
    if age is not None and age > 180:
        c.add(Finding("ad.krbtgt", SEC, MAJOR if age > 3 * 365 else MINOR, f"Mot de passe du compte krbtgt inchangé depuis {age // 365 or age} "
                      + ("an(s)" if age >= 365 else "jours"),
                      detail=f"Dernier changement : {fr_date(parse_dt(a.get('krbtgt_pwd')))}.",
                      impact="Après une compromission passée, des « golden tickets » forgés avec l'ancienne clé restent valables.",
                      fix="Réinitialiser deux fois le mot de passe krbtgt (script New-KrbtgtKeys de Microsoft), avec au moins 10 heures d'intervalle."))
    age = _age(c, a.get("admin_pwd"))
    if a.get("admin_enabled") and age is not None and age > 365:
        c.add(Finding("ad.admin_pwd", SEC, MINOR, f"Mot de passe du compte « {a.get('admin_name')} » (administrateur intégré) inchangé depuis {age // 365} an(s)",
                      impact="Compte connu de tous les attaquants, aux pleins pouvoirs sur le domaine.",
                      fix="Changer son mot de passe (long, conservé dans un coffre) et utiliser des comptes d'administration nominatifs."))
    da = a.get("domain_admins")
    if da is not None and len(da) > 4:
        c.add(Finding("ad.domain_admins", SEC, MAJOR if len(da) > 10 else MINOR, f"{len(da)} membres dans « Admins du domaine »",
                      detail=", ".join(da[:20]),
                      impact="Chaque compte de ce groupe contrôle tout le domaine : plus il y en a, plus le risque de compromission est élevé.",
                      fix="Limiter le groupe à 2 ou 3 comptes d'administration nominatifs, dédiés et non utilisés pour la messagerie ou la navigation."))
    sa = a.get("schema_admins") or []
    if sa:
        c.add(Finding("ad.schema_admins", SEC, MINOR, f"Groupe « Administrateurs du schéma » non vide ({len(sa)})", detail=", ".join(sa),
                      fix="Vider ce groupe ; n'y ajouter un compte que le temps d'une modification du schéma."))
    n = int(a.get("computers_inactive_count") or 0)
    if n:
        c.add(Finding("ad.inactive_computers", SVC, MINOR, f"{n} ordinateur(s) inactif(s) depuis 90 jours dans l'annuaire",
                      detail=", ".join(a.get("computers_inactive") or []) + (" …" if n > 25 else ""),
                      fix="Désactiver puis supprimer les comptes d'ordinateurs qui n'existent plus."))
    n = int(a.get("old_os_count") or 0)
    if n:
        c.add(Finding("ad.old_os", SEC, MAJOR, f"{n} ordinateur(s) du domaine sous un Windows plus supporté",
                      detail=", ".join(a.get("old_os") or []) + (" …" if n > 25 else ""),
                      impact="Ces machines ne reçoivent plus de correctifs : point d'entrée idéal pour un rançongiciel sur le réseau.",
                      fix="Remplacer ou mettre à niveau ces machines ; à défaut, les isoler du reste du réseau."))
    comp = int(a.get("computers") or 0)
    laps = int(a.get("laps_count") or 0)
    if comp > 5 and laps == 0:
        c.add(Finding("ad.laps", SEC, MAJOR, "LAPS non déployé sur le domaine",
                      detail=f"Aucun des {comp} ordinateurs actifs n'a de mot de passe administrateur local géré par LAPS.",
                      impact="Le même mot de passe administrateur local est souvent réutilisé partout : un poste compromis donne accès à tous les autres.",
                      fix="Déployer Windows LAPS par stratégie de groupe (intégré à Windows depuis avril 2023)."))
    elif comp > 5 and laps < comp * 0.5:
        c.add(Finding("ad.laps_partial", SEC, MINOR, f"LAPS déployé sur {laps} ordinateur(s) sur {comp}",
                      fix="Étendre la stratégie LAPS à toutes les unités d'organisation contenant des ordinateurs."))


# ---------------------------------------------------------------- DNS, DHCP
def dns_server(c: Ctx):
    d = c.get("roles", "dns_server")
    if not d:
        return
    down = d.get("forwarders_down") or []
    if down:
        c.add(Finding("dns.forwarders", SVC, MAJOR if len(down) == len(d.get("forwarders") or []) else MINOR,
                      "Redirecteur(s) DNS ne répondant pas : " + ", ".join(down),
                      detail="Redirecteurs configurés : " + sjoin(", ", d.get("forwarders")) + ".",
                      impact="Résolution des noms Internet lente ou impossible pour tous les postes qui utilisent ce serveur.",
                      fix="Remplacer les redirecteurs inopérants (DNS du fournisseur d'accès, du pare-feu ou résolveurs publics)."))
    unsafe = [z.get("name") for z in d.get("zones") or [] if (z.get("dynamic") or "").lower() == "nonsecureandsecure"]
    if unsafe:
        c.add(Finding("dns.unsecure", SVC, MAJOR, "Zone(s) DNS acceptant les mises à jour non sécurisées",
                      detail=", ".join(unsafe),
                      impact="N'importe quel appareil du réseau peut créer ou remplacer un enregistrement (usurpation d'un serveur).",
                      fix="Passer les zones intégrées à Active Directory en « Sécurisé uniquement »."))
    if d.get("scavenging") is False:
        c.add(Finding("dns.scavenging", SVC, MINOR, "Nettoyage des enregistrements DNS obsolètes désactivé",
                      impact="Les anciens enregistrements s'accumulent : un nom peut pointer vers une adresse attribuée depuis à un autre appareil.",
                      fix="Activer le vieillissement sur les zones et le nettoyage sur un serveur DNS (7 jours / 7 jours)."))
    errs = d.get("errors") or []
    n = sum(int(g.get("count") or 0) for g in errs)
    if n:
        c.add(Finding("dns.errors", SVC, MAJOR if n >= 20 else MINOR, f"Erreurs du serveur DNS sur 14 jours : {n}", evidence=_events_text(errs),
                      fix="Analyser les événements du journal « DNS Server »."))


def dhcp(c: Ctx):
    d = c.get("roles", "dhcp")
    if not d:
        return
    for s in d.get("scopes") or []:
        if (s.get("state") or "").lower() != "active" or s.get("pct") is None:
            continue
        pct = float(s.get("pct") or 0)
        if pct >= 85:
            c.add(Finding(f"dhcp.full.{s.get('id')}", SVC, MAJOR if pct >= 95 else MINOR,
                          f"Étendue DHCP « {s.get('name') or s.get('id')} » occupée à {pct:.0f} %",
                          detail=f"{s.get('in_use')} adresse(s) attribuée(s), {s.get('free')} libre(s) ; bail de {s.get('lease_h'):.0f} h.",
                          impact="Les nouveaux appareils n'obtiendront plus d'adresse IP et ne pourront pas se connecter au réseau.",
                          fix="Agrandir l'étendue, réduire la durée du bail (réseau invité) ou supprimer les réservations inutiles.",
                          predictive=pct < 100))
    fo = [f for f in d.get("failover") or [] if (f.get("state") or "").lower() != "normal"]
    if fo:
        c.add(Finding("dhcp.failover", SVC, MAJOR, "Basculement DHCP dégradé",
                      detail="; ".join(f"{f.get('name')} avec {f.get('partner')} : {f.get('state')}" for f in fo),
                      impact="En cas de panne d'un serveur, l'autre ne prendra pas le relais correctement.",
                      fix="Vérifier la communication entre partenaires et l'heure des deux serveurs ; recréer la relation si besoin."))
    if d.get("authorized") is False and c.in_domain:
        c.add(Finding("dhcp.unauthorized", SVC, MAJOR, "Serveur DHCP non autorisé dans Active Directory",
                      impact="Le service DHCP refuse de distribuer des adresses tant qu'il n'est pas autorisé.",
                      fix="Autoriser le serveur dans la console DHCP (clic droit sur le serveur › Autoriser)."))


# ---------------------------------------------------------------- Hyper-V
def hyperv(c: Ctx):
    h = c.get("roles", "hyperv")
    if not h:
        return
    vms = h.get("vms") or []
    old_cp = [(v, _age(c, v.get("oldest_cp"))) for v in vms if v.get("checkpoints")]
    old_cp = [(v, a) for v, a in old_cp if a is not None and a > 7]
    if old_cp:
        worst = max(a for _v, a in old_cp)
        c.add(Finding("hv.checkpoints", SVC, MAJOR if worst > 30 else MINOR, f"Points de contrôle anciens sur {len(old_cp)} machine(s) virtuelle(s)",
                      detail="; ".join(f"{v.get('name')} : {v.get('checkpoints')} point(s), le plus ancien il y a {a} jours" for v, a in old_cp[:8]),
                      impact="Les disques de différenciation grossissent sans fin, ralentissent la VM et peuvent saturer le stockage ; "
                             "un point de contrôle n'est pas une sauvegarde.",
                      fix="Supprimer les points de contrôle inutiles (la fusion se fait en arrière-plan) ; vérifier qu'un logiciel de sauvegarde "
                          "n'en laisse pas derrière lui.", predictive=True))
    hb = [v.get("name") for v in vms if v.get("state") == "Running" and v.get("heartbeat")
          and not v["heartbeat"].lower().startswith("ok")]
    if hb:
        c.add(Finding("hv.heartbeat", SVC, MINOR, "Machines virtuelles qui ne répondent pas à l'hôte : " + ", ".join(hb),
                      impact="Système invité bloqué ou services d'intégration absents : arrêt propre et sauvegarde cohérente impossibles.",
                      fix="Vérifier l'état de la VM et installer / mettre à jour les services d'intégration."))
    repl = [(v.get("name"), v.get("repl")) for v in vms if (v.get("repl") or "").lower() in ("critical", "warning")]
    if repl:
        c.add(Finding("hv.replica", SVC, MAJOR if any(r[1].lower() == "critical" for r in repl) else MINOR,
                      "Réplication Hyper-V dégradée", detail="; ".join(f"{n} : {s}" for n, s in repl),
                      impact="Le site de secours n'est plus à jour.", fix="Consulter l'état de réplication (Measure-VMReplication) et la reprendre."))
    # disques dynamiques : croissance possible au-delà de l'espace libre
    free = {(v.get("letter") or "").upper(): int(v.get("free") or 0) for v in c.lst("disks", "volumes") if v.get("letter")}
    grow: dict[str, int] = {}
    for d in h.get("vhds") or []:
        if (d.get("type") or "").lower() in ("dynamic", "differencing") and d.get("max") and d.get("file") is not None:
            vol = (d.get("path") or "")[:2].upper()
            grow[vol] = grow.get(vol, 0) + max(0, int(d["max"]) - int(d["file"]))
    for vol, g in grow.items():
        if vol in free and g > free[vol]:
            c.add(Finding(f"hv.overcommit.{vol}", SVC, MAJOR, f"Disques virtuels dynamiques pouvant saturer le volume {vol}",
                          detail=f"Les disques dynamiques peuvent encore grossir de {human_bytes(g)} alors qu'il reste {human_bytes(free[vol])} libres.",
                          impact="Si le volume se remplit, toutes les machines virtuelles qu'il héberge se mettent en pause.",
                          fix="Ajouter de l'espace, déplacer des VM, ou surveiller l'espace libre de près.", predictive=True))
    errs = h.get("errors") or []
    n = sum(int(g.get("count") or 0) for g in errs)
    if n:
        c.add(Finding("hv.errors", SVC, MINOR, f"Erreurs Hyper-V sur 14 jours : {n}", evidence=_events_text(errs),
                      fix="Analyser le journal « Hyper-V-VMMS-Admin »."))
    if vms:
        run = sum(1 for v in vms if v.get("state") == "Running")
        c.add(Finding("hv.info", SVC, INFO, f"Hyper-V : {len(vms)} machine(s) virtuelle(s), {run} démarrée(s)",
                      detail=", ".join(f"{v.get('name')} ({v.get('state')})" for v in vms[:15])))


# ---------------------------------------------------------------- SQL Server, IIS
def sql(c: Ctx):
    for i in c.lst("roles", "sql"):
        ver = str(i.get("patch") or i.get("version") or "")
        major = ver.split(".")[0] if ver else ""
        key = "10.50" if ver.startswith("10.50") else major
        name = f"{i.get('instance')}"
        if key in SQL_EOL:
            label, end = SQL_EOL[key]
            days = (end - c.now.date()).days
            if days < 0:
                c.add(Finding(f"sql.eol.{name}", SVC, MAJOR, f"{label} plus supporté (instance {name})",
                              detail=f"Version {ver}, édition {i.get('edition')} ; fin de support le {end:%d/%m/%Y}.",
                              impact="Plus aucun correctif de sécurité pour le moteur de base de données.",
                              fix="Migrer les bases vers une version supportée de SQL Server."))
            elif days < 365:
                c.add(Finding(f"sql.eol.{name}", SVC, MINOR, f"{label} : fin de support le {end:%d/%m/%Y} (instance {name})",
                              detail=f"Version {ver}, édition {i.get('edition')}.", fix="Planifier la migration vers une version récente.",
                              predictive=True))
        if "express" in (i.get("edition") or "").lower():
            big = [f for f in i.get("mdf") or [] if int(f.get("bytes") or 0) >= 8 * 1024 ** 3]
            for f in big:
                sz = int(f["bytes"])
                c.add(Finding(f"sql.express_limit.{name}.{f.get('name')}", SVC, CRIT if sz >= 9.5 * 1024 ** 3 else MAJOR,
                              f"Base « {f.get('name')} » proche de la limite de SQL Express ({human_bytes(sz)} sur 10 Go)",
                              detail=f"Instance {name}, édition {i.get('edition')}.",
                              impact="À 10 Go, la base ne peut plus grossir : le logiciel métier s'arrête avec des erreurs d'écriture.",
                              fix="Purger / archiver les données, ou passer à SQL Server Standard.", predictive=True))
            c.add(Finding(f"sql.express_backup.{name}", SVC, INFO, f"SQL Server Express ({name}) : pas d'agent de sauvegarde intégré",
                          detail="L'édition Express ne dispose pas de l'Agent SQL : aucune sauvegarde planifiée n'est possible depuis SQL Server lui-même.",
                          fix="Vérifier que les bases sont sauvegardées par un script planifié ou par le logiciel de sauvegarde (avec prise en charge SQL)."))
        mdf = {re.sub(r"(_data)?\.mdf$", "", f.get("name") or "", flags=re.I).lower(): int(f.get("bytes") or 0) for f in i.get("mdf") or []}
        for f in i.get("ldf") or []:
            sz = int(f.get("bytes") or 0)
            base = re.sub(r"(_log)?\.ldf$", "", f.get("name") or "", flags=re.I).lower()
            if sz > 10 * 1024 ** 3 and sz > 2 * mdf.get(base, 0):
                c.add(Finding(f"sql.log.{name}.{f.get('name')}", SVC, MINOR, f"Journal de transactions très volumineux : {f.get('name')} ({human_bytes(sz)})",
                              detail=f"Instance {name}. Base de données : {human_bytes(mdf.get(base))}.",
                              impact="En mode de récupération complet sans sauvegarde du journal, il grossit jusqu'à saturer le disque.",
                              fix="Planifier des sauvegardes du journal de transactions, ou passer la base en mode de récupération simple si adapté."))


def iis(c: Ctx):
    i = c.get("roles", "iis")
    if i and int(i.get("log_bytes") or 0) > 5 * 1024 ** 3:
        c.add(Finding("iis.logs", SVC, MINOR, f"Journaux IIS jamais purgés : {human_bytes(i.get('log_bytes'))}",
                      detail=f"{i.get('log_files')} fichier(s), le plus ancien du {fr_date(parse_dt(i.get('oldest')))}.",
                      impact="Les journaux finissent par remplir le disque système.",
                      fix="Planifier une suppression des journaux de plus de 90 jours (tâche planifiée ou script).", predictive=True))


# ---------------------------------------------------------------- sauvegardes
def _backup_products(names) -> list[str]:
    """Regroupe les composants d'un même éditeur (plug-ins, consoles, explorateurs, services)."""
    out: dict[str, str] = {}
    for n in sorted(names):
        m = BACKUP_SW.search(n)
        key = m.group(0).lower() if m else n.lower()
        short = re.sub(r"\s*\(.*?\)|\s+v?\d[\d.]*$", "", n).strip()
        noisy = re.search(r"plug-?in|explorer|console|extract|redistributable|mount|transport|catalog|\bservice\b|"
                          r"agent for|\bapi\b|proxy|installer|data analyzer", short, re.I)
        if key not in out or (not noisy and (out[key] is None or len(short) < len(out[key]))):
            out[key] = None if noisy else short
    return [v or k.title() for k, v in out.items()][:6]


def backups(c: Ctx):
    if not c.section("backup"):
        return
    errs = c.errors()
    soft = {s.get("name") for s in c.lst("software", "software") if BACKUP_SW.search(s.get("name") or "")}
    svcs = c.lst("backup", "backup_services")
    found = set(soft)
    for s in svcs:
        if BACKUP_SW.search(f"{s.get('name')} {s.get('display')}"):
            found.add(s.get("display") or s.get("name"))
    features = (c.get("software", "features") or {}).get("server_features") or []
    wsb = c.get("backup", "wsb")
    # --- Sauvegarde Windows Server
    if wsb and (wsb.get("policy") or _age(c, wsb.get("last_success")) is not None):
        found.add("Sauvegarde Windows Server")
        age = _age(c, wsb.get("last_success"))
        if age is None:
            c.add(Finding("bk.wsb.never", SVC, CRIT, "Sauvegarde Windows Server : aucune sauvegarde réussie",
                          detail=f"Une planification existe mais aucune sauvegarde n'a abouti. {wsb.get('message') or ''}".strip(),
                          impact="Aucune restauration possible en cas de panne, d'erreur ou de rançongiciel.",
                          fix="Lancer une sauvegarde manuelle, lire l'erreur et vérifier le disque ou le partage de destination."))
        elif age > 2:
            c.add(Finding("bk.wsb.age", SVC, CRIT if age > 7 else MAJOR, f"Dernière sauvegarde Windows Server réussie il y a {age} jours",
                          detail=f"Le {fr_date(parse_dt(wsb.get('last_success')))} ; {wsb.get('versions')} version(s) disponible(s).",
                          impact=f"Toutes les modifications des {age} derniers jours seraient perdues en cas de sinistre.",
                          fix="Vérifier la planification, le disque de destination (présent, pas plein) et le journal « Microsoft-Windows-Backup »."))
        else:
            c.add(Finding("bk.wsb.ok", SVC, OK, f"Sauvegarde Windows Server réussie le {fr_date(parse_dt(wsb.get('last_success')))}"))
        if int(wsb.get("last_result") or 0) != 0:
            c.add(Finding("bk.wsb.failed", SVC, MAJOR, f"Dernière sauvegarde Windows Server en échec (code 0x{int(wsb['last_result']) & 0xFFFFFFFF:08X})",
                          detail=wsb.get("message") or "", fix="Lire le détail dans la console Sauvegarde Windows Server et corriger la cause."))
    elif not wsb and "Windows-Server-Backup" in features and "wsb" in errs and DENIED.search(errs["wsb"]):
        c.not_checked("nc.wsb", SVC, "État de la Sauvegarde Windows Server")
    # --- Veeam
    ve = c.lst("backup", "veeam")
    if ve:
        found.add("Veeam")
        ev = sorted(ve, key=lambda e: e.get("date") or "")
        last = ev[-1]
        succ = [e for e in ev if int(e.get("level") or 4) in (0, 3, 4)]
        age = _age(c, succ[-1].get("date")) if succ else None
        if int(last.get("level") or 4) in (1, 2):
            c.add(Finding("bk.veeam.failed", SVC, MAJOR, "Dernier travail de sauvegarde Veeam en échec",
                          detail=f"Le {fr_date(parse_dt(last.get('date')))} : {last.get('message') or ''}",
                          impact="La sauvegarde la plus récente n'est pas exploitable.",
                          fix="Ouvrir la console Veeam, lire l'erreur du travail et relancer la sauvegarde."))
        if age is None:
            c.add(Finding("bk.veeam.none", SVC, CRIT, "Veeam : aucune sauvegarde réussie depuis 60 jours",
                          fix="Vérifier la configuration des travaux et la destination de sauvegarde."))
        elif age > 2:
            c.add(Finding("bk.veeam.age", SVC, CRIT if age > 7 else MAJOR, f"Dernière sauvegarde Veeam réussie il y a {age} jours",
                          detail=f"Dernier travail terminé (événement 190) le {fr_date(parse_dt(last.get('date')))} : "
                                 f"{(last.get('message') or '').strip()[:160]}",
                          impact=f"Toutes les modifications des {age} derniers jours seraient perdues en cas de sinistre.",
                          fix="Vérifier la planification et l'état des travaux dans la console Veeam."))
        else:
            c.add(Finding("bk.veeam.ok", SVC, OK, f"Veeam : dernière sauvegarde réussie le {fr_date(parse_dt(succ[-1].get('date')))}"))
    # --- erreurs des logiciels de sauvegarde dans le journal Application
    groups = [g for g in c.lst("events", "application_errors") if BACKUP_PROV.search(g.get("provider") or "")]
    n = c.count_since(groups, 14)
    if n:
        provs = sorted({g.get("provider") for g in groups})
        c.add(Finding("bk.errors", SVC, MAJOR if n >= 3 else MINOR, f"Erreurs du logiciel de sauvegarde sur 14 jours : {n}",
                      detail="Source(s) : " + ", ".join(provs) + ".", evidence=_events_text(groups),
                      impact="Des sauvegardes échouent peut-être sans que personne ne s'en aperçoive.",
                      fix="Vérifier le rapport du dernier travail dans la console du logiciel de sauvegarde."))
    # --- services de sauvegarde arrêtés
    stopped = [s.get("display") or s.get("name") for s in svcs
               if (s.get("start") or "").lower() == "auto" and s.get("state") != "Running" and (s.get("name") or "").lower() != "wbengine"]
    if stopped:
        c.add(Finding("bk.service", SVC, MAJOR, "Service de sauvegarde arrêté : " + ", ".join(stopped[:5]),
                      impact="Les sauvegardes planifiées ne s'exécutent pas.", fix="Démarrer le service et vérifier pourquoi il s'est arrêté."))
    # --- aucune solution détectée
    found.discard(None)
    if not found:
        if c.is_server:
            c.add(Finding("bk.none", SVC, MINOR if c.is_vm else MAJOR, "Aucune solution de sauvegarde détectée sur ce serveur",
                          detail="Ni Sauvegarde Windows Server ni logiciel de sauvegarde connu n'ont été trouvés"
                                 + (" ; s'agissant d'une machine virtuelle, elle est peut-être sauvegardée depuis l'hyperviseur : à confirmer."
                                    if c.is_vm else " (la sauvegarde peut aussi être faite depuis un NAS ou une autre machine : à confirmer)."),
                          impact="Sans sauvegarde, une panne disque, une erreur ou un rançongiciel entraîne une perte définitive des données.",
                          fix="Mettre en place une sauvegarde quotidienne avec au moins une copie hors site ou déconnectée (règle 3-2-1)."))
        else:
            c.add(Finding("bk.none", SVC, INFO, "Aucun logiciel de sauvegarde détecté sur ce poste",
                          detail="Les données sont peut-être sauvegardées ailleurs (OneDrive, serveur de fichiers) : à confirmer avec l'utilisateur."))
    else:
        c.add(Finding("bk.info", SVC, INFO, "Solution(s) de sauvegarde détectée(s) : " + ", ".join(_backup_products(found))))
    # --- clichés instantanés (versions précédentes) des volumes partagés
    if c.is_server:
        shares = c.lst("security", "shares")
        share_vols = {(s.get("path") or "")[:2].upper() for s in shares if s.get("path")}
        share_vols.discard("")
        sh = {(s.get("volume") or "").upper().rstrip("\\"): s for s in c.lst("backup", "shadows")}
        if share_vols and "shadows" not in errs:
            missing = sorted(v for v in share_vols if v not in sh)
            if missing:
                c.add(Finding("bk.shadows", SVC, MINOR, "Pas de clichés instantanés sur les volumes partagés : " + ", ".join(missing),
                              impact="Les utilisateurs ne peuvent pas restaurer eux-mêmes une version précédente d'un fichier écrasé ou supprimé.",
                              fix="Activer les clichés instantanés sur ces volumes (2 par jour, sur un volume distinct si possible). "
                                  "Ce n'est pas une sauvegarde, mais un complément très utile."))
            stale = [f"{v} (dernier le {fr_date(parse_dt(sh[v].get('newest')))})" for v in share_vols
                     if v in sh and (_age(c, sh[v].get("newest")) or 0) > 7]
            if stale:
                c.add(Finding("bk.shadows_old", SVC, MINOR, "Clichés instantanés qui ne se créent plus : " + ", ".join(stale),
                              fix="Vérifier la tâche planifiée « ShadowCopyVolume » et l'espace réservé aux clichés."))
        elif share_vols and "shadows" in errs and DENIED.search(errs["shadows"]):
            c.not_checked("nc.shadows", SVC, "Clichés instantanés des volumes partagés")


RULES = [domain_controller, dns_server, dhcp, hyperv, sql, iis, backups]
