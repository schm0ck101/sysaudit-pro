"""Règles « Sécurité » (inspirées des recommandations ANSSI et des bonnes
pratiques Microsoft) : antivirus, pare-feu, chiffrement, protocoles
obsolètes, comptes, accès distants, certificats, logiciels vulnérables."""
from __future__ import annotations

import re

from .context import DENIED, Ctx
from .eol import REMOTE_ACCESS, SOFTWARE_RULES, version_lt
from .model import CRIT, INFO, MAJOR, MINOR, OK, SEC, Finding, fr_date, parse_dt

EVERYONE = {"everyone", "tout le monde", "jeder", "todos", "tutti", "iedereen"}
AV_SERVICES = re.compile(r"^(SentinelAgent|CSFalconService|ekrn|SAVService|Sophos.*|WRSVC|bdservicehost|EPSecurityService|"
                         r"MBAMService|TMBMServer|ntrtscan|mcshield|masvc|AVP.*|klnagent|CylanceSvc|CbDefense|"
                         r"cyserver|xagt|Harfanglab.*|hurukai.*|WithSecure.*|fsdevcon|SepMasterService|ccSvcHst|"
                         r"AvastSvc|AVGSvc|avgsvc|NortonSecurity|WinDefend)$", re.I)


def _svc_running(c: Ctx, pattern) -> list[str]:
    return [s.get("display") or s.get("name") for s in c.lst("software", "services")
            if (s.get("state") == "Running") and pattern.match(s.get("name") or "")]


def antivirus(c: Ctx):
    products = c.lst("security", "av_products")
    d = c.get("security", "defender") or {}
    enabled, outdated = [], []
    for p in products:
        # productState = 0xTTSSDD : SS = état du moteur (0x10/0x11 actif), DD = signatures (0x00 à jour, 0x10 périmées)
        st = int(p.get("state") or 0)
        on = ((st >> 8) & 0xFF) in (0x10, 0x11)
        late = (st & 0xFF) != 0
        if on:
            enabled.append(p.get("name"))
            if late:
                outdated.append(p.get("name"))
    third = [n for n in _svc_running(c, AV_SERVICES) if "defender" not in (n or "").lower()]
    def_on = bool(d.get("realtime")) and bool(d.get("antivirus"))
    if not enabled and not def_on and not third:
        c.add(Finding("av.none", SEC, CRIT, "Aucune protection antivirus active",
                      detail="Ni Microsoft Defender (protection en temps réel) ni un autre antivirus actif n'ont été détectés.",
                      impact="Le poste est exposé aux logiciels malveillants et rançongiciels.",
                      fix="Réactiver Microsoft Defender ou installer / réparer la solution antivirus de l'entreprise."))
        return
    if outdated:
        c.add(Finding("av.outdated", SEC, MAJOR, "Antivirus non à jour : " + ", ".join(outdated),
                      detail="Le Centre de sécurité Windows signale des signatures obsolètes.",
                      impact="Les menaces récentes ne sont pas détectées.", fix="Forcer la mise à jour de l'antivirus et vérifier son accès à Internet."))
    if def_on:
        age = d.get("sig_age")
        if age is not None and 2 < age < 100000:
            c.add(Finding("av.defender_sig", SEC, MAJOR if age > 7 else MINOR, f"Signatures Defender vieilles de {age} jours",
                          impact="Les menaces récentes ne sont pas détectées.",
                          fix="Lancer une mise à jour des définitions (Sécurité Windows › Mises à jour de la protection)."))
        if d.get("tamper") is False and not c.is_server:
            c.add(Finding("av.tamper", SEC, MINOR, "Protection contre les falsifications de Defender désactivée",
                          impact="Un logiciel malveillant peut désactiver l'antivirus.",
                          fix="Activer « Protection contre les falsifications » dans Sécurité Windows."))
    names = enabled or (["Microsoft Defender"] if def_on else []) + third
    if not outdated:
        c.add(Finding("av.ok", SEC, OK, "Protection antivirus active : " + ", ".join(dict.fromkeys(n for n in names if n))))
    threats = c.lst("security", "defender_threats")
    if threats:
        failed = [t for t in threats if not t.get("action_ok")]
        c.add(Finding("av.threats", SEC, CRIT if failed else MINOR, f"Menaces détectées sur 30 jours : {len(threats)}",
                      detail="; ".join(f"{t.get('name') or t.get('id')} le {fr_date(parse_dt(t.get('date')))}" for t in threats[:6]),
                      impact="Le poste a été exposé à des logiciels malveillants" + (" et certaines menaces n'ont pas pu être supprimées." if failed else "."),
                      fix="Lancer une analyse complète hors ligne (Microsoft Defender Offline) et rechercher l'origine de l'infection."))


def firewall(c: Ctx):
    prof = c.lst("security", "firewall")
    if not prof:
        return
    off = [p["name"] for p in prof if str(p.get("enabled")).lower() not in ("true", "1")]
    third = [p.get("name") for p in c.lst("security", "fw_products")]
    if off and not third:
        c.add(Finding("fw.off", SEC, CRIT if "Public" in off else MAJOR, "Pare-feu Windows désactivé : profil(s) " + ", ".join(off),
                      impact="Les services du poste sont exposés à tout le réseau (propagation de rançongiciels, attaques internes).",
                      fix="Réactiver le pare-feu sur tous les profils et créer des règles d'autorisation ciblées si besoin."))
    else:
        c.add(Finding("fw.ok", SEC, OK, "Pare-feu actif sur tous les profils" if not off else "Pare-feu tiers actif : " + ", ".join(third)))


def encryption(c: Ctx):
    vols = c.lst("security", "bitlocker")
    errs = c.errors()
    if not vols:
        if "bitlocker" in errs and DENIED.search(errs["bitlocker"]):
            c.not_checked("nc.bitlocker", SEC, "Chiffrement des disques (BitLocker)")
        return
    sysd = (c.os.get("system_drive") or "C:").upper()
    for v in vols:
        if (v.get("letter") or "").upper() != sysd:
            continue
        if int(v.get("protection") or 0) != 1:
            sev = MAJOR if c.is_laptop else MINOR if not c.is_server else INFO
            c.add(Finding("bl.system", SEC, sev, f"Disque système non chiffré ({sysd})",
                          detail="BitLocker n'est pas actif sur le volume système.",
                          impact="En cas de vol ou de perte" + (" de cet ordinateur portable" if c.is_laptop else "") +
                                 ", toutes les données sont lisibles en retirant le disque.",
                          fix="Activer BitLocker (avec TPM) et sauvegarder la clé de récupération dans l'annuaire ou un coffre."))
        else:
            c.add(Finding("bl.ok", SEC, OK, f"Disque système chiffré par BitLocker ({sysd})"))


def protocols(c: Ctx):
    r = c.get("security", "registry") or {}
    smb = c.get("security", "smb_server") or {}
    if smb.get("smb1") or r.get("smb1_server") == 1 or (r.get("smb1_client_start") not in (None, 4)):
        c.add(Finding("proto.smb1", SEC, CRIT, "Protocole SMBv1 activé",
                      detail="Le protocole de partage de fichiers SMB version 1 est actif (serveur ou client).",
                      impact="Protocole obsolète exploité par les rançongiciels WannaCry et NotPetya.",
                      fix="Désactiver SMBv1 : « Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol ». "
                          "Remplacer les appareils qui l'exigent encore (vieux NAS, copieurs)."))
    else:
        c.add(Finding("proto.smb1.ok", SEC, OK, "SMBv1 désactivé"))
    signing = smb.get("signing_required") if smb else (r.get("smb_server_signing") == 1)
    if signing is False or (not smb and r.get("smb_server_signing") in (0,)):
        c.add(Finding("proto.smb_signing", SEC, MAJOR if c.is_server else MINOR, "Signature SMB non exigée",
                      detail="Le serveur SMB de ce poste accepte des échanges non signés.",
                      impact="Permet des attaques par relais NTLM sur le réseau local.",
                      fix="Exiger la signature SMB par stratégie de groupe (« Serveur réseau Microsoft : signer numériquement les "
                          "communications (toujours) »)."))
    if r.get("wdigest") == 1:
        c.add(Finding("proto.wdigest", SEC, CRIT, "Mots de passe conservés en clair en mémoire (WDigest)",
                      detail="UseLogonCredential = 1.", impact="Un attaquant peut extraire les mots de passe en clair des sessions ouvertes (Mimikatz).",
                      fix="Mettre UseLogonCredential à 0 (HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest)."))
    lm = r.get("lm_compat")
    if lm is not None and int(lm) < 3:
        c.add(Finding("proto.ntlmv1", SEC, MAJOR, "Authentification LM/NTLMv1 autorisée",
                      detail=f"LmCompatibilityLevel = {lm}.", impact="Ces protocoles se cassent en quelques minutes.",
                      fix="Régler « Sécurité réseau : niveau d'authentification LAN Manager » sur « NTLMv2 uniquement, refuser LM et NTLM » (5)."))
    if r.get("no_lm_hash") == 0:
        c.add(Finding("proto.lmhash", SEC, MAJOR, "Stockage des empreintes LM autorisé",
                      fix="Activer « Ne pas stocker de valeurs de hachage de niveau LAN Manager »."))
    if r.get("llmnr") != 0:
        nb = [n for n in c.lst("network", "netbios") if int(n.get("netbios") or 0) != 2]
        c.add(Finding("proto.llmnr", SEC, MINOR, "Résolution de noms LLMNR / NetBIOS active",
                      detail="LLMNR n'est pas désactivé par stratégie" + (f" et NetBIOS est actif sur {len(nb)} carte(s)." if nb else "."),
                      impact="Un attaquant sur le réseau local peut répondre à la place des serveurs et capturer des empreintes de mots de passe (Responder).",
                      fix="Désactiver LLMNR (GPO « Désactiver la résolution de noms multidiffusion ») et NetBIOS sur TCP/IP."))
    if c.is_server:
        if r.get("ssl3_server") == 1:
            c.add(Finding("proto.ssl3", SEC, MAJOR, "SSL 3.0 activé côté serveur", fix="Désactiver SSL 3.0 (registre SCHANNEL)."))
        if c.build < 26100 and r.get("tls10_server") not in (0,):
            c.add(Finding("proto.tls10", SEC, MINOR, "TLS 1.0 / 1.1 non désactivés côté serveur",
                          impact="Protocoles obsolètes, refusés par les référentiels de sécurité actuels.",
                          fix="Désactiver TLS 1.0 et 1.1 après avoir vérifié la compatibilité des clients (registre SCHANNEL ou IIS Crypto)."))


def hardening(c: Ctx):
    r = c.get("security", "registry") or {}
    if r.get("uac_lua") == 0:
        c.add(Finding("uac.off", SEC, CRIT, "Contrôle de compte d'utilisateur (UAC) désactivé",
                      impact="Tout programme lancé par un administrateur obtient tous les droits sans confirmation.",
                      fix="Réactiver l'UAC (EnableLUA = 1) puis redémarrer."))
    elif r.get("uac_admin_prompt") == 0:
        c.add(Finding("uac.silent", SEC, MAJOR, "UAC en élévation silencieuse pour les administrateurs",
                      detail="ConsentPromptBehaviorAdmin = 0.", impact="Les élévations de privilèges se font sans aucune confirmation.",
                      fix="Rétablir la demande de consentement (valeur 5 par défaut)."))
    if r.get("autologon") in ("1", 1) and r.get("autologon_password_set"):
        c.add(Finding("acct.autologon", SEC, CRIT, "Ouverture de session automatique avec mot de passe stocké",
                      detail=f"Compte : {r.get('autologon_user') or '?'} ; le mot de passe est enregistré dans le registre (lisible).",
                      impact="Le mot de passe est récupérable par toute personne ayant accès au poste ; la session s'ouvre sans contrôle.",
                      fix="Désactiver l'ouverture automatique (netplwiz) ou utiliser un compte kiosque dédié sans privilèges, et changer ce mot de passe."))
    if r.get("rdp_deny") == 0:
        if r.get("rdp_nla") == 0:
            c.add(Finding("rdp.nla", SEC, MAJOR, "Bureau à distance ouvert sans authentification réseau (NLA)",
                          detail=f"Bureau à distance activé (port {r.get('rdp_port')}) et NLA désactivée.",
                          impact="L'écran d'ouverture de session est exposé avant toute authentification : attaques par force brute "
                                 "et failles RDP (BlueKeep) facilitées.",
                          fix="Activer « Autoriser uniquement les connexions … avec authentification au niveau du réseau »."))
        else:
            c.add(Finding("rdp.on", SEC, INFO, f"Bureau à distance activé (NLA active, port {r.get('rdp_port')})",
                          detail="S'assurer qu'il n'est pas exposé directement sur Internet (passer par un VPN)."))
    if not c.is_vm:
        sb = c.get("system", "secure_boot") or {}
        if sb.get("enabled") == 0:
            c.add(Finding("boot.secureboot", SEC, MINOR, "Démarrage sécurisé (Secure Boot) désactivé",
                          impact="Le poste peut démarrer un chargeur modifié (bootkit) avant Windows.",
                          fix="Activer Secure Boot dans le firmware UEFI (vérifier d'abord le mode de démarrage UEFI)."))
        elif sb.get("firmware") == 1:
            c.add(Finding("boot.legacy", SEC, MINOR, "Démarrage en mode BIOS hérité (non UEFI)",
                          impact="Pas de Secure Boot possible ; incompatible avec Windows 11.",
                          fix="Convertir le disque en GPT (mbr2gpt) puis passer le firmware en UEFI."))
        tpm = c.get("system", "tpm")
        if tpm is not None and not tpm.get("present"):
            c.add(Finding("boot.tpm", SEC, MINOR, "Aucune puce TPM détectée",
                          impact="BitLocker sans TPM est moins sûr ; Windows 11 exige un TPM 2.0.",
                          fix="Activer le TPM / fTPM / PTT dans le firmware."))
    if r.get("lsa_ppl") not in (1, 2) and not c.is_vm:
        c.add(Finding("lsa.ppl", SEC, MINOR, "Protection du processus LSA non activée",
                      impact="Les outils de vol d'identifiants peuvent lire la mémoire de LSASS.",
                      fix="Activer « RunAsPPL » (protection LSA) après vérification de la compatibilité des pilotes."))
    an = r.get("autorun")
    if an is None or int(an) != 255:
        c.add(Finding("autorun", SEC, MINOR, "Exécution automatique des médias amovibles non désactivée",
                      impact="Une clé USB piégée peut lancer un programme.",
                      fix="Désactiver l'exécution automatique pour tous les lecteurs (NoDriveTypeAutoRun = 255 par GPO)."))
    if r.get("remote_registry") == "Running":
        c.add(Finding("svc.remote_registry", SEC, MINOR, "Service « Registre à distance » démarré",
                      fix="Le passer en démarrage désactivé sauf besoin d'un outil d'administration."))
    spool = r.get("print_spooler")
    if spool == "Running" and c.is_dc:
        c.add(Finding("svc.spooler_dc", SEC, MAJOR, "Spouleur d'impression actif sur un contrôleur de domaine",
                      impact="Vecteur d'attaques connues (PrintNightmare, contrainte d'authentification).",
                      fix="Arrêter et désactiver le service Spouleur d'impression sur les contrôleurs de domaine."))
    if not c.is_server and r.get("inactivity_timeout") in (None, 0) and str(r.get("screen_saver_secure")) != "1":
        c.add(Finding("lock.timeout", SEC, MINOR, "Pas de verrouillage automatique de session",
                      impact="Un poste laissé ouvert reste accessible à tout passant.",
                      fix="Configurer le verrouillage après 10 minutes d'inactivité (GPO « Limite d'inactivité de l'ordinateur »)."))


def accounts(c: Ctx):
    users = c.lst("security", "local_users")
    admins = c.lst("security", "admins")
    for u in users:
        sid = u.get("sid") or ""
        if not u.get("enabled"):
            continue
        if sid.endswith("-501"):
            c.add(Finding("acct.guest", SEC, MAJOR, "Compte Invité activé", fix="Désactiver le compte Invité."))
        elif sid.endswith("-500") and not c.in_domain:
            c.add(Finding("acct.admin500", SEC, MINOR, f"Compte Administrateur intégré activé ({u.get('name')})",
                          impact="Compte connu de tous les attaquants, souvent avec le même mot de passe sur tous les postes.",
                          fix="Le désactiver et utiliser des comptes administrateurs nominatifs (ou LAPS pour les postes du domaine)."))
        if not u.get("password_required") and not sid.endswith(("-503", "-504")):
            c.add(Finding(f"acct.nopwd.{u.get('name')}", SEC, MAJOR, f"Compte « {u.get('name')} » autorisé sans mot de passe",
                          detail="L'indicateur « mot de passe obligatoire » est désactivé sur ce compte actif.",
                          impact="Le compte peut avoir un mot de passe vide : accès local, voire réseau, sans authentification.",
                          fix=f"Exécuter « net user \"{u.get('name')}\" /passwordreq:yes » et définir un mot de passe robuste."))
    local_admins = [a for a in admins if (a.get("source") or "").lower() in ("local", "") and not (a.get("sid") or "").endswith("-500")]
    if len(admins) > 3 or len(local_admins) > 2:
        c.add(Finding("acct.admins", SEC, MINOR, f"{len(admins)} membres dans le groupe Administrateurs",
                      detail=", ".join(a.get("name") or "?" for a in admins[:12]),
                      impact="Chaque compte administrateur supplémentaire est une porte d'entrée privilégiée.",
                      fix="Limiter le groupe aux comptes strictement nécessaires ; les utilisateurs doivent travailler sans droits administrateur."))
    user = (c.get("security", "uac_user") or {}).get("user", "")
    if user and any((a.get("name") or "").lower() == user.lower() for a in admins) and not c.is_server:
        c.add(Finding("acct.user_admin", SEC, MINOR, f"L'utilisateur du poste ({user}) est administrateur",
                      impact="Un logiciel malveillant ouvert par l'utilisateur obtient facilement les pleins pouvoirs.",
                      fix="Donner un compte standard pour le travail quotidien et un compte d'administration séparé."))
    if c.in_domain and not c.is_dc:
        r = c.get("security", "registry") or {}
        if not r.get("laps") and not r.get("laps_legacy"):
            c.add(Finding("acct.laps", SEC, MINOR, "Mot de passe administrateur local non géré (pas de LAPS)",
                          impact="Le même mot de passe administrateur local est souvent réutilisé sur tous les postes : "
                                 "un poste compromis donne accès à tous les autres.",
                          fix="Déployer Windows LAPS (intégré à Windows depuis avril 2023)."))
    pp = c.get("security", "password_policy")
    if pp:
        if (pp.get("MinimumPasswordLength") or 0) < 12:
            c.add(Finding("pwd.length", SEC, MAJOR if (pp.get("MinimumPasswordLength") or 0) < 8 else MINOR,
                          f"Longueur minimale des mots de passe : {pp.get('MinimumPasswordLength', 0)} caractères",
                          impact="Des mots de passe courts se devinent ou se cassent rapidement.",
                          fix="Exiger au moins 12 caractères (recommandation ANSSI) dans la stratégie de mots de passe."))
        if (pp.get("LockoutBadCount") or 0) == 0:
            c.add(Finding("pwd.lockout", SEC, MAJOR, "Aucun verrouillage après des échecs de connexion",
                          impact="Les attaques par force brute sur les comptes ne sont pas freinées.",
                          fix="Configurer un verrouillage (par ex. 10 tentatives, 15 minutes)."))
        if pp.get("ClearTextPassword") == 1:
            c.add(Finding("pwd.cleartext", SEC, CRIT, "Mots de passe stockés avec un chiffrement réversible",
                          fix="Désactiver « Enregistrer les mots de passe en utilisant un chiffrement réversible »."))
    elif not c.admin:
        c.not_checked("nc.pwd_policy", SEC, "Stratégie de mots de passe et de verrouillage")
    sl = c.get("events", "security_logons")
    if sl:
        n = sl.get("failed") or 0
        if n >= 20:
            top = "; ".join(f"{t.get('user') or '?'} depuis {t.get('ip') or '?'} ({t.get('count')})" for t in sl.get("top") or [])
            c.add(Finding("logon.failed", SEC, MAJOR if n >= 200 else MINOR, f"{n} échecs de connexion en 7 jours",
                          detail=f"Principales sources : {top}." + (f" {sl.get('lockouts')} verrouillage(s) de compte." if sl.get("lockouts") else ""),
                          impact="Tentatives de deviner des mots de passe, ou ancien mot de passe enregistré dans une application.",
                          fix="Identifier les sources ; bloquer les adresses externes, mettre à jour les identifiants enregistrés.",
                          predictive=True))
    elif not c.admin:
        c.not_checked("nc.logons", SEC, "Échecs de connexion (journal Sécurité)")


def shares(c: Ctx):
    for s in c.lst("security", "shares"):
        open_ = [a for a in s.get("access") or [] if (a.get("account") or "").split("\\")[-1].lower() in EVERYONE
                 and (a.get("type") or "").lower() == "allow"]
        if not open_:
            continue
        right = {a.get("right") for a in open_}
        full = bool(right & {"Full", "Change"})
        c.add(Finding(f"share.everyone.{s.get('name')}", SEC, MAJOR if full else MINOR,
                      f"Partage « {s.get('name')} » ouvert à « Tout le monde »" + (" en écriture" if full else ""),
                      detail=f"Chemin : {s.get('path')} ; droits : {', '.join(sorted(r for r in right if r))}.",
                      impact="Tout compte du réseau peut lire" + (" et modifier (ou chiffrer, en cas de rançongiciel)" if full else "") + " ces fichiers.",
                      fix="Restreindre les autorisations du partage à des groupes précis."))


def certificates(c: Ctx):
    soon = []
    for cert in c.lst("security", "certificates"):
        if not cert.get("private_key"):
            continue
        end = parse_dt(cert.get("not_after"))
        if not end:
            continue
        days = (end - c.now).days
        subj = re.sub(r"^CN=", "", (cert.get("subject") or "").split(",")[0])
        if days < 0 and (c.now - end).days < 90:
            soon.append((days, subj, end, cert))
        elif 0 <= days <= 45:
            soon.append((days, subj, end, cert))
    for days, subj, end, cert in sorted(soon, key=lambda x: x[0])[:6]:
        if cert.get("self_signed") and not c.is_server:
            continue
        expired = days < 0
        c.add(Finding(f"cert.{cert.get('thumbprint')}", SEC, MAJOR if (expired or days <= 15) else MINOR,
                      f"Certificat « {subj} » " + (f"expiré depuis le {fr_date(end)}" if expired else f"expire dans {days} jours ({fr_date(end)})"),
                      detail=f"Émetteur : {cert.get('issuer')} ; usages : {', '.join(cert.get('eku') or []) or '—'}.",
                      impact="Les services qui l'utilisent (site web, bureau à distance, VPN, Wi‑Fi 802.1X…) afficheront des erreurs ou refuseront les connexions.",
                      fix="Renouveler le certificat et le lier aux services concernés.", predictive=not expired))


def software(c: Ctx):
    soft = c.lst("software", "software")
    hits_eol, hits_vuln = {}, {}
    for s in soft:
        name, ver = s.get("name") or "", s.get("version") or ""
        for rule in SOFTWARE_RULES:
            if not re.search(rule.pattern, name, re.I):
                continue
            if rule.end and rule.end <= c.now.date():
                hits_eol.setdefault(rule.label, (rule.end, name))
            elif rule.end and (rule.end - c.now.date()).days <= 180:
                hits_eol.setdefault(rule.label + " (bientôt)", (rule.end, name))
            if rule.max_vuln and ver and version_lt(ver, rule.max_vuln):
                hits_vuln.setdefault(rule.label, (ver, rule.max_vuln, rule.why))
    for label, (end, name) in hits_eol.items():
        future = end > c.now.date()
        c.add(Finding(f"soft.eol.{label}", SEC, MINOR if future else MAJOR,
                      f"{label} : " + (f"fin de support le {end:%d/%m/%Y}" if future else f"plus supporté depuis le {end:%d/%m/%Y}"),
                      detail=f"Logiciel installé : {name}.",
                      impact="Plus de correctifs de sécurité : les documents piégés et les failles connues restent exploitables.",
                      fix="Migrer vers une version supportée ou désinstaller le logiciel s'il n'est plus utilisé.", predictive=future))
    for label, (ver, fixed, why) in hits_vuln.items():
        c.add(Finding(f"soft.vuln.{label}", SEC, MAJOR, f"{label} {ver} : version vulnérable",
                      detail=f"Version corrigée : {fixed} ou plus récente ; {why}.",
                      fix=f"Mettre à jour {label}."))
    ra = sorted({s.get("name") for s in soft if REMOTE_ACCESS.search(s.get("name") or "")})
    if ra:
        c.add(Finding("soft.remote", SEC, INFO, "Logiciels de prise en main à distance installés",
                      detail=", ".join(ra[:8]),
                      impact="Chacun est un accès possible au poste depuis l'extérieur : à valider avec le client.",
                      fix="Désinstaller ceux qui ne sont pas utilisés ; protéger les autres par un mot de passe fort et la double authentification."))
    unq = []
    for s in c.lst("software", "services"):
        p = (s.get("path") or "").strip()
        if not p or p.startswith('"') or " " not in p.split(".exe")[0]:
            continue
        exe = p.split(".exe")[0]
        if re.match(r"(?i)^[a-z]:\\windows\\", exe):
            continue
        unq.append(s.get("name"))
    if unq:
        c.add(Finding("svc.unquoted", SEC, MINOR, f"Chemins de services sans guillemets ({len(unq)})",
                      detail=", ".join(unq[:8]),
                      impact="Un utilisateur pouvant écrire dans un dossier du chemin peut faire exécuter son programme avec les droits du service.",
                      fix="Ajouter des guillemets autour du chemin (clé ImagePath du service) ou mettre à jour le logiciel."))
    risky = {21: "FTP", 23: "Telnet", 69: "TFTP", 5900: "VNC", 5901: "VNC", 5800: "VNC (web)", 512: "rexec", 513: "rlogin", 514: "rsh"}
    exp = [f"{risky[p['port']]} (port {p['port']}, {p.get('process')})" for p in c.lst("network", "listening") if p.get("port") in risky]
    if exp:
        c.add(Finding("net.risky_ports", SEC, MAJOR, "Services non chiffrés à l'écoute sur le réseau",
                      detail=", ".join(exp), impact="Identifiants et données circulent en clair, protocoles souvent sans protection contre la force brute.",
                      fix="Désactiver ces services ou les remplacer par des équivalents chiffrés (SFTP, SSH, RDP avec NLA)."))
    hosts = c.lst("network", "hosts")
    sus = [h for h in hosts if re.search(r"microsoft|windowsupdate|defender|kaspersky|eset|sophos|avast|bitdefender|norton|mcafee|"
                                         r"trendmicro|malwarebytes|virustotal", h, re.I)]
    if sus:
        c.add(Finding("net.hosts_hijack", SEC, MAJOR, "Fichier hosts : sites de sécurité redirigés",
                      detail="; ".join(sus[:6]), impact="Technique classique des logiciels malveillants pour bloquer les mises à jour et l'antivirus.",
                      fix="Nettoyer le fichier hosts et lancer une analyse antivirus complète."))
    elif hosts:
        c.add(Finding("net.hosts", SEC, INFO, f"Fichier hosts personnalisé ({len(hosts)} entrée(s))", detail="; ".join(hosts[:6])))


RULES = [antivirus, firewall, encryption, protocols, hardening, accounts, shares, certificates, software]
