"""Règles « Matériel et stabilité » : disques, erreurs matérielles, écrans
bleus, arrêts brutaux, surchauffe, plantages, batterie, périphériques."""
from __future__ import annotations

from collections import Counter
from statistics import mean

from .context import DENIED, Ctx
from .model import sjoin, CRIT, HW, INFO, MAJOR, MINOR, OK, Finding, fr_date, human_bytes, parse_dt

DISK_EVENTS = {
    # (fournisseur, id) : (gravité, intitulé, prédictif)
    7: (CRIT, "secteurs défectueux détectés", True),
    11: (MAJOR, "erreurs du contrôleur de disque", True),
    51: (MAJOR, "erreurs lors de la pagination (lecture/écriture)", True),
    153: (MAJOR, "opérations d'E/S répétées (le disque a dû réessayer)", True),
    154: (MAJOR, "opérations d'E/S en échec (erreur matérielle)", True),
    52: (CRIT, "prédiction de panne SMART du disque", True),
}
CTRL_PROVIDERS = ("storahci", "stornvme", "iaStorA", "iaStorAC", "iaStorAVC", "Microsoft-Windows-StorPort")
NTFS_IDS = {55, 98, 130, 137, 140}


def disks(c: Ctx):
    phys = c.lst("disks", "physical")
    smart = c.lst("disks", "smart_predict")
    if not phys and not c.has("disks", "physical"):
        return
    problems = 0
    for d in phys:
        name = f"{d.get('name') or d.get('model') or 'Disque'} ({human_bytes(d.get('size'))}, {d.get('media') or '?'}/{d.get('bus') or '?'})"
        health = (d.get("health") or "").lower()
        ops = [str(x).lower() for x in d.get("operational") or []]
        if health in ("unhealthy", "warning") or any("predictive" in o or "failed" in o for o in ops):
            problems += 1
            c.add(Finding(f"disk.health.{d.get('serial') or d.get('id')}", HW, CRIT if health == "unhealthy" or any("fail" in o for o in ops) else MAJOR,
                          f"Disque signalé en mauvais état : {d.get('name')}",
                          detail=f"Windows indique l'état « {d.get('health')} » ({sjoin(', ', d.get('operational'))}) pour {name}.",
                          impact="Le disque risque de tomber en panne et d'entraîner une perte de données.",
                          fix="Sauvegarder immédiatement les données, puis remplacer le disque.", predictive=True))
        rc = d.get("reliability") or {}
        if rc:
            wear = rc.get("wear")
            if wear is not None and wear >= 50 and (d.get("media") or "").upper() in ("SSD", "UNSPECIFIED", ""):
                sev = CRIT if wear >= 90 else MAJOR if wear >= 75 else MINOR
                problems += sev >= MAJOR
                c.add(Finding(f"disk.wear.{d.get('serial')}", HW, sev, f"Usure du SSD : {wear} %",
                              detail=f"{name} a consommé {wear} % de son endurance d'écriture prévue par le fabricant.",
                              impact="Au-delà de 100 %, le SSD peut passer en lecture seule ou tomber en panne sans prévenir.",
                              fix="Planifier son remplacement" + (" rapidement." if wear >= 75 else " lors du prochain renouvellement."),
                              predictive=True))
            unc = (rc.get("read_uncorrected") or 0) + (rc.get("write_uncorrected") or 0)
            if unc > 0:
                problems += 1
                c.add(Finding(f"disk.uncorrected.{d.get('serial')}", HW, CRIT, f"Erreurs de lecture/écriture non corrigées : {d.get('name')}",
                              detail=f"{unc} erreur(s) non corrigible(s) enregistrée(s) par {name}.",
                              impact="Des données n'ont pas pu être lues ou écrites correctement : signe de défaillance du support.",
                              fix="Sauvegarder les données et remplacer le disque.", predictive=True))
            t, tmax = rc.get("temperature"), rc.get("temperature_max")
            if t and t >= 65:
                c.add(Finding(f"disk.temp.{d.get('serial')}", HW, MAJOR if t >= 70 else MINOR, f"Disque trop chaud : {t} °C",
                              detail=f"{name} est à {t} °C" + (f" (maximum supporté : {tmax} °C)." if tmax else "."),
                              impact="La chaleur accélère l'usure et peut provoquer des erreurs ou un bridage des performances.",
                              fix="Vérifier la ventilation du boîtier, l'empoussièrement et l'emplacement du disque.", predictive=True))
            poh = rc.get("power_on_hours")
            if poh and (d.get("media") or "").upper() == "HDD" and poh >= 40000:
                c.add(Finding(f"disk.age.{d.get('serial')}", HW, MINOR, f"Disque dur âgé : {poh // 8760} ans de fonctionnement",
                              detail=f"{name} totalise {poh:,} heures de fonctionnement.".replace(",", " "),
                              impact="Le taux de panne des disques mécaniques augmente nettement après 4 à 5 ans de service continu.",
                              fix="Prévoir son remplacement (idéalement par un SSD) et vérifier les sauvegardes.", predictive=True))
    for s in smart:
        if s.get("predict_failure"):
            problems += 1
            c.add(Finding(f"disk.smart.{s.get('instance')}", HW, CRIT, "Le disque annonce lui-même une panne imminente (SMART)",
                          detail=f"Indicateur SMART « panne prévue » actif (motif {s.get('reason')}) pour {s.get('instance')}.",
                          impact="Le fabricant du disque estime que la panne est imminente.",
                          fix="Sauvegarder immédiatement et remplacer le disque.", predictive=True))
    # événements disque / contrôleur / NTFS
    for g in c.events(("disk", "Disk")):
        rule = DISK_EVENTS.get(int(g.get("id") or 0))
        if not rule:
            continue
        sev, label, pred = rule
        n = int(g.get("count") or 0)
        if int(g["id"]) == 153 and n < 5:
            sev = MINOR
        problems += 1
        c.add(Finding(f"disk.event.{g['id']}", HW, sev, f"Journal système : {label}",
                      detail=f"{n} événement(s) « disk » {g['id']} sur la période (dernier le {fr_date(parse_dt(g.get('last')))}).",
                      impact="Ces erreurs précèdent souvent la panne du disque ou signalent un câble / contrôleur défaillant.",
                      fix="Sauvegarder les données, vérifier la connectique, lancer un diagnostic constructeur du disque.",
                      evidence=[(g.get("message") or "")[:300]], predictive=pred))
    ctrl = c.events(CTRL_PROVIDERS, {129, 9, 11, 15, 549})
    if ctrl:
        n = c.count(ctrl)
        c.add(Finding("disk.controller", HW, MAJOR if n >= 3 else MINOR, f"Réinitialisations du contrôleur de stockage ({n})",
                      detail=f"Le pilote de stockage a dû réinitialiser le disque {n} fois ({sjoin(', ', sorted({g.get('provider') or '?' for g in ctrl}))}).",
                      impact="Gels temporaires du poste, risque de corruption de fichiers ; souvent un disque ou un câble en fin de vie.",
                      fix="Mettre à jour le firmware du SSD et le pilote du contrôleur, contrôler le câble ; si cela persiste, remplacer le disque.",
                      predictive=True))
    ntfs = [g for g in c.events(("Ntfs", "Microsoft-Windows-Ntfs")) if int(g.get("id") or 0) in NTFS_IDS]
    if ntfs:
        c.add(Finding("disk.ntfs", HW, MAJOR, "Corruption du système de fichiers détectée (NTFS)",
                      detail=f"{c.count(ntfs)} signalement(s) de corruption NTFS.",
                      impact="Fichiers illisibles ou perdus ; la corruption peut s'étendre.",
                      fix="Planifier « chkdsk /f » (ou « Réparer » dans les propriétés du volume) et vérifier l'état du disque.",
                      evidence=[(g.get("message") or "")[:250] for g in ntfs[:2]], predictive=True))
    defrag = c.events("Microsoft-Windows-Defrag", {257, 264})
    if defrag:
        c.add(Finding("disk.defrag", HW, MINOR, "L'optimisation automatique du disque échoue",
                      detail=f"{c.count(defrag)} échec(s) de l'optimiseur de stockage (TRIM / défragmentation).",
                      impact="Sur un SSD, l'absence de TRIM dégrade progressivement les performances en écriture ; "
                             "certaines erreurs indiquent aussi des problèmes de lecture.",
                      fix="Lancer « Optimiser les lecteurs » manuellement et lire le message d'erreur ; vérifier le disque si l'erreur parle de données.",
                      evidence=[(defrag[0].get("message") or "")[:300]]))
    if phys and problems == 0:
        c.add(Finding("disk.ok", HW, OK, "Disques : aucun signe de défaillance",
                      detail=f"{len(phys)} disque(s) contrôlé(s) : état, compteurs de fiabilité et journaux sans anomalie."))


def crashes(c: Ctx):
    bug = c.events("Microsoft-Windows-WER-SystemErrorReporting", {1001})
    dumps = c.lst("disks", "minidumps")
    n30 = c.count_since(bug, 30)
    recent_dumps = [d for d in dumps if (dt := parse_dt(d.get("date"))) and (c.now - dt).days <= 90]
    if n30 or recent_dumps:
        n = max(n30, len([d for d in recent_dumps if (c.now - parse_dt(d['date'])).days <= 30]))
        sev = CRIT if n >= 2 else MAJOR if n == 1 else MINOR
        ev = [(g.get("message") or "")[:300] for g in bug[:2]] + [f"Vidage mémoire : {d['name']} du {fr_date(parse_dt(d['date']))}" for d in recent_dumps[:5]]
        c.add(Finding("stab.bsod", HW, sev, f"Écrans bleus (plantages système) : {n} sur 30 jours" if n else "Écrans bleus dans les 3 derniers mois",
                      detail=f"{n} plantage(s) système sur 30 jours, {len(recent_dumps)} fichier(s) de vidage sur 90 jours.",
                      impact="Perte du travail en cours ; causes fréquentes : pilote défectueux, mémoire vive ou disque défaillants, surchauffe.",
                      fix="Analyser les vidages (code d'arrêt), mettre à jour les pilotes et le BIOS, tester la mémoire (mdsched.exe).",
                      evidence=ev, predictive=n >= 2))
    kp = c.events("Microsoft-Windows-Kernel-Power", {41}) + c.events("EventLog", {6008})
    n = c.count_since(kp, 30)
    if n:
        sev = MAJOR if n >= 3 else MINOR
        c.add(Finding("stab.unexpected_shutdown", HW, sev, f"Arrêts brutaux du poste : {n} sur 30 jours",
                      detail=f"Windows a redémarré {n} fois sans arrêt propre (Kernel-Power 41 / EventLog 6008).",
                      impact="Risque de corruption des données ; causes : coupure de courant, alimentation ou batterie faible, "
                             "surchauffe, plantage matériel, arrêt forcé par l'utilisateur.",
                      fix="Vérifier l'alimentation (onduleur pour un serveur), la température, et interroger l'utilisateur sur des arrêts forcés.",
                      predictive=n >= 3))
    whea_err = [g for g in c.events("Microsoft-Windows-WHEA-Logger") if int(g.get("level") or 4) <= 2]
    whea_warn = [g for g in c.events("Microsoft-Windows-WHEA-Logger") if int(g.get("level") or 4) == 3]
    if whea_err:
        c.add(Finding("hw.whea.fatal", HW, CRIT, "Erreurs matérielles graves (WHEA)",
                      detail=f"{c.count(whea_err)} erreur(s) matérielle(s) non corrigée(s) signalée(s) par le processeur ou le chipset.",
                      impact="Indique un composant défaillant (mémoire, processeur, carte mère, PCIe) : plantages et pertes de données probables.",
                      fix="Tester la mémoire et le processeur (outils constructeur), mettre à jour le BIOS ; remplacer le composant en cause.",
                      evidence=[(g.get("message") or "")[:300] for g in whea_err[:2]], predictive=True))
    if whea_warn:
        n = c.count(whea_warn)
        c.add(Finding("hw.whea.corrected", HW, MAJOR if n >= 10 else MINOR, f"Erreurs matérielles corrigées : {n}",
                      detail=f"Le matériel a corrigé {n} erreur(s) (mémoire, bus PCIe, cache processeur).",
                      impact="Des erreurs corrigées fréquentes annoncent souvent une panne à venir du composant.",
                      fix="Identifier le composant dans le détail des événements WHEA, mettre à jour BIOS et pilotes, surveiller l'évolution.",
                      evidence=[(g.get("message") or "")[:300] for g in whea_warn[:2]], predictive=True))
    throttle = c.events("Microsoft-Windows-Kernel-Processor-Power", {37})
    if throttle and not c.is_vm:
        n = c.count(throttle)
        c.add(Finding("hw.throttling", HW, MAJOR if n >= 5 else MINOR, "Processeur bridé par le firmware (surchauffe probable)",
                      detail=f"{n} événement(s) de limitation de la vitesse du processeur par le firmware.",
                      impact="Performances fortement réduites ; une surchauffe prolongée réduit la durée de vie du matériel.",
                      fix="Dépoussiérer, vérifier les ventilateurs et la pâte thermique, contrôler l'alimentation électrique.",
                      predictive=True))
    for t in c.lst("system", "thermal"):
        cel, crit = t.get("celsius"), t.get("critical")
        if cel and cel > 0 and ((crit and cel >= crit - 8) or cel >= 85):
            c.add(Finding("hw.temp", HW, CRIT if crit and cel >= crit - 3 else MAJOR, f"Température élevée : {cel} °C",
                          detail=f"Zone thermique {t.get('zone')} à {cel} °C (seuil critique {crit} °C).",
                          impact="Arrêt d'urgence possible et vieillissement accéléré des composants.",
                          fix="Dépoussiérer et vérifier la ventilation.", predictive=True))
    tdr = c.events(("Display",), {4101}) + c.events(("nvlddmkm", "amdkmdag"))
    if tdr:
        c.add(Finding("hw.gpu_tdr", HW, MINOR, f"Pilote graphique réinitialisé ({c.count(tdr)} fois)",
                      detail="Le pilote graphique a cessé de répondre puis a été relancé par Windows.",
                      impact="Écran noir ou figé quelques secondes, plantage possible des applications graphiques.",
                      fix="Mettre à jour le pilote graphique depuis le site du constructeur ; vérifier la température de la carte."))
    # services qui plantent
    svc = c.events("Service Control Manager", {7031, 7034})
    if svc:
        names = Counter()
        for g in svc:
            names[(g.get("props") or ["?"])[0]] += int(g.get("count") or 0)
        top = ", ".join(f"{n} ({k}×)" for n, k in names.most_common(6))
        c.add(Finding("stab.service_crash", HW, MAJOR if sum(names.values()) >= 5 else MINOR,
                      f"Services Windows arrêtés de façon inattendue ({sum(names.values())})",
                      detail=f"Services concernés : {top}.",
                      impact="Fonctionnalités indisponibles par intermittence ; un service qui plante en boucle signale un bug ou une corruption.",
                      fix="Mettre à jour ou réinstaller le logiciel propriétaire du service ; consulter son journal.",
                      evidence=[(g.get("message") or "")[:200] for g in svc[:3]]))


def app_crashes(c: Ctx):
    crashes = c.events("Application Error", {1000}, logs=("application_errors",))
    hangs = c.events("Application Hang", {1002}, logs=("application_errors",))
    per_app = Counter()
    for g in crashes:
        per_app[g.get("key") or "?"] += int(g.get("count") or 0)
    total = sum(per_app.values())
    if total:
        top = per_app.most_common(8)
        sev = MAJOR if total >= 15 or top[0][1] >= 8 else MINOR if total >= 5 else INFO
        c.add(Finding("stab.app_crash", HW, sev, f"Plantages d'applications : {total} sur la période",
                      detail="Applications concernées : " + ", ".join(f"{a} ({n})" for a, n in top) + ".",
                      impact="Perte de travail et perte de temps pour l'utilisateur ; un même programme qui plante souvent est à corriger.",
                      fix="Mettre à jour ou réparer les applications citées ; si beaucoup d'applications différentes plantent, suspecter la mémoire vive.",
                      predictive=len(per_app) >= 5))
    if hangs:
        per = Counter()
        for g in hangs:
            per[g.get("key") or "?"] += int(g.get("count") or 0)
        c.add(Finding("stab.app_hang", HW, MINOR if sum(per.values()) >= 5 else INFO, f"Applications figées : {sum(per.values())}",
                      detail="Applications qui ont cessé de répondre : " + ", ".join(f"{a} ({n})" for a, n in per.most_common(6)) + ".",
                      impact="L'utilisateur doit forcer la fermeture ; souvent lié à un manque de mémoire, un disque lent ou un module défectueux.",
                      fix="Mettre à jour ces applications et vérifier les ressources (mémoire, disque)."))


def reliability(c: Ctx):
    pts = []
    for r in c.lst("events", "reliability"):
        d = parse_dt(r.get("t"))
        if d and r.get("v") is not None:
            pts.append((d, float(r["v"])))
    if not pts:
        return
    pts.sort()
    last = pts[-1][1]
    recent = [v for d, v in pts if (c.now - d).days < 7]
    before = [v for d, v in pts if 7 <= (c.now - d).days < 30]
    if recent and before:
        r, b = mean(recent), mean(before)
        if b - r >= 1.5:
            c.add(Finding("stab.reliability_trend", HW, MAJOR if b - r >= 3 else MINOR,
                          f"Fiabilité en baisse : {b:.1f} → {r:.1f} / 10".replace(".", ","),
                          detail="L'indice de fiabilité calculé par Windows a nettement baissé sur les 7 derniers jours.",
                          impact="De nouveaux incidents (plantages, échecs de mises à jour, erreurs matérielles) apparaissent : la situation se dégrade.",
                          fix="Consulter l'historique de fiabilité (perfmon /rel) pour dater le premier incident et le changement associé.",
                          predictive=True))
    if last < 5:
        c.add(Finding("stab.reliability", HW, MAJOR if last < 3 else MINOR, f"Indice de fiabilité Windows bas : {last:.1f} / 10".replace(".", ","),
                      detail="Windows calcule cet indice à partir des plantages, échecs et erreurs des 28 derniers jours.",
                      impact="Poste instable.", fix="Traiter les plantages et erreurs listés dans ce rapport."))
    elif last >= 8 and not any(f.id.startswith("stab.reliability") for f in c.findings):
        c.add(Finding("stab.reliability.ok", HW, OK, f"Indice de fiabilité Windows correct : {last:.1f} / 10".replace(".", ",")))


def devices(c: Ctx):
    devs = [d for d in c.lst("software", "devices") if d.get("present", True) and int(d.get("code") or 0) not in (22, 45)]
    if devs:
        hard = [d for d in devs if int(d.get("code") or 0) in (10, 43)]
        c.add(Finding("hw.devices", HW, MAJOR if hard else MINOR, f"Périphériques en erreur : {len(devs)}",
                      detail="; ".join(f"{d.get('name') or d.get('id')} (code {d.get('code')})" for d in devs[:8]),
                      impact="Matériel inutilisable ou pilote absent (code 28), défaillant (code 43) ou qui ne démarre pas (code 10).",
                      fix="Installer le pilote du constructeur, ou vérifier / remplacer le périphérique (code 43)."))
    pnp = c.events("Microsoft-Windows-Kernel-PnP", {219})
    if pnp and c.count(pnp) >= 3:
        c.add(Finding("hw.driver_load", HW, MINOR, "Pilotes qui ne se chargent pas au démarrage",
                      detail=f"{c.count(pnp)} échec(s) de chargement de pilote.", impact="Démarrage ralenti, périphérique indisponible.",
                      fix="Identifier le périphérique dans l'événement et réinstaller son pilote.",
                      evidence=[(pnp[0].get("message") or "")[:250]]))


def battery(c: Ctx):
    b = c.get("system", "battery")
    if not b:
        return
    design, full = b.get("design_mwh"), b.get("full_mwh")
    if design and full and design > 0:
        wear = max(0.0, 1 - full / design) * 100
        if wear >= 25:
            c.add(Finding("hw.battery", HW, MAJOR if wear >= 40 else MINOR, f"Batterie usée : {wear:.0f} % de capacité perdue",
                          detail=f"Capacité actuelle {full / 1000:.1f} Wh pour {design / 1000:.1f} Wh à l'origine".replace(".", ",")
                                 + (f", {b['cycles']} cycles." if b.get("cycles") else "."),
                          impact="Autonomie réduite ; une batterie très usée peut provoquer des arrêts brutaux ou gonfler.",
                          fix="Prévoir le remplacement de la batterie.", predictive=True))
        else:
            c.add(Finding("hw.battery.ok", HW, OK, f"Batterie en bon état ({100 - wear:.0f} % de la capacité d'origine)"))


def firmware(c: Ctx):
    if c.is_vm:
        return
    bios = c.get("system", "bios") or {}
    rel = parse_dt(bios.get("release"))
    if rel and (c.now - rel).days > 5 * 365:
        c.add(Finding("hw.bios_age", HW, MINOR, f"BIOS/UEFI ancien ({fr_date(rel)})",
                      detail=f"Version {bios.get('version')} de {bios.get('manufacturer')}, publiée il y a {(c.now - rel).days // 365} ans.",
                      impact="Les mises à jour de firmware corrigent des failles de sécurité (processeur, Secure Boot) et des problèmes de stabilité.",
                      fix="Vérifier sur le site du constructeur si une version plus récente existe pour ce modèle."))
    for g in c.lst("system", "gpu"):
        d = parse_dt(g.get("driver_date"))
        if d and (c.now - d).days > 3 * 365 and not c.is_server and "basic" not in (g.get("name") or "").lower():
            c.add(Finding("hw.gpu_driver", HW, INFO, f"Pilote graphique ancien ({fr_date(d)})",
                          detail=f"{g.get('name')} : pilote {g.get('driver')}.",
                          fix="Installer le pilote récent du constructeur (Intel, AMD, NVIDIA)."))
            break


def not_checked(c: Ctx):
    errs = c.errors()
    for key, msg in errs.items():
        if key in ("tpm", "smart_predict", "thermal") and DENIED.search(msg) and not c.is_vm:
            c.not_checked(f"nc.{key}", HW, {"tpm": "Puce TPM", "smart_predict": "Prédiction de panne SMART",
                                            "thermal": "Températures"}[key])
    phys = c.lst("disks", "physical")
    if phys and all(not d.get("reliability") for d in phys) and not c.admin and not c.is_vm:
        c.not_checked("nc.disk_reliability", HW, "Compteurs d'usure et d'erreurs des disques (SMART)")


RULES = [disks, crashes, app_crashes, reliability, devices, battery, firmware, not_checked]
