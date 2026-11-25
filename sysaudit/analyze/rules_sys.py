"""Règles « Système et performances » : support de Windows, mises à jour,
espace disque, mémoire, processeur, démarrage, services, tâches, réseau, heure."""
from __future__ import annotations

import re
from collections import Counter
from statistics import median

from .context import Ctx
from .eol import os_life
from .model import sjoin, CRIT, INFO, MAJOR, MINOR, OK, SYS, Finding, fr_date, human_bytes, parse_dt

# services « Automatique » qu'il est normal de trouver arrêtés
SERVICE_IGNORE = re.compile(
    r"^(edgeupdate|edgeupdatem|gupdate|gupdatem|GoogleUpdater.*|MozillaMaintenance|MapsBroker|sppsvc|RemoteRegistry|"
    r"ShellHWDetection|tiledatamodelsvc|WbioSrvc|clr_optimization.*|TrustedInstaller|BITS|wuauserv|UsoSvc|"
    r"CDPSvc|DoSvc|WaaSMedicSvc|gpsvc|IntelAudioService|sedsvc|AdobeARMservice|AGSService|AGMService|"
    r"spice-agent|vmicvss|vmictimesync|vmicheartbeat|vmickvpexchange|vmicshutdown|vmicrdv|vmicguestinterface|"
    r"stisvc|WMPNetworkSvc|ClickToRunSvc|OneSyncSvc_.*|CDPUserSvc_.*|WpnUserService_.*|RtkAudioUniversalService|"
    r"NetTcpPortSharing|MSDTC|CertPropSvc|DPS|WdiServiceHost|DiagTrack|lfsvc|SensrSvc|SysMain|Spooler)$", re.I)

BAD_WU = {4: "échec", 5: "annulée"}


def os_support(c: Ctx):
    life = os_life(c.build, c.product_type, c.os.get("edition"))
    name = c.os.get("caption") or life.name
    ver = f"{name} {c.os.get('display_version') or ''} (build {c.build}.{c.os.get('ubr') or 0})".replace("  ", " ")
    if life.end is None:
        c.add(Finding("os.support", SYS, INFO, f"Version de Windows : {ver}", detail=life.note or "Version supportée."))
        return
    days = (life.end - c.now.date()).days
    if days < 0:
        c.add(Finding("os.support", SYS, CRIT, f"Windows n'est plus supporté depuis le {life.end:%d/%m/%Y}",
                      detail=f"{ver} — {life.name} : fin de support le {life.end:%d/%m/%Y}.",
                      impact="Plus aucun correctif de sécurité : chaque nouvelle faille découverte reste exploitable sur ce poste.",
                      fix="Mettre à niveau vers une version supportée (mise à jour de fonctionnalité ou nouvelle version de Windows) ; "
                          "à défaut, souscrire aux mises à jour de sécurité étendues (ESU) si elles existent pour cette version."))
    elif days < 365:
        c.add(Finding("os.support", SYS, MAJOR if days < 180 else MINOR,
                      f"Fin de support de Windows dans {days // 30} mois ({life.end:%d/%m/%Y})",
                      detail=f"{ver} — {life.name}.",
                      impact="Après cette date, plus aucun correctif de sécurité.",
                      fix="Planifier la mise à niveau avant cette date (vérifier la compatibilité matérielle et logicielle).",
                      predictive=True))
    else:
        c.add(Finding("os.support", SYS, OK, f"Windows supporté jusqu'au {life.end:%d/%m/%Y}", detail=ver))


def updates(c: Ctx):
    hot = [(parse_dt(h.get("installed")), h) for h in c.lst("updates", "hotfixes")]
    hot = [(d, h) for d, h in hot if d]
    hist = c.lst("updates", "history")
    ok_dates = [parse_dt(h.get("date")) for h in hist if int(h.get("result") or 0) in (2, 3)
                and not re.search(r"defender|antivirus|intelligence|veille de sécurité|security intelligence|KB2267602|KB890830",
                                  h.get("title") or "", re.I)]
    ok_dates = [d for d in ok_dates if d]
    last = max([d for d, _ in hot] + ok_dates, default=None)
    if last:
        age = (c.now - last).days
        if age > 60:
            sev, title = CRIT, f"Aucune mise à jour Windows installée depuis {age} jours"
        elif age > 40:
            sev, title = MAJOR, f"Dernière mise à jour Windows il y a {age} jours"
        else:
            sev, title = OK, f"Mises à jour Windows récentes (dernière le {fr_date(last)})"
        c.add(Finding("wu.age", SYS, sev, title,
                      detail=f"Dernière mise à jour du système installée le {fr_date(last)}.",
                      impact="" if sev == OK else "Microsoft publie des correctifs de sécurité chaque mois : le poste est exposé aux failles connues.",
                      fix="" if sev == OK else "Lancer Windows Update et installer toutes les mises à jour ; vérifier pourquoi elles ne s'installent plus."))
    # échecs répétés
    fails = Counter()
    for h in hist:
        if int(h.get("result") or 0) in BAD_WU:
            t = re.sub(r"\s*\(version [^)]*\)", "", h.get("title") or "?")
            fails[t] += 1
    for g in c.events("Microsoft-Windows-WindowsUpdateClient", {20}):
        t = g.get("key") or ((g.get("props") or [])[1:2] or ["?"])[0]
        fails[t] = max(fails[t], int(g.get("count") or 0))
    store = re.compile(r"^[0-9A-Z]{12}-")       # applications du Microsoft Store (ex. 9N3RK8ZV2ZR8-Microsoft.…)
    sys_fail = {t: k for t, k in fails.items() if not store.match(t)}
    app_fail = {t: k for t, k in fails.items() if store.match(t)}
    if sys_fail:
        n = sum(sys_fail.values())
        c.add(Finding("wu.failures", SYS, MAJOR if max(sys_fail.values()) >= 2 else MINOR,
                      f"Mises à jour Windows en échec ({len(sys_fail)})",
                      detail="; ".join(f"{t} ({k} échec(s))" for t, k in sorted(sys_fail.items(), key=lambda x: -x[1])[:5]),
                      impact="Une mise à jour qui échoue en boucle bloque souvent les suivantes et laisse le poste sans correctifs.",
                      fix="Lancer l'utilitaire de résolution des problèmes Windows Update ; en administrateur : "
                          "« DISM /Online /Cleanup-Image /RestoreHealth » puis « sfc /scannow », et réessayer.",
                      predictive=n >= 3))
    if app_fail:
        c.add(Finding("wu.store_failures", SYS, MINOR, f"Applications du Store qui ne se mettent pas à jour ({len(app_fail)})",
                      detail="; ".join(f"{t.split('-', 1)[1]} ({k} échec(s))" for t, k in sorted(app_fail.items(), key=lambda x: -x[1])[:5]),
                      impact="Tentatives répétées en arrière-plan ; l'application concernée reste dans une ancienne version.",
                      fix="Fermer l'application concernée puis relancer la mise à jour depuis le Microsoft Store (Bibliothèque › Obtenir les mises à jour)."))
    pend = c.lst("updates", "pending")
    if c.get("updates", "pending_checked"):
        sec = [p for p in pend if (p.get("severity") or "") in ("Critical", "Important") or
               any("sécurité" in x.lower() or "security" in x.lower() for x in p.get("categories") or [])]
        if sec:
            c.add(Finding("wu.pending_security", SYS, MAJOR, f"{len(sec)} mise(s) à jour de sécurité en attente",
                          detail="; ".join(p.get("title") or "" for p in sec[:6]),
                          impact="Des failles corrigées par Microsoft restent ouvertes sur ce poste.",
                          fix="Installer ces mises à jour et redémarrer."))
        elif pend:
            c.add(Finding("wu.pending", SYS, MINOR, f"{len(pend)} mise(s) à jour disponible(s)",
                          detail="; ".join(p.get("title") or "" for p in pend[:6]), fix="Les installer lors de la prochaine maintenance."))
    for s in c.lst("updates", "wu_services"):
        if s.get("name") == "wuauserv" and (s.get("start") or "").lower() == "disabled":
            c.add(Finding("wu.disabled", SYS, CRIT, "Le service Windows Update est désactivé",
                          impact="Le poste ne reçoit plus aucune mise à jour.",
                          fix="Remettre le service « Windows Update » en démarrage manuel ; si un outil tiers l'a désactivé, le retirer."))
    pol = c.get("updates", "wu_policy") or {}
    if pol.get("no_auto") == 1:
        c.add(Finding("wu.policy_off", SYS, MAJOR, "Mises à jour automatiques désactivées par stratégie",
                      detail="Clé NoAutoUpdate = 1.", impact="Les mises à jour dépendent d'une action manuelle, souvent oubliée.",
                      fix="Réactiver les mises à jour automatiques ou s'assurer qu'un outil de gestion (WSUS, Intune, RMM) les déploie."))
    if pol.get("paused_until"):
        d = parse_dt(pol["paused_until"])
        if d and d > c.now:
            c.add(Finding("wu.paused", SYS, MINOR, f"Mises à jour suspendues jusqu'au {fr_date(d)}",
                          fix="Reprendre les mises à jour dans Paramètres › Windows Update."))
    pr = c.lst("system", "pending_reboot")
    if pr:
        up = c.uptime_days or 0
        c.add(Finding("os.pending_reboot", SYS, MAJOR if up > 14 else MINOR, "Redémarrage en attente",
                      detail=f"Un redémarrage est nécessaire pour terminer des installations ({sjoin(', ', pr)}) ; "
                             f"poste allumé depuis {up:.0f} jour(s).".replace(".", ","),
                      impact="Des correctifs installés ne sont pas encore actifs ; d'autres installations peuvent échouer.",
                      fix="Redémarrer le poste (planifier une fenêtre de maintenance pour un serveur)."))


def uptime(c: Ctx):
    up = c.uptime_days
    if up is None:
        return
    limit = 45 if c.is_server else 21
    if up > limit:
        c.add(Finding("os.uptime", SYS, MINOR, f"Poste allumé sans redémarrage depuis {up:.0f} jours",
                      detail=f"Dernier démarrage le {fr_date(parse_dt(c.os.get('last_boot')))}.",
                      impact="Correctifs non appliqués, fuites de mémoire qui s'accumulent, lenteurs progressives.",
                      fix="Redémarrer régulièrement (au moins après chaque mise à jour mensuelle).", predictive=True))


def disk_space(c: Ctx):
    vols = [v for v in c.lst("disks", "volumes") if v.get("letter") and (v.get("size") or 0) > 2 * 1024 ** 3]
    folders = {f.get("path", "").lower(): f for f in c.lst("disks", "folders")}
    any_issue = False
    for v in vols:
        size, free = v.get("size") or 0, v.get("free") or 0
        pct = free / size * 100 if size else 100
        system = (v.get("letter") or "").upper() == (c.os.get("system_drive") or "C:").upper()
        gb = free / 1024 ** 3
        if pct < 5 or gb < 3:
            sev = CRIT
        elif pct < 10 or (system and gb < 15):
            sev = MAJOR
        elif pct < 15 or (system and gb < 25):
            sev = MINOR
        else:
            continue
        any_issue = True
        tips = []
        if system:
            for key, label in (("temp", "fichiers temporaires"), ("softwaredistribution\\download", "cache Windows Update"),
                               ("windows.old", "ancienne installation (Windows.old)"), ("$recycle.bin", "corbeille")):
                for p, f in folders.items():
                    if p.endswith(key) and (f.get("bytes") or 0) > 300 * 1024 ** 2:
                        tips.append(f"{label} : {human_bytes(f['bytes'])}")
            md = c.get("disks", "memory_dump")
            if md and (md.get("bytes") or 0) > 300 * 1024 ** 2:
                tips.append(f"vidage mémoire MEMORY.DMP : {human_bytes(md['bytes'])}")
        c.add(Finding(f"disk.space.{v['letter']}", SYS, sev, f"Espace disque faible sur {v['letter']} : {pct:.0f} % libre",
                      detail=f"{human_bytes(free)} libres sur {human_bytes(size)}." + (" Espace récupérable : " + ", ".join(tips) + "." if tips else ""),
                      impact=("Sur le disque système : mises à jour impossibles, lenteurs, plantages d'applications, "
                              "fichier d'échange bloqué." if system else "Les applications qui écrivent sur ce volume vont échouer."),
                      fix="Nettoyer (Nettoyage de disque / Stockage › Fichiers temporaires), déplacer des données ou agrandir le volume.",
                      predictive=sev < CRIT))
    for v in c.lst("disks", "volumes"):
        if v.get("dirty"):
            c.add(Finding(f"disk.dirty.{v.get('letter') or v.get('name')}", SYS, MAJOR,
                          f"Volume {v.get('letter') or v.get('label') or ''} marqué « à vérifier »",
                          detail="Windows a détecté une incohérence du système de fichiers (bit « dirty »).",
                          impact="Corruption possible de fichiers ; une vérification longue sera lancée au prochain démarrage.",
                          fix="Planifier « chkdsk /f » sur ce volume.", predictive=True))
    for v in c.lst("disks", "volume_health"):
        if v.get("health") and v["health"] not in ("Healthy", "0") and v.get("letter"):
            c.add(Finding(f"disk.volhealth.{v['letter']}", SYS, MAJOR, f"Volume {v['letter']}: état « {v['health']} »",
                          detail=f"État opérationnel : {v.get('operational')}.", fix="Lancer une vérification du volume (chkdsk)."))
    if vols and not any_issue:
        c.add(Finding("disk.space.ok", SYS, OK, "Espace disque suffisant sur tous les volumes"))


def memory(c: Ctx):
    m = c.get("system", "memory_perf") or {}
    ram = c.ram
    if m.get("commit_limit"):
        ratio = m["committed"] / m["commit_limit"] * 100
        if ratio >= 80:
            c.add(Finding("mem.commit", SYS, CRIT if ratio >= 92 else MAJOR, f"Mémoire virtuelle presque saturée : {ratio:.0f} %",
                          detail=f"{human_bytes(m['committed'])} engagés pour une limite de {human_bytes(m['commit_limit'])} "
                                 f"(mémoire vive {human_bytes(ram)} + fichier d'échange).",
                          impact="À 100 %, les applications plantent ou refusent de s'ouvrir (« mémoire insuffisante »).",
                          fix="Fermer ou corriger les programmes gourmands, laisser Windows gérer le fichier d'échange, ajouter de la mémoire.",
                          predictive=True))
    if ram and m.get("available_mb") is not None:
        avail = m["available_mb"] * 1024 ** 2 / ram * 100
        if avail < 10:
            c.add(Finding("mem.available", SYS, MAJOR if avail < 5 else MINOR, f"Mémoire vive disponible faible : {avail:.0f} %",
                          detail=f"{m['available_mb']} Mo disponibles sur {human_bytes(ram)}.",
                          impact="Le système utilise le disque comme mémoire : forte lenteur.",
                          fix="Identifier les processus gourmands ci-dessous ; ajouter de la mémoire si l'usage est normal."))
    if ram and not c.is_server:
        gb = ram / 1024 ** 3
        if gb < 7.5:
            c.add(Finding("mem.size", SYS, MAJOR if gb < 3.8 else MINOR, f"Mémoire vive insuffisante : {gb:.0f} Go".replace(".", ","),
                          detail="Windows 11 et les applications actuelles (navigateur, Teams, Office) demandent au moins 8 Go, idéalement 16 Go.",
                          impact="Lenteurs permanentes dès que plusieurs applications sont ouvertes.",
                          fix="Ajouter de la mémoire si la carte mère le permet."))
    np = m.get("pool_nonpaged") or 0
    if np > 1.5 * 1024 ** 3 or (ram and np > ram * 0.12):
        c.add(Finding("mem.pool", SYS, MAJOR, f"Mémoire du noyau anormalement élevée : {human_bytes(np)}",
                      detail="La réserve « non paginée » du noyau est très grande.",
                      impact="Signe classique de fuite de mémoire d'un pilote : le poste finit par se bloquer ou planter.",
                      fix="Identifier le pilote fautif (poolmon / RAMMap) et le mettre à jour (antivirus, filtre réseau, pilote de stockage).",
                      predictive=True))
    for pf in c.lst("system", "pagefile"):
        if pf.get("allocated_mb") and pf.get("peak_mb", 0) >= pf["allocated_mb"] * 0.9:
            c.add(Finding("mem.pagefile", SYS, MINOR, "Fichier d'échange trop petit",
                          detail=f"{pf.get('name')} : pic d'utilisation {pf['peak_mb']} Mo pour {pf['allocated_mb']} Mo alloués.",
                          impact="Risque d'erreurs « mémoire insuffisante » ; empêche aussi l'écriture des vidages en cas d'écran bleu.",
                          fix="Laisser Windows gérer automatiquement la taille du fichier d'échange.", predictive=True))
    exh = c.events("Microsoft-Windows-Resource-Exhaustion-Detector", {2004})
    if exh:
        c.add(Finding("mem.exhaustion", SYS, MAJOR, f"Mémoire épuisée à {c.count(exh)} reprise(s)",
                      detail="Windows a détecté un manque de mémoire virtuelle et désigné les programmes les plus gourmands.",
                      impact="Plantages et blocages au moment de l'épuisement ; souvent une fuite de mémoire d'une application.",
                      fix="Mettre à jour ou corriger les programmes cités, redémarrer régulièrement, ajouter de la mémoire si nécessaire.",
                      evidence=[(g.get("message") or "")[:400] for g in exh[:2]], predictive=True))
    procs = (c.get("system", "processes") or {}).get("top") or []
    leaks = []
    for p in procs:
        name = p.get("name") or "?"
        priv, h = p.get("private") or 0, p.get("handles") or 0
        if name.lower() in ("system", "memory compression", "registry", "vmmem", "vmmemwsl", "sqlservr", "msmpeng"):
            continue
        if (ram and priv > ram * 0.3 and priv > 3 * 1024 ** 3) or h > 25000:
            leaks.append(f"{name} (PID {p.get('pid')}) : {human_bytes(priv)} privés, {h} handles")
    if leaks:
        c.add(Finding("mem.leak", SYS, MINOR, "Processus suspect de fuite de ressources",
                      detail="; ".join(leaks[:5]),
                      impact="Un programme qui accumule de la mémoire ou des handles finit par ralentir puis bloquer le poste.",
                      fix="Mettre à jour le programme ; le redémarrer régulièrement en attendant un correctif.", predictive=True))


def cpu_perf(c: Ctx):
    load = [x for x in c.lst("system", "cpu_load") if isinstance(x, (int, float))]
    if load:
        avg = sum(load) / len(load)
        if avg >= 70:
            procs = sorted(((c.get("system", "processes") or {}).get("top") or []), key=lambda p: -(p.get("cpu_pct") or 0))
            top = ", ".join(f"{p['name']} ({p.get('cpu_pct')} %)" for p in procs[:4] if p.get("cpu_pct"))
            c.add(Finding("cpu.load", SYS, MAJOR if avg >= 90 else MINOR, f"Processeur très sollicité : {avg:.0f} %",
                          detail=f"Charge mesurée pendant l'analyse. Processus principaux : {top or 'non déterminés'}.",
                          impact="Lenteurs générales.", fix="Identifier le processus en cause (analyse antivirus, mise à jour, programme bloqué)."))
    for d in c.lst("system", "disk_perf"):
        lat = max(d.get("read_s") or 0, d.get("write_s") or 0)
        if lat >= 0.05 and (d.get("busy") or 0) >= 50:
            c.add(Finding(f"disk.latency.{d.get('name')}", SYS, MAJOR if lat >= 0.2 else MINOR,
                          f"Disque lent : {lat * 1000:.0f} ms par opération",
                          detail=f"Disque {d.get('name')} occupé à {d.get('busy')} %, file d'attente {d.get('queue')}.",
                          impact="Démarrage et ouverture des applications très lents.",
                          fix="Remplacer un disque mécanique par un SSD ; vérifier l'état du disque."))


def boot(c: Ctx):
    bp = sorted((x for x in c.lst("events", "boot_perf") if x.get("boot_ms")), key=lambda x: x.get("date") or "")
    if bp:
        last = bp[-1]["boot_ms"] / 1000
        recent = [x["boot_ms"] for x in bp[-5:]]
        older = [x["boot_ms"] for x in bp[:-5]][-10:]
        trend = median(recent) / median(older) if older else 1
        deg = c.lst("events", "boot_degradation")
        culprits = Counter()
        for d in deg:
            if d.get("name") or d.get("file"):
                culprits[d.get("name") or d.get("file")] += int(d.get("degradation_ms") or 0)
        ev = [f"{n} : +{ms / 1000:.0f} s cumulées" for n, ms in culprits.most_common(5)]
        if last >= 60 or trend >= 1.4:
            sev = MAJOR if last >= 120 else MINOR
            c.add(Finding("boot.time", SYS, sev, f"Démarrage lent : {last:.0f} s" + (" (en hausse)" if trend >= 1.4 else ""),
                          detail=f"Durée du dernier démarrage {last:.0f} s ; médiane des 5 derniers {median(recent) / 1000:.0f} s"
                                 + (f" contre {median(older) / 1000:.0f} s auparavant." if older else "."),
                          impact="Perte de temps quotidienne ; une dégradation progressive annonce souvent un disque en fin de vie ou "
                                 "une accumulation de programmes au démarrage.",
                          fix="Réduire les programmes au démarrage, vérifier le disque, mettre à jour les pilotes cités.",
                          evidence=ev, predictive=trend >= 1.4))
        else:
            c.add(Finding("boot.time.ok", SYS, OK, f"Durée de démarrage correcte ({last:.0f} s)"))
    st = c.lst("software", "startup")
    if len(st) > 15 and not c.is_server:
        c.add(Finding("boot.startup", SYS, MINOR, f"{len(st)} programmes lancés au démarrage",
                      detail=", ".join(sorted({s.get('name') or '' for s in st}))[:400],
                      impact="Ralentit l'ouverture de session et consomme de la mémoire en permanence.",
                      fix="Désactiver les programmes inutiles (Gestionnaire des tâches › Démarrage)."))


def services(c: Ctx):
    bad = []
    for s in c.lst("software", "services"):
        if (s.get("start") or "") != "Auto" or (s.get("state") or "") == "Running":
            continue
        if s.get("trigger") or SERVICE_IGNORE.match(s.get("name") or ""):
            continue
        if s.get("delayed") == 1 and (c.uptime_days or 1) < 0.02:
            continue
        bad.append(s)
    if bad:
        crashed = [s for s in bad if int(s.get("exit") or 0) not in (0, 1077)]
        c.add(Finding("svc.stopped", SYS, MAJOR if crashed else MINOR, f"Services automatiques arrêtés : {len(bad)}",
                      detail="; ".join(f"{s.get('display')} ({s.get('name')})" + (f" — code {s['exit']}" if int(s.get('exit') or 0) not in (0, 1077) else "")
                                       for s in bad[:10]),
                      impact="Ces services devraient fonctionner en permanence : la fonctionnalité correspondante est indisponible.",
                      fix="Démarrer le service et lire l'erreur ; s'il n'est plus utile, le passer en démarrage manuel ou désinstaller le logiciel."))
    fails = c.events("Service Control Manager", {7000, 7009, 7011, 7022, 7023, 7024, 7026, 7038})
    per = Counter()
    for g in fails:
        per[(g.get("props") or ["?"])[0]] += int(g.get("count") or 0)
    noisy = [(n, k) for n, k in per.most_common() if k >= 3]
    if noisy:
        c.add(Finding("svc.start_fail", SYS, MINOR, f"Services en échec de démarrage répété ({len(noisy)})",
                      detail="; ".join(f"{n} ({k}×)" for n, k in noisy[:6]),
                      impact="Fonctionnalités indisponibles, journal système saturé d'erreurs qui masquent les vrais problèmes.",
                      fix="Corriger la configuration ou désactiver les services inutiles concernés."))


def tasks(c: Ctx):
    ok_codes = {0, 1, 267008, 267009, 267010, 267011, 267012, 267014, 2147750687}
    bad = []
    for t in c.lst("software", "tasks"):
        res = t.get("last_result")
        lr = parse_dt(t.get("last_run"))
        if res is None or int(res) in ok_codes or not lr or lr.year < 2000 or (c.now - lr).days > 60:
            continue
        if (t.get("state") or "").lower() == "disabled":
            continue
        bad.append(t)
    if bad:
        c.add(Finding("task.failed", SYS, MINOR, f"Tâches planifiées en échec : {len(bad)}",
                      detail="; ".join(f"{t.get('path', '')}{t.get('name')} (code 0x{int(t['last_result']) & 0xFFFFFFFF:08X}, "
                                       f"le {fr_date(parse_dt(t.get('last_run')))})" for t in bad[:8]),
                      impact="Sauvegardes, synchronisations ou scripts de maintenance qui ne s'exécutent plus correctement.",
                      fix="Vérifier chaque tâche (chemin du programme, compte d'exécution, mot de passe expiré) et la relancer manuellement."))


def network(c: Ctx):
    for a in c.lst("network", "adapters"):
        if (a.get("status") or "") != "Up" or a.get("virtual") or a.get("hidden"):
            continue
        st = a.get("stats") or {}
        rx = st.get("rx_packets") or 0
        errs = (st.get("rx_errors") or 0) + (st.get("tx_errors") or 0)
        if rx > 10000 and errs / rx > 0.001:
            c.add(Finding(f"net.errors.{a.get('name')}", SYS, MAJOR, f"Erreurs sur la carte réseau « {a.get('name')} »",
                          detail=f"{errs} paquet(s) en erreur pour {rx} reçus ({errs / rx * 100:.2f} %).",
                          impact="Lenteurs, coupures, transferts interrompus : souvent un câble, une prise ou un port de switch défectueux.",
                          fix="Changer le câble réseau, tester un autre port du switch, mettre à jour le pilote.", predictive=True))
        bps = a.get("bps") or 0
        media = (a.get("media") or "").lower()
        if bps and bps <= 100_000_000 and ("802.3" in media or "ethernet" in (a.get("description") or "").lower()) \
                and "wireless" not in media and not c.is_vm:
            c.add(Finding(f"net.speed.{a.get('name')}", SYS, MINOR, f"Liaison réseau à {bps // 1_000_000} Mb/s seulement",
                          detail=f"{a.get('description')} est connectée à {a.get('speed')}.",
                          impact="Débit limité à 10 % d'une liaison gigabit : câble abîmé (paires coupées), câble trop ancien ou port lent.",
                          fix="Remplacer le câble (catégorie 5e minimum) et vérifier le port du switch."))
    for ip in c.lst("network", "ip"):
        for a in ip.get("ipv4") or []:
            if a and a.startswith("169.254."):
                c.add(Finding(f"net.apipa.{ip.get('alias')}", SYS, MAJOR, f"Pas d'adresse IP valide sur « {ip.get('alias')} »",
                              detail=f"Adresse automatique {a} : aucun serveur DHCP n'a répondu.",
                              impact="Pas d'accès au réseau sur cette interface.", fix="Vérifier le câble, le switch et le serveur DHCP."))
    con = c.get("network", "connectivity") or {}
    gw = con.get("gateway")
    if gw and gw.get("sent"):
        loss = 100 - gw.get("received", 0) / gw["sent"] * 100
        if loss >= 25:
            c.add(Finding("net.gateway", SYS, MAJOR, f"Pertes vers la passerelle : {loss:.0f} %",
                          detail=f"Passerelle {gw.get('host')} : {gw.get('received')}/{gw.get('sent')} réponses.",
                          impact="Connexion réseau instable.", fix="Vérifier câble, Wi‑Fi, switch et routeur."))
        elif (gw.get("avg_ms") or 0) > 20 and not c.is_vm:
            c.add(Finding("net.gateway_latency", SYS, MINOR, f"Latence élevée vers la passerelle : {gw.get('avg_ms')} ms",
                          detail="Sur un réseau local, la passerelle répond normalement en moins de 5 ms (moins de 20 ms en Wi‑Fi).",
                          fix="Vérifier la qualité du Wi‑Fi ou la charge du réseau."))
    if con.get("dns_ok") is False:
        c.add(Finding("net.dns", SYS, MAJOR, "La résolution DNS échoue",
                      detail=con.get("dns_error") or "", impact="Accès à Internet et aux serveurs par leur nom impossible.",
                      fix="Vérifier les serveurs DNS configurés sur la carte réseau."))
    elif (con.get("dns_ms") or 0) > 400:
        c.add(Finding("net.dns_slow", SYS, MINOR, f"Résolution DNS lente : {con['dns_ms']} ms",
                      fix="Vérifier les serveurs DNS configurés."))
    inet = con.get("internet")
    if inet and inet.get("received") == 0 and con.get("http_ok") is False:
        c.add(Finding("net.internet", SYS, MINOR, "Pas d'accès à Internet",
                      detail="Ni ping ni connexion HTTP vers Internet n'ont abouti (peut être normal sur un réseau isolé)."))
    dnsc = c.events("Microsoft-Windows-DNS-Client", {1014})
    if c.count(dnsc) >= 30:
        c.add(Finding("net.dns_timeouts", SYS, MINOR, f"Délais de résolution DNS dépassés ({c.count(dnsc)} fois)",
                      impact="Lenteurs à l'ouverture des sites et des partages.", fix="Vérifier la fiabilité des serveurs DNS."))
    if c.in_domain:
        nl = c.events("NETLOGON", {5719, 5783, 3210})
        if nl:
            c.add(Finding("net.dc", SYS, MAJOR, "Contrôleur de domaine injoignable par moments",
                          detail=f"{c.count(nl)} erreur(s) NETLOGON.",
                          impact="Échecs d'ouverture de session, stratégies de groupe non appliquées, relation d'approbation cassée.",
                          fix="Vérifier le DNS (doit pointer vers les contrôleurs de domaine), le réseau et l'heure.",
                          evidence=[(nl[0].get("message") or "")[:250]]))
        gp = c.events("Microsoft-Windows-GroupPolicy", {1053, 1054, 1055, 1058, 1129, 1030})
        if gp:
            c.add(Finding("net.gpo", SYS, MAJOR, "Les stratégies de groupe ne s'appliquent pas",
                          detail=f"{c.count(gp)} erreur(s) de traitement des GPO.",
                          impact="Les paramètres de sécurité et de configuration du domaine ne sont pas appliqués.",
                          fix="Exécuter « gpupdate /force » et « gpresult /h » pour identifier la cause (DNS, accès au SYSVOL)."))


def time_sync(c: Ctx):
    t = c.get("network", "time_sync") or {}
    off = t.get("offset_s")
    if off is not None:
        a = abs(off)
        limit_crit = 240 if c.in_domain else 600
        if a >= 5:
            c.add(Finding("time.offset", SYS, CRIT if a >= limit_crit else MAJOR, f"Horloge décalée de {a:.0f} s",
                          detail=f"Écart avec {t.get('reference')} : {off:+.1f} s.".replace(".", ","),
                          impact="Au-delà de 5 minutes, l'authentification Kerberos (domaine) échoue ; les journaux et certificats "
                                 "deviennent incohérents.",
                          fix="Vérifier le service « Temps Windows » et sa source (w32tm /query /source), puis « w32tm /resync »."))
    if (t.get("service") or "").lower() == "stopped" and c.in_domain:
        c.add(Finding("time.service", SYS, MINOR, "Service de synchronisation de l'heure arrêté",
                      fix="Démarrer le service « Temps Windows » (W32Time) en automatique."))


def logs(c: Ctx):
    for l in c.lst("events", "log_coverage"):
        old = parse_dt(l.get("oldest"))
        if old and (c.now - old).days < 7:
            c.add(Finding(f"log.coverage.{l.get('log')}", SYS, MINOR,
                          f"Journal « {l.get('log')} » trop court : {max(0, (c.now - old).days)} jour(s) d'historique",
                          detail=f"Taille maximale {human_bytes(l.get('max_bytes'))}, les événements anciens sont écrasés.",
                          impact="Le diagnostic des incidents passés est impossible (et l'analyse de ce rapport porte sur une période réduite).",
                          fix="Augmenter la taille maximale du journal (au moins 64 Mo) dans l'Observateur d'événements."))
    dism = c.get("software", "dism_health")
    if dism and dism.get("output"):
        o = dism["output"].lower()
        if "repairable" in o or "corrupt" in o and "no component store corruption" not in o:
            c.add(Finding("os.cbs", SYS, MAJOR, "Fichiers système Windows endommagés",
                          detail="Le magasin de composants Windows signale une corruption réparable.",
                          impact="Échecs de mises à jour, fonctionnalités Windows défaillantes.",
                          fix="En administrateur : « DISM /Online /Cleanup-Image /RestoreHealth » puis « sfc /scannow »."))
        elif "no component store corruption" in o:
            c.add(Finding("os.cbs.ok", SYS, OK, "Fichiers système Windows intègres (DISM)"))


def power(c: Ctx):
    pp = c.get("system", "power_plan") or {}
    pid = (pp.get("id") or "").lower()
    # modes « Utilisation normale » et « Économie d'énergie »
    if c.is_server and pid in ("381b4222-f694-41f0-9685-ff5bb260df2e", "a1841308-3c39-4ff4-8e4f-ac06ab3ac0e3"):
        c.add(Finding("power.server", SYS, MINOR, f"Serveur en mode d'alimentation « {pp.get('name')} »",
                      detail="Le processeur réduit sa fréquence pour économiser l'énergie.",
                      impact="Latence accrue pour les applications serveur (bases de données, virtualisation, bureaux à distance).",
                      fix="Choisir le mode « Performances élevées » (powercfg /setactive SCHEME_MIN) et vérifier le réglage dans le BIOS."))


RULES = [os_support, updates, uptime, disk_space, memory, cpu_perf, boot, services, tasks, network, time_sync, logs, power]
