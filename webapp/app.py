from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
import sqlite3
import os
import csv
import io
from datetime import datetime, timedelta
import joblib
import pandas as pd
import threading
import ipaddress

from network.capture_traffic import capture_ip_traffic
from network.simulate_attack import simulate_nmap_attack
from network.live_ids import start_live_ids
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, flash
import ipaddress
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "change-me-in-prod")
DB_PATH = "netscan.db"

# Charger modèle ML
model = joblib.load("ml/model.pkl")
encoders = joblib.load("ml/encoders.pkl")

# ─── Init base de données ───────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS alertes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            ip TEXT NOT NULL,
            type TEXT NOT NULL,
            severite TEXT NOT NULL,
            statut TEXT DEFAULT 'Nouvelle',
            nb_paquets INTEGER DEFAULT 0,
            rate REAL DEFAULT 0,
            syn_count INTEGER DEFAULT 0,
            ports_testes INTEGER DEFAULT 0,
            duree REAL DEFAULT 0,
            regles_declenchees TEXT DEFAULT ''
        )
    """)

    for col, definition in [
        ("syn_count",          "INTEGER DEFAULT 0"),
        ("ports_testes",       "INTEGER DEFAULT 0"),
        ("duree",              "REAL DEFAULT 0"),
        ("regles_declenchees", "TEXT DEFAULT ''"),
    ]:
        try:
            c.execute(f"ALTER TABLE alertes ADD COLUMN {col} {definition}")
        except sqlite3.OperationalError:
            pass

    c.execute("""
        CREATE TABLE IF NOT EXISTS regles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            type_scan TEXT NOT NULL,
            seuil INTEGER NOT NULL,
            active INTEGER DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS rapports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date_generation TEXT NOT NULL,
            date_debut TEXT NOT NULL,
            date_fin TEXT NOT NULL,
            type TEXT NOT NULL
        )
    """)

    # ─── Règles par défaut (uniquement si la table est vide) ───────────────
    nb_regles = c.execute("SELECT COUNT(*) FROM regles").fetchone()[0]
    if nb_regles == 0:
        regles_defaut = [
            ("Détection scan de ports",    "PORT_SCAN", 15),
            ("Détection SYN flood",        "SYN",       100),
            ("Trafic anormalement rapide", "RATE",      10),
        ]
        c.executemany(
            "INSERT INTO regles (nom, type_scan, seuil, active) VALUES (?,?,?,1)",
            regles_defaut
        )

    conn.commit()
    conn.close()


# ─── Dashboard ──────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    conn = get_db()
    total    = conn.execute("SELECT COUNT(*) FROM alertes").fetchone()[0]
    critiques = conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Critique'").fetchone()[0]
    ips      = conn.execute("SELECT COUNT(DISTINCT ip) FROM alertes").fetchone()[0]
    recentes = conn.execute("SELECT * FROM alertes ORDER BY date DESC LIMIT 5").fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        critiques=critiques,
        ips=ips,
        recentes=recentes
    )


# ─── SIMULATION ATTAQUE ─────────────────────────────────────────────────────

@app.route("/simulate_attack/<ip>")
def simulate_attack(ip):
    print("🚨 ROUTE SIMULATION ACTIVE")
    print("IP =", ip)
    simulate_nmap_attack(ip)
    return redirect(url_for("dashboard"))
import time

@app.route("/tester_attaque", methods=["POST"])
def tester_attaque():
    """Lance nmap en arrière-plan PUIS analyse l'IP : 1 clic = démo complète."""
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("⚠️ Veuillez saisir une adresse IP.", "error")
        return redirect(url_for("dashboard"))

    # 1) Démarre nmap en arrière-plan (ne bloque pas)
    simulate_nmap_attack(ip)

    # 2) Petite pause pour laisser nmap envoyer ses 1ers paquets
    time.sleep(1)

    # 3) On relance la même logique d'analyse → la capture (15 s)
    #    va capturer pendant que nmap continue d'envoyer ses SYN.
    #    On simule un POST interne en réutilisant la route existante.
    from werkzeug.datastructures import ImmutableMultiDict
    request.form = ImmutableMultiDict([("ip", ip)])
    return analyser_ip()

# ─── ALERTES ────────────────────────────────────────────────────────────────

@app.route("/alertes")
def alertes():
    search   = request.args.get("search", "").strip()
    severite = request.args.get("severite", "all").strip() or "all"

    conn   = get_db()
    query  = "SELECT * FROM alertes WHERE 1=1"
    params = []

    if search:
        query += " AND (ip LIKE ? OR type LIKE ?)"
        params += [f"%{search}%", f"%{search}%"]

    if severite != "all":
        query += " AND severite = ?"
        params.append(severite)

    query += " ORDER BY date DESC"
    alertes_list = conn.execute(query, params).fetchall()

    counts = {
        "Critique": conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Critique'").fetchone()[0],
        "Moyen":    conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Moyen'").fetchone()[0],
        "Info":     conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Info'").fetchone()[0],
    }
    conn.close()

    return render_template(
        "alertes.html",
        alertes=alertes_list,
        counts=counts,
        search=search,
        severite=severite
    )


@app.route("/alertes/traiter/<int:id>")
def traiter_alerte(id):
    conn = get_db()
    conn.execute("UPDATE alertes SET statut='Traitée' WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for("alertes"))


@app.route("/alertes/supprimer/<int:id>")
def supprimer_alerte(id):
    conn = get_db()
    conn.execute("DELETE FROM alertes WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for("alertes"))


@app.route("/alertes/supprimer_tout")
def supprimer_tout():
    conn = get_db()
    conn.execute("DELETE FROM alertes")
    conn.commit()
    conn.close()
    return redirect(url_for("alertes"))


@app.route("/alertes/export_csv")
def export_csv():
    period = request.args.get("period", None)
    conn   = get_db()
    query  = "SELECT * FROM alertes"
    params = []

    if period == "24h":
        since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M")
        query += " WHERE date >= ?"
        params.append(since)
    elif period == "7d":
        since = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M")
        query += " WHERE date >= ?"
        params.append(since)
    elif period == "30d":
        since = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M")
        query += " WHERE date >= ?"
        params.append(since)

    query += " ORDER BY date DESC"
    alertes_list = conn.execute(query, params).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Date","IP","Type","Sévérité","Statut","Paquets","Rate","SYN","Ports","Durée","Règles"])
    for a in alertes_list:
        writer.writerow([
            a["id"], a["date"], a["ip"], a["type"],
            a["severite"], a["statut"],
            a["nb_paquets"] or "",
            a["rate"] or "",
            a["syn_count"] or "",
            a["ports_testes"] or "",
            a["duree"] or "",
            a["regles_declenchees"] or "",
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=alertes_netscan.csv"
    response.headers["Content-type"] = "text/csv; charset=utf-8"
    return response


# ─── HISTORIQUE ─────────────────────────────────────────────────────────────

@app.route("/historique")
def historique():
    search     = request.args.get("search", "")
    severite   = request.args.get("severite", "all")
    date_debut = request.args.get("date_debut", "")
    date_fin   = request.args.get("date_fin", "")

    conn   = get_db()
    query  = "SELECT * FROM alertes WHERE 1=1"
    params = []

    if search:
        query += " AND ip LIKE ?"
        params.append(f"%{search}%")

    if severite != "all":
        query += " AND severite = ?"
        params.append(severite)

    if date_debut:
        query += " AND date >= ?"
        params.append(date_debut + " 00:00")   # ← ajout " 00:00"

    if date_fin:
        query += " AND date <= ?"
        params.append(date_fin + " 23:59")

    query += " ORDER BY date DESC"
    scans = conn.execute(query, params).fetchall()

    stats = {
        "total":    conn.execute("SELECT COUNT(*) FROM alertes").fetchone()[0],
        "critiques": conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Critique'").fetchone()[0],
        "moyens":   conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Moyen'").fetchone()[0],
        "infos":    conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Info'").fetchone()[0],
    }
    conn.close()

    return render_template(
        "historique.html",
        scans=scans,
        stats=stats,
        search=search,
        severite=severite,
        date_debut=date_debut,
        date_fin=date_fin
    )

@app.route("/historique/export_csv")
def export_historique_csv():
    conn  = get_db()
    scans = conn.execute("SELECT * FROM alertes ORDER BY date DESC").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Date","IP","Résultat","Sévérité","Statut","Paquets","Rate","SYN","Ports","Durée","Règles"])
    for s in scans:
        writer.writerow([
            s["id"], s["date"], s["ip"], s["type"],
            s["severite"], s["statut"],
            s["nb_paquets"] or "",
            s["rate"] or "",
            s["syn_count"] or "",
            s["ports_testes"] or "",
            s["duree"] or "",
            s["regles_declenchees"] or "",
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=historique_scans.csv"
    response.headers["Content-type"] = "text/csv; charset=utf-8"
    return response


@app.route("/historique/supprimer_tout")
def supprimer_historique():
    conn = get_db()
    conn.execute("DELETE FROM alertes")
    conn.commit()
    conn.close()
    return redirect(url_for("historique"))


# ─── RÈGLES ─────────────────────────────────────────────────────────────────

@app.route("/regles")
def regles():
    conn = get_db()
    regles_list = conn.execute("SELECT * FROM regles").fetchall()
    conn.close()
    return render_template("regles.html", regles=regles_list)


@app.route("/regles/ajouter", methods=["POST"])
def ajouter_regle():
    nom       = request.form["nom"]
    type_scan = request.form["type_scan"]
    seuil     = request.form["seuil"]

    conn = get_db()
    conn.execute(
        "INSERT INTO regles (nom, type_scan, seuil, active) VALUES (?,?,?,1)",
        (nom, type_scan, seuil)
    )
    conn.commit()
    conn.close()
    return redirect(url_for("regles"))


@app.route("/regles/toggle/<int:id>")
def toggle_regle(id):
    conn = get_db()
    conn.execute(
        "UPDATE regles SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?",
        (id,)
    )
    conn.commit()
    conn.close()
    return redirect(url_for("regles"))


@app.route("/regles/supprimer/<int:id>")
def supprimer_regle(id):
    conn = get_db()
    conn.execute("DELETE FROM regles WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for("regles"))

# ─── RAPPORTS ───────────────────────────────────────────────────────────────

@app.route("/rapports")
def rapports():
    conn = get_db()
    rapports_list = conn.execute(
        "SELECT * FROM rapports ORDER BY date_generation DESC"
    ).fetchall()
    conn.close()
    return render_template("rapports.html", rapports=rapports_list)


# ⚠️ PAS de @app.route ici — c'est une fonction utilitaire interne
def _generer_csv_rapport(date_debut, date_fin, type_rapport):
    conn = get_db()
    query  = "SELECT * FROM alertes WHERE date >= ? AND date <= ?"
    params = [date_debut + " 00:00", date_fin + " 23:59"]

    if type_rapport == "Alertes":
        query += " AND severite IN ('Critique','Moyen')"
    elif type_rapport == "Top IPs":
        query = """
            SELECT ip,
                   COUNT(*) as nb_alertes,
                   SUM(CASE WHEN severite='Critique' THEN 1 ELSE 0 END) as critiques,
                   SUM(CASE WHEN severite='Moyen'    THEN 1 ELSE 0 END) as moyens,
                   SUM(CASE WHEN severite='Info'     THEN 1 ELSE 0 END) as infos
            FROM alertes
            WHERE date >= ? AND date <= ?
            GROUP BY ip
            ORDER BY nb_alertes DESC
        """

    rows = conn.execute(query, params).fetchall()

    stats = conn.execute("""
        SELECT
            COUNT(*)                                              AS total,
            SUM(CASE WHEN severite='Critique' THEN 1 ELSE 0 END) AS critiques,
            SUM(CASE WHEN severite='Moyen'    THEN 1 ELSE 0 END) AS moyens,
            SUM(CASE WHEN severite='Info'     THEN 1 ELSE 0 END) AS infos,
            COUNT(DISTINCT ip)                                    AS ips_uniques
        FROM alertes WHERE date >= ? AND date <= ?
    """, params).fetchone()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["NetScan - Rapport", type_rapport])
    writer.writerow(["Période", f"{date_debut}  →  {date_fin}"])
    writer.writerow(["Généré le", datetime.now().strftime("%Y-%m-%d %H:%M")])
    writer.writerow([])
    writer.writerow(["Total alertes", stats["total"] or 0])
    writer.writerow(["Critiques",     stats["critiques"] or 0])
    writer.writerow(["Moyens",        stats["moyens"] or 0])
    writer.writerow(["Info",          stats["infos"] or 0])
    writer.writerow(["IPs uniques",   stats["ips_uniques"] or 0])
    writer.writerow([])

    if type_rapport == "Statistiques":
        pass
    elif type_rapport == "Top IPs":
        writer.writerow(["IP", "Nb alertes", "Critiques", "Moyens", "Info"])
        for r in rows:
            writer.writerow([r["ip"], r["nb_alertes"], r["critiques"], r["moyens"], r["infos"]])
    else:
        writer.writerow(["ID","Date","IP","Type","Sévérité","Statut",
                         "Paquets","Rate","SYN","Ports","Durée","Règles"])
        for a in rows:
            writer.writerow([
                a["id"], a["date"], a["ip"], a["type"],
                a["severite"], a["statut"],
                a["nb_paquets"] or "", a["rate"] or "",
                a["syn_count"] or "", a["ports_testes"] or "",
                a["duree"] or "", a["regles_declenchees"] or "",
            ])

    filename = f"rapport_{type_rapport.lower().replace(' ', '_')}_{date_debut}_{date_fin}.csv"
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-type"] = "text/csv; charset=utf-8"
    return response


@app.route("/rapports/generer", methods=["POST"])
def generer_rapport():
    date_debut   = request.form.get("date_debut", "").strip()
    date_fin     = request.form.get("date_fin", "").strip()
    type_rapport = request.form.get("type", "Complet").strip()

    if not date_debut or not date_fin:
        flash("⚠️ Veuillez choisir une date de début et de fin.", "error")
        return redirect(url_for("rapports"))

    if date_debut > date_fin:
        flash("❌ La date de début doit être avant la date de fin.", "error")
        return redirect(url_for("rapports"))

    conn = get_db()
    conn.execute("""
        INSERT INTO rapports (date_generation, date_debut, date_fin, type)
        VALUES (?,?,?,?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        date_debut, date_fin, type_rapport
    ))
    conn.commit()
    conn.close()

    return _generer_csv_rapport(date_debut, date_fin, type_rapport)


@app.route("/rapports/telecharger/<int:id>")
def telecharger_rapport(id):
    conn = get_db()
    r = conn.execute("SELECT * FROM rapports WHERE id=?", (id,)).fetchone()
    conn.close()
    if not r:
        flash("❌ Rapport introuvable.", "error")
        return redirect(url_for("rapports"))
    return _generer_csv_rapport(r["date_debut"], r["date_fin"], r["type"])


@app.route("/rapports/supprimer/<int:id>")
def supprimer_rapport(id):
    conn = get_db()
    conn.execute("DELETE FROM rapports WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for("rapports"))


# ─── ANALYSER IP ────────────────────────────────────────────────────────────
@app.route("/analyser_ip", methods=["POST"])
def analyser_ip():
    ip = request.form.get("ip", "").strip()

    # ─── Validation de l'adresse IP ─────────────────────────────────────────
    if not ip:
        flash("⚠️ Veuillez saisir une adresse IP.", "error")
        return redirect(url_for("dashboard"))

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        flash(f"❌ Adresse IP invalide : '{ip}'. Exemple valide : 192.168.1.10", "error")
        return redirect(url_for("dashboard"))

    if not isinstance(ip_obj, ipaddress.IPv4Address):
        flash("❌ Seules les adresses IPv4 sont supportées.", "error")
        return redirect(url_for("dashboard"))

    # IP réservées : pas de scan utile dessus
    if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
        flash(f"❌ L'IP {ip} est réservée (loopback/multicast). Choisis une vraie IP du réseau.", "error")
        return redirect(url_for("dashboard"))

    print(f"\n🔍 Surveillance de l'IP : {ip}")

    # ─── Tout le pipeline est protégé contre les plantages ─────────────────
    try:
        df = capture_ip_traffic(ip, duration=15)

        if df is None or len(df) == 0:
            conn = get_db()
            conn.execute("""
                INSERT INTO alertes (date, ip, type, severite, statut, nb_paquets, rate,
                                     syn_count, ports_testes, duree, regles_declenchees)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                ip, "Aucun trafic détecté", "Info", "Nouvelle",
                0, 0.0, 0, 0, 0.0, ""
            ))
            conn.commit()
            conn.close()
            flash(f"ℹ️ Aucun trafic détecté pour {ip}.", "info")
            return redirect(url_for("dashboard"))

        # ─── Extraction des métriques (avec valeurs par défaut sûres) ──────
        spkts        = int(df["spkts"][0]            or 0)
        dpkts        = int(df["dpkts"][0]            or 0)
        rate         = float(df["rate"][0]           or 0.0)
        dur          = float(df["dur"][0]            or 0.0)
        syn_count    = int(df["ct_srv_src"][0]       or 0)
        ports_testes = int(df["ct_src_dport_ltm"][0] or 0)

        # ─── Encodage défensif (catégorie inconnue → 0) ────────────────────
        for col in ("proto", "service", "state"):
            try:
                df[col] = encoders[col].transform(df[col])
            except (ValueError, KeyError):
                df[col] = 0
                print(f"⚠️ Valeur inconnue pour '{col}', remplacée par 0.")

        is_scan = False
        regles_declenchees = []

        # ─── Règles personnalisées depuis la base ───────────────────────────
        conn = get_db()
        regles_db = conn.execute("SELECT * FROM regles WHERE active=1").fetchall()
        conn.close()

        for r in regles_db:
            nom       = r["nom"]
            type_scan = (r["type_scan"] or "").upper()
            try:
                seuil = int(r["seuil"])
            except (TypeError, ValueError):
                continue  # règle mal configurée → ignorée

            declenchee = False

            if type_scan in ("PORT_SCAN", "PORTS"):
                if ports_testes > seuil:
                    declenchee = True
            elif type_scan == "SYN":
                if syn_count > seuil:
                    declenchee = True
            elif type_scan == "RATE":
                if rate > seuil:
                    declenchee = True
            elif type_scan in ("TCP", "UDP", "ICMP", "FIN"):
                # Volume de paquets envoyés
                if spkts > seuil:
                    declenchee = True
            else:
                # Type inconnu → on compare au volume de paquets par défaut
                if spkts > seuil:
                    declenchee = True

            if declenchee:
                is_scan = True
                regles_declenchees.append(f"{nom} (seuil {seuil})")

        # ─── Règles intégrées (toujours actives) ────────────────────────────
        if spkts > 20 and dpkts < spkts * 0.5:
            is_scan = True
            regles_declenchees.append("Règle 1: beaucoup de paquets, peu de réponses")

        if rate > 5 and spkts > 15:
            is_scan = True
            regles_declenchees.append("Règle 2: trafic rapide")

        if spkts > 30:
            is_scan = True
            regles_declenchees.append("Règle 3: volume élevé")

        # ─── Prédiction ML protégée ────────────────────────────────────────
        try:
            pred = int(model.predict(df)[0])
        except Exception as e:
            print(f"⚠️ Erreur ML : {e}")
            pred = 0

        if is_scan:
            type_scan = "⚠️ Scan de ports détecté sur cette IP"
            severite  = "Critique"
            flash(f"🚨 Attaque détectée sur {ip} : scan de ports !", "danger")
        elif pred == 1:
            type_scan = "⚠️ Comportement suspect (ML)"
            severite  = "Moyen"
            regles_declenchees.append("ML: comportement suspect")
            flash(f"⚠️ Comportement suspect détecté sur {ip}.", "warning")
        else:
            type_scan = "✅ Trafic normal"
            severite  = "Info"
            flash(f"✅ Trafic normal pour {ip}.", "success")

        conn = get_db()
        conn.execute("""
            INSERT INTO alertes (date, ip, type, severite, statut, nb_paquets, rate,
                                 syn_count, ports_testes, duree, regles_declenchees)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            ip, type_scan, severite, "Nouvelle",
            spkts, round(rate, 2),
            syn_count, ports_testes, round(dur, 2),
            " | ".join(regles_declenchees)
        ))
        conn.commit()
        conn.close()

        return redirect(url_for("dashboard"))

    except Exception as e:
        # Filet de sécurité ultime : toute exception non prévue
        print(f"❌ Erreur lors de l'analyse de {ip} : {e}")
        flash(f"❌ Une erreur est survenue lors de l'analyse de {ip} : {e}", "error")
        return redirect(url_for("dashboard"))
# ─── API STATS ──────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    conn = get_db()
    data = conn.execute("""
        SELECT substr(date,1,10) as jour, COUNT(*) as total
        FROM alertes
        GROUP BY jour
        ORDER BY jour DESC LIMIT 7
    """).fetchall()

    labels = [row["jour"] for row in data]
    values = [row["total"] for row in data]
    conn.close()

    return jsonify({"labels": labels[::-1], "values": values[::-1]})


@app.route("/api/types")
def api_types():
    conn = get_db()
    data = conn.execute("""
        SELECT severite as type, COUNT(*) as total
        FROM alertes
        GROUP BY severite
    """).fetchall()

    labels = [row["type"] for row in data]
    values = [row["total"] for row in data]
    conn.close()

    return jsonify({"labels": labels, "values": values})

# ─── DÉTAIL D'UNE ALERTE ─────────────────────────────────────────────────────

@app.route("/alertes/<int:id>")
def detail_alerte(id):
    conn = get_db()
    alerte = conn.execute("SELECT * FROM alertes WHERE id=?", (id,)).fetchone()
    conn.close()

    if not alerte:
        flash("❌ Alerte introuvable.", "error")
        return redirect(url_for("alertes"))

    regles = []
    if alerte["regles_declenchees"]:
        regles = [r.strip() for r in alerte["regles_declenchees"].split("|") if r.strip()]

    attack_info = _analyser_type_attaque(alerte, regles)

    return render_template("detail_alerte.html", alerte=alerte, regles=regles, attack_info=attack_info)


def _analyser_type_attaque(alerte, regles):
    syn   = alerte["syn_count"]    or 0
    ports = alerte["ports_testes"] or 0
    rate  = alerte["rate"]         or 0
    pkts  = alerte["nb_paquets"]   or 0
    dur   = alerte["duree"]        or 0

    if syn > 100:
        attack_type  = "SYN Flood"
        attack_desc  = "Envoi massif de paquets SYN sans compléter la poignée de main TCP. Objectif : saturer les ressources de la cible."
        attack_icon  = "bi-lightning-fill"
        attack_color = "#f85149"
        mitre        = "T1498 — Network Denial of Service"
        risk         = "Très élevé"
    elif ports > 50:
        attack_type  = "Scan de ports agressif (Nmap -sS)"
        attack_desc  = "Balayage SYN sur un grand nombre de ports. L'attaquant cherche des services ouverts sans établir de connexion complète."
        attack_icon  = "bi-radar"
        attack_color = "#f85149"
        mitre        = "T1046 — Network Service Discovery"
        risk         = "Élevé"
    elif ports > 15:
        attack_type  = "Scan de ports modéré"
        attack_desc  = "Sondage de plusieurs ports TCP. Peut indiquer une reconnaissance réseau avant une attaque plus ciblée."
        attack_icon  = "bi-search"
        attack_color = "#e3b341"
        mitre        = "T1046 — Network Service Discovery"
        risk         = "Moyen"
    elif rate > 10:
        attack_type  = "Trafic anormalement rapide"
        attack_desc  = "Volume de paquets par seconde très supérieur à la normale. Peut indiquer un flood ou un outil automatisé."
        attack_icon  = "bi-speedometer2"
        attack_color = "#e3b341"
        mitre        = "T1498 — Network Denial of Service"
        risk         = "Moyen"
    elif "ML" in str(alerte["type"]):
        attack_type  = "Comportement suspect (ML)"
        attack_desc  = "Le modèle ML a détecté un comportement statistiquement anormal par rapport au trafic réseau habituel."
        attack_icon  = "bi-cpu"
        attack_color = "#e3b341"
        mitre        = "T1040 — Network Sniffing"
        risk         = "Moyen"
    else:
        attack_type  = "Trafic normal"
        attack_desc  = "Aucun comportement malveillant détecté."
        attack_icon  = "bi-shield-check"
        attack_color = "#3fb950"
        mitre        = "—"
        risk         = "Aucun"

    phases = []
    if "Scan" in attack_type or "Flood" in attack_type:
        phases = [
            {"step": "1", "label": "Reconnaissance", "desc": "L'attaquant identifie l'IP cible sur le réseau local",    "icon": "bi-binoculars",        "color": "#58a6ff"},
            {"step": "2", "label": "Lancement scan",  "desc": f"Envoi de {pkts} paquets TCP SYN vers la cible",          "icon": "bi-send",              "color": "#e3b341"},
            {"step": "3", "label": "Détection IDS",   "desc": f"NetScan détecte l'anomalie après {dur:.1f}s de capture", "icon": "bi-shield-exclamation","color": "#f85149"},
            {"step": "4", "label": "Alerte générée",  "desc": f"Alerte {alerte['severite']} enregistrée en base",        "icon": "bi-bell-fill",         "color": "#3fb950"},
        ]

    return {
        "type":   attack_type,
        "desc":   attack_desc,
        "icon":   attack_icon,
        "color":  attack_color,
        "mitre":  mitre,
        "risk":   risk,
        "phases": phases,
    }

# ─── LANCEMENT ──────────────────────────────────────────────────────────────

def run_ids():
    start_live_ids()


if __name__ == "__main__":
    init_db()

    thread = threading.Thread(target=run_ids)
    thread.daemon = True
    thread.start()

    app.run(debug=True)