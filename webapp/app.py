from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
DB_PATH = "netscan.db"

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
            statut TEXT DEFAULT 'Nouvelle'
        )
    """)

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

    # Données fictives si vide
    if c.execute("SELECT COUNT(*) FROM alertes").fetchone()[0] == 0:
        alertes = [
            ("2026-03-12 14:32", "192.168.1.105", "SYN Scan", "Critique", "Nouvelle"),
            ("2026-03-12 13:15", "10.0.0.42",     "UDP Scan", "Moyen",    "Nouvelle"),
            ("2026-03-11 22:08", "172.16.0.8",    "Connect Scan", "Info", "Traitée"),
            ("2026-03-11 18:45", "192.168.2.200", "SYN Scan", "Critique", "Nouvelle"),
            ("2026-03-10 09:12", "10.0.0.15",     "FIN Scan", "Moyen",    "Traitée"),
        ]
        c.executemany("INSERT INTO alertes (date, ip, type, severite, statut) VALUES (?,?,?,?,?)", alertes)

    if c.execute("SELECT COUNT(*) FROM regles").fetchone()[0] == 0:
        regles = [
            ("Détection SYN Flood", "SYN", 100, 1),
            ("Scan UDP suspect",    "UDP", 50,  0),
        ]
        c.executemany("INSERT INTO regles (nom, type_scan, seuil, active) VALUES (?,?,?,?)", regles)

    conn.commit()
    conn.close()

# ─── Dashboard ──────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    conn = get_db()
    total     = conn.execute("SELECT COUNT(*) FROM alertes").fetchone()[0]
    critiques = conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Critique'").fetchone()[0]
    ips       = conn.execute("SELECT COUNT(DISTINCT ip) FROM alertes").fetchone()[0]
    recentes  = conn.execute("SELECT * FROM alertes ORDER BY date DESC LIMIT 5").fetchall()
    conn.close()
    return render_template("dashboard.html",
        total=total, critiques=critiques, ips=ips, recentes=recentes)

# ─── Alertes ────────────────────────────────────────────────────────────────

@app.route("/alertes")
def alertes():
    search   = request.args.get("search", "")
    severite = request.args.get("severite", "all")
    conn = get_db()
    query = "SELECT * FROM alertes WHERE 1=1"
    params = []
    if search:
        query += " AND (ip LIKE ? OR type LIKE ?)"
        params += [f"%{search}%", f"%{search}%"]
    if severite != "all":
        query += " AND severite = ?"
        params.append(severite)
    query += " ORDER BY date DESC"
    alertes = conn.execute(query, params).fetchall()
    counts = {
        "Critique": conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Critique'").fetchone()[0],
        "Moyen":    conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Moyen'").fetchone()[0],
        "Info":     conn.execute("SELECT COUNT(*) FROM alertes WHERE severite='Info'").fetchone()[0],
    }
    conn.close()
    return render_template("alertes.html",
        alertes=alertes, counts=counts, search=search, severite=severite)

@app.route("/alertes/traiter/<int:id>")
def traiter_alerte(id):
    conn = get_db()
    conn.execute("UPDATE alertes SET statut='Traitée' WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for("alertes"))

# ─── Règles ─────────────────────────────────────────────────────────────────

@app.route("/regles")
def regles():
    conn = get_db()
    regles = conn.execute("SELECT * FROM regles").fetchall()
    conn.close()
    return render_template("regles.html", regles=regles)

@app.route("/regles/ajouter", methods=["POST"])
def ajouter_regle():
    nom       = request.form["nom"]
    type_scan = request.form["type_scan"]
    seuil     = request.form["seuil"]
    conn = get_db()
    conn.execute("INSERT INTO regles (nom, type_scan, seuil, active) VALUES (?,?,?,1)",
                 (nom, type_scan, seuil))
    conn.commit()
    conn.close()
    return redirect(url_for("regles"))

@app.route("/regles/toggle/<int:id>")
def toggle_regle(id):
    conn = get_db()
    conn.execute("UPDATE regles SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?", (id,))
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

# ─── Rapports ───────────────────────────────────────────────────────────────

@app.route("/rapports")
def rapports():
    conn = get_db()
    rapports = conn.execute("SELECT * FROM rapports ORDER BY date_generation DESC").fetchall()
    conn.close()
    return render_template("rapports.html", rapports=rapports)

@app.route("/rapports/generer", methods=["POST"])
def generer_rapport():
    date_debut = request.form["date_debut"]
    date_fin   = request.form["date_fin"]
    type_r     = request.form["type"]
    now        = datetime.now().strftime("%Y-%m-%d %H:%M")
    conn = get_db()
    conn.execute("INSERT INTO rapports (date_generation, date_debut, date_fin, type) VALUES (?,?,?,?)",
                 (now, date_debut, date_fin, type_r))
    conn.commit()
    conn.close()
    return redirect(url_for("rapports"))

# ─── Lancement ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=True)