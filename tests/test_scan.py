import os
from datetime import datetime

import pandas as pd
import pytest

os.environ.setdefault("NETSCAN_SKIP_MODEL_LOAD", "1")

from webapp import app as app_module


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "netscan_test.db"
    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))
    app_module.app.config.update(TESTING=True, SECRET_KEY="test-secret")
    app_module.init_db()

    with app_module.app.test_client() as test_client:
        yield test_client


def _fetch_alertes():
    conn = app_module.get_db()
    rows = conn.execute("SELECT * FROM alertes ORDER BY id").fetchall()
    conn.close()
    return rows


def _insert_alert(ip="192.168.1.10", severite="Critique", type_scan="Scan de ports"):
    conn = app_module.get_db()
    conn.execute(
        """
        INSERT INTO alertes (date, ip, type, severite, statut, nb_paquets, rate,
                             syn_count, ports_testes, duree, regles_declenchees)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            ip,
            type_scan,
            severite,
            "Nouvelle",
            42,
            12.5,
            8,
            22,
            3.0,
            "Test rule",
        ),
    )
    conn.commit()
    conn.close()


def _traffic_df(spkts=10, dpkts=8, rate=1.0, syn_count=0, ports_testes=1, dur=1.0):
    return pd.DataFrame(
        {
            "dur": [dur],
            "proto": ["tcp"],
            "service": ["http"],
            "state": ["FIN"],
            "spkts": [spkts],
            "dpkts": [dpkts],
            "rate": [rate],
            "ct_srv_src": [syn_count],
            "ct_src_dport_ltm": [ports_testes],
        }
    )


def test_init_db_creates_default_rules(client):
    conn = app_module.get_db()
    count = conn.execute("SELECT COUNT(*) FROM regles").fetchone()[0]
    names = [row["nom"] for row in conn.execute("SELECT nom FROM regles").fetchall()]
    conn.close()

    assert count == 3
    assert "Détection scan de ports" in names


def test_dashboard_loads_without_alerts(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "NetScan" in response.get_data(as_text=True)


def test_analyser_ip_rejects_invalid_ip_without_creating_alert(client):
    response = client.post("/analyser_ip", data={"ip": "not-an-ip"}, follow_redirects=True)

    assert response.status_code == 200
    assert _fetch_alertes() == []
    assert "Adresse IP invalide" in response.get_data(as_text=True)


def test_analyser_ip_records_info_alert_when_no_traffic(client, monkeypatch):
    monkeypatch.setattr(app_module, "capture_ip_traffic", lambda ip, duration=15: None)

    response = client.post("/analyser_ip", data={"ip": "192.168.1.20"}, follow_redirects=True)

    alerts = _fetch_alertes()
    assert response.status_code == 200
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "192.168.1.20"
    assert alerts[0]["type"] == "Aucun trafic détecté"
    assert alerts[0]["severite"] == "Info"


def test_analyser_ip_detects_port_scan_from_rules(client, monkeypatch):
    monkeypatch.setattr(
        app_module,
        "capture_ip_traffic",
        lambda ip, duration=15: _traffic_df(spkts=35, dpkts=4, rate=8.0, syn_count=12, ports_testes=20),
    )

    response = client.post("/analyser_ip", data={"ip": "192.168.1.30"}, follow_redirects=True)

    alerts = _fetch_alertes()
    assert response.status_code == 200
    assert len(alerts) == 1
    assert alerts[0]["severite"] == "Critique"
    assert "Scan de ports" in alerts[0]["type"]
    assert "Détection scan de ports" in alerts[0]["regles_declenchees"]


def test_alertes_filter_by_severity(client):
    _insert_alert(ip="192.168.1.10", severite="Critique")
    _insert_alert(ip="192.168.1.11", severite="Info", type_scan="Trafic normal")

    response = client.get("/alertes?severite=Critique")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "192.168.1.10" in body
    assert "192.168.1.11" not in body


def test_generer_rapport_returns_csv_and_saves_history(client):
    _insert_alert(ip="192.168.1.40", severite="Critique")

    response = client.post(
        "/rapports/generer",
        data={"date_debut": "2000-01-01", "date_fin": "2999-12-31", "type": "Complet"},
    )

    conn = app_module.get_db()
    rapports_count = conn.execute("SELECT COUNT(*) FROM rapports").fetchone()[0]
    conn.close()

    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/csv")
    assert "rapport_complet_2000-01-01_2999-12-31.csv" in response.headers["Content-Disposition"]
    assert "192.168.1.40" in response.get_data(as_text=True)
    assert rapports_count == 1


def test_attack_analysis_classifies_syn_flood(client):
    alerte = {
        "syn_count": 120,
        "ports_testes": 5,
        "rate": 2,
        "nb_paquets": 150,
        "duree": 4.5,
        "type": "Scan",
        "severite": "Critique",
    }

    info = app_module._analyser_type_attaque(alerte, [])

    assert info["type"] == "SYN Flood"
    assert info["risk"] == "Très élevé"
    assert len(info["phases"]) == 4
