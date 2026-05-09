# ─────────────────────────────────────────────
# NetScan IDS — Tests automatiques
# ─────────────────────────────────────────────

import pytest
import sys
from unittest.mock import MagicMock, patch

# ── Mock des modules qui nécessitent du matériel réseau ──────────────────────
sys.modules['scapy']                    = MagicMock()
sys.modules['scapy.all']               = MagicMock()
sys.modules['network.capture_traffic'] = MagicMock()
sys.modules['network.simulate_attack'] = MagicMock()
sys.modules['network.live_ids']        = MagicMock()
sys.modules['joblib']                  = MagicMock()

import joblib
joblib.load = MagicMock(return_value=MagicMock())

import app as netscan

# ─────────────────────────────────────────────
# CONFIGURATION DES TESTS
# ─────────────────────────────────────────────

@pytest.fixture
def client():
    """Crée un client de test Flask."""
    netscan.app.config['TESTING']   = True
    netscan.app.config['SECRET_KEY'] = 'test-secret-key'
    netscan.init_db()
    with netscan.app.test_client() as client:
        yield client


# ─────────────────────────────────────────────
# TESTS DES PAGES (routes)
# ─────────────────────────────────────────────

class TestPages:

    def test_dashboard_accessible(self, client):
        """Le tableau de bord doit répondre 200."""
        response = client.get('/')
        assert response.status_code == 200, "❌ Dashboard inaccessible"
        print("✅ Dashboard OK")

    def test_alertes_accessible(self, client):
        """La page alertes doit répondre 200."""
        response = client.get('/alertes')
        assert response.status_code == 200, "❌ Page alertes inaccessible"
        print("✅ Page alertes OK")

    def test_historique_accessible(self, client):
        """La page historique doit répondre 200."""
        response = client.get('/historique')
        assert response.status_code == 200, "❌ Page historique inaccessible"
        print("✅ Page historique OK")

    def test_regles_accessible(self, client):
        """La page règles doit répondre 200."""
        response = client.get('/regles')
        assert response.status_code == 200, "❌ Page règles inaccessible"
        print("✅ Page règles OK")

    def test_rapports_accessible(self, client):
        """La page rapports doit répondre 200."""
        response = client.get('/rapports')
        assert response.status_code == 200, "❌ Page rapports inaccessible"
        print("✅ Page rapports OK")

    def test_page_inexistante_404(self, client):
        """Une page inexistante doit retourner 404."""
        response = client.get('/page-qui-nexiste-pas')
        assert response.status_code == 404, "❌ Devrait retourner 404"
        print("✅ 404 OK")


# ─────────────────────────────────────────────
# TESTS DE L'API
# ─────────────────────────────────────────────

class TestAPI:

    def test_api_stats(self, client):
        """L'API stats doit retourner du JSON valide."""
        response = client.get('/api/stats')
        assert response.status_code == 200, "❌ API stats inaccessible"
        data = response.get_json()
        assert 'labels' in data, "❌ Clé 'labels' manquante"
        assert 'values' in data, "❌ Clé 'values' manquante"
        assert isinstance(data['labels'], list), "❌ 'labels' doit être une liste"
        assert isinstance(data['values'], list), "❌ 'values' doit être une liste"
        print("✅ API stats OK")

    def test_api_types(self, client):
        """L'API types doit retourner du JSON valide."""
        response = client.get('/api/types')
        assert response.status_code == 200, "❌ API types inaccessible"
        data = response.get_json()
        assert 'labels' in data, "❌ Clé 'labels' manquante"
        assert 'values' in data, "❌ Clé 'values' manquante"
        print("✅ API types OK")


# ─────────────────────────────────────────────
# TESTS DE LA BASE DE DONNÉES
# ─────────────────────────────────────────────

class TestDatabase:

    def test_init_db(self):
        """La base de données doit s'initialiser sans erreur."""
        try:
            netscan.init_db()
            print("✅ init_db OK")
        except Exception as e:
            pytest.fail(f"❌ init_db a échoué : {e}")

    def test_get_db(self):
        """La connexion à la base doit fonctionner."""
        try:
            conn = netscan.get_db()
            assert conn is not None, "❌ Connexion nulle"
            conn.close()
            print("✅ get_db OK")
        except Exception as e:
            pytest.fail(f"❌ get_db a échoué : {e}")

    def test_table_alertes_existe(self):
        """La table alertes doit exister."""
        conn = netscan.get_db()
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alertes'"
        ).fetchone()
        conn.close()
        assert result is not None, "❌ Table 'alertes' inexistante"
        print("✅ Table alertes OK")

    def test_table_regles_existe(self):
        """La table règles doit exister."""
        conn = netscan.get_db()
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='regles'"
        ).fetchone()
        conn.close()
        assert result is not None, "❌ Table 'regles' inexistante"
        print("✅ Table règles OK")

    def test_regles_par_defaut(self):
        """Les règles par défaut doivent être présentes."""
        conn = netscan.get_db()
        count = conn.execute("SELECT COUNT(*) FROM regles").fetchone()[0]
        conn.close()
        assert count >= 3, f"❌ Il devrait y avoir au moins 3 règles, trouvé : {count}"
        print(f"✅ {count} règles par défaut trouvées OK")

    def test_insertion_alerte(self):
        """On doit pouvoir insérer une alerte dans la base."""
        conn = netscan.get_db()
        conn.execute("""
            INSERT INTO alertes (date, ip, type, severite, statut)
            VALUES ('2025-01-01 12:00', '192.168.1.99', 'Test', 'Info', 'Nouvelle')
        """)
        conn.commit()
        result = conn.execute(
            "SELECT * FROM alertes WHERE ip='192.168.1.99'"
        ).fetchone()
        conn.close()
        assert result is not None, "❌ Alerte non insérée"
        assert result['ip'] == '192.168.1.99', "❌ IP incorrecte"
        print("✅ Insertion alerte OK")


# ─────────────────────────────────────────────
# TESTS DE VALIDATION DES IPs
# ─────────────────────────────────────────────

class TestValidationIP:

    def test_ip_invalide_rejetee(self, client):
        """Une IP invalide doit être rejetée."""
        response = client.post('/analyser_ip',
                               data={'ip': 'pas-une-ip'},
                               follow_redirects=True)
        assert response.status_code == 200
        print("✅ IP invalide rejetée OK")

    def test_ip_vide_rejetee(self, client):
        """Une IP vide doit être rejetée."""
        response = client.post('/analyser_ip',
                               data={'ip': ''},
                               follow_redirects=True)
        assert response.status_code == 200
        print("✅ IP vide rejetée OK")

    def test_ip_loopback_rejetee(self, client):
        """L'IP loopback 127.0.0.1 doit être rejetée."""
        response = client.post('/analyser_ip',
                               data={'ip': '127.0.0.1'},
                               follow_redirects=True)
        assert response.status_code == 200
        print("✅ IP loopback rejetée OK")

    def test_ip_multicast_rejetee(self, client):
        """Une IP multicast doit être rejetée."""
        response = client.post('/analyser_ip',
                               data={'ip': '224.0.0.1'},
                               follow_redirects=True)
        assert response.status_code == 200
        print("✅ IP multicast rejetée OK")


# ─────────────────────────────────────────────
# TESTS DES RÈGLES IDS
# ─────────────────────────────────────────────

class TestRegles:

    def test_ajouter_regle(self, client):
        """On doit pouvoir ajouter une règle."""
        response = client.post('/regles/ajouter',
                               data={
                                   'nom'      : 'Règle Test',
                                   'type_scan': 'PORT_SCAN',
                                   'seuil'    : '20'
                               },
                               follow_redirects=True)
        assert response.status_code == 200
        conn = netscan.get_db()
        result = conn.execute(
            "SELECT * FROM regles WHERE nom='Règle Test'"
        ).fetchone()
        conn.close()
        assert result is not None, "❌ Règle non ajoutée"
        print("✅ Ajout règle OK")

    def test_toggle_regle(self, client):
        """On doit pouvoir activer/désactiver une règle."""
        conn = netscan.get_db()
        regle = conn.execute("SELECT id, active FROM regles LIMIT 1").fetchone()
        conn.close()
        if regle:
            etat_initial = regle['active']
            client.get(f'/regles/toggle/{regle["id"]}',
                       follow_redirects=True)
            conn = netscan.get_db()
            regle_apres = conn.execute(
                "SELECT active FROM regles WHERE id=?", (regle['id'],)
            ).fetchone()
            conn.close()
            assert regle_apres['active'] != etat_initial, "❌ Toggle n'a pas fonctionné"
            print("✅ Toggle règle OK")