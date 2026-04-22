from scapy.all import sniff, IP, TCP
from datetime import datetime
import sqlite3

DB_PATH = "netscan.db"
packets_window = []

def get_db():
    return sqlite3.connect(DB_PATH)

def save_alert(ip, type_scan, severity):
    conn = get_db()
    conn.execute("""
        INSERT INTO alertes (date, ip, type, severite, statut)
        VALUES (?,?,?,?,?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        ip,
        type_scan,
        severity,
        "Auto"
    ))
    conn.commit()
    conn.close()

def detect_scan(packets):
    if len(packets) < 10:
        return False

    targets = {}
    syn = 0
    syn_ack = 0

    for p in packets:
        if IP not in p:
            continue

        dst = p[IP].dst
        targets.setdefault(dst, set())

        if p.haslayer(TCP):
            dport = p[TCP].dport
            targets[dst].add(dport)
            flags = p.sprintf("%TCP.flags%")

            if "S" in flags and "A" not in flags:
                syn += 1
            if "SA" in flags:
                syn_ack += 1

    single_target = len(targets) == 1
    multi_ports = any(len(ports) > 10 for ports in targets.values())
    syn_scan = syn > 10 and syn_ack < 5

    if single_target and (multi_ports or syn_scan):
        return True

    return False

def process_packet(packet):
    global packets_window

    if IP not in packet:
        return

    ip = packet[IP].src
    packets_window.append(packet)

    # garder les 100 derniers paquets
    if len(packets_window) > 100:
        packets_window = packets_window[-100:]

    if detect_scan(packets_window):
        print("🚨 LIVE IDS: Scan détecté sur", ip)
        save_alert(ip, "Scan détecté temps réel", "Critique")
        packets_window.clear()

def start_live_ids():
    print("🟢 IDS LIVE ACTIF...")
    sniff(prn=process_packet, store=False, filter="tcp")