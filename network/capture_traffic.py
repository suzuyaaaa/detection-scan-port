from scapy.all import sniff, IP, TCP
import pandas as pd

def extract_features(packets):
    if len(packets) == 0:
        return None

    # 🔥 séparer paquets envoyés et reçus
    src_packets = [p for p in packets if p[IP].src != p[IP].dst]
    dst_packets = [p for p in packets if p[IP].dst != p[IP].src]

    spkts = len(src_packets) if src_packets else len(packets)
    dpkts = max(1, spkts // 4)  # un scan a peu de réponses

    sbytes = sum(len(p) for p in packets)
    dbytes = sbytes // 4

    start_time = packets[0].time
    end_time = packets[-1].time
    dur = end_time - start_time if end_time > start_time else 0.01

    rate = spkts / dur if dur > 0 else 0

    # 🔥 compter les SYN
    syn_count = 0
    ports_testes = set()
    for p in packets:
        if p.haslayer(TCP):
            flags = p.sprintf("%TCP.flags%")
            if "S" in flags and "A" not in flags:
                syn_count += 1
            ports_testes.add(p[TCP].dport)

    print(f"🔍 SYN count: {syn_count}")
    print(f"🔍 Ports testés: {len(ports_testes)}")
    print(f"🔍 spkts: {spkts}, dpkts: {dpkts}, rate: {rate:.2f}")

    data = {
        "dur": [dur],
        "proto": ["tcp"],
        "service": ["http"],
        "state": ["FIN"],
        "spkts": [spkts],
        "dpkts": [dpkts],
        "sbytes": [sbytes],
        "dbytes": [dbytes],
        "rate": [rate],
        "sttl": [64],
        "dttl": [64],
        "sload": [0],
        "dload": [0],
        "sloss": [0],
        "dloss": [0],
        "sinpkt": [0],
        "dinpkt": [0],
        "sjit": [0],
        "djit": [0],
        "swin": [255],
        "stcpb": [0],
        "dtcpb": [0],
        "dwin": [255],
        "tcprtt": [0],
        "synack": [0],
        "ackdat": [0],
        "smean": [sbytes / spkts if spkts > 0 else 0],
        "dmean": [dbytes / dpkts if dpkts > 0 else 0],
        "trans_depth": [0],
        "response_body_len": [0],
        "ct_srv_src": [syn_count],
        "ct_state_ttl": [1],
        "ct_dst_ltm": [1],
        "ct_src_dport_ltm": [len(ports_testes)],
        "ct_dst_sport_ltm": [1],
        "ct_dst_src_ltm": [1],
        "is_ftp_login": [0],
        "ct_ftp_cmd": [0],
        "ct_flw_http_mthd": [0],
        "ct_src_ltm": [1],
        "ct_srv_dst": [1],
        "is_sm_ips_ports": [0]
    }

    return pd.DataFrame(data)

def capture_ip_traffic(target_ip, duration=10):
    print(f"🚨 Capture trafic pour {target_ip} pendant {duration}s...")

    packets = sniff(
        timeout=duration,
        filter=f"tcp and host {target_ip}",
        lfilter=lambda p: IP in p and (
            p[IP].src == target_ip or p[IP].dst == target_ip
        )
    )

    filtered = list(packets)
    print(f"📦 {len(filtered)} paquets filtrés")

    if len(filtered) == 0:
        print("❌ Aucun paquet capturé")
        return None

    return extract_features(filtered)