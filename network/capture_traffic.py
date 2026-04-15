from scapy.all import sniff, IP, TCP
import pandas as pd
import time

def extract_features(packets):
    if not packets:
        return None

    spkts = len(packets)
    sbytes = sum(len(p) for p in packets)

    start = packets[0].time
    end = packets[-1].time
    dur = max(end - start, 0.01)

    proto = "tcp"
    service = "http"
    state = "FIN"

    data = {
        "dur": [dur],
        "proto": [proto],
        "service": [service],
        "state": [state],
        "spkts": [spkts],
        "dpkts": [spkts],
        "sbytes": [sbytes],
        "dbytes": [sbytes],
        "rate": [spkts / dur],
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
        "smean": [sbytes/spkts],
        "dmean": [sbytes/spkts],
        "trans_depth": [0],
        "response_body_len": [0],
        "ct_srv_src": [1],
        "ct_state_ttl": [1],
        "ct_dst_ltm": [1],
        "ct_src_dport_ltm": [1],
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
    print(f"Capture trafic vers {target_ip}...")

    packets = sniff(
        timeout=duration,
        filter=f"host {target_ip}"
    )

    print(f"{len(packets)} packets")

    return extract_features(packets)
