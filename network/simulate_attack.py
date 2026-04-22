import platform
import subprocess

def simulate_nmap_attack(ip):
    """Lance un scan Nmap en arrière-plan (non-bloquant) sur ~15 s."""
    print(f"🚨 Simulation scan Nmap sur {ip}")
    system = platform.system()

    # Scan ralenti volontairement pour qu'il dure ~15 s
    # → laisse le temps à NetScan de capturer le trafic
    base = ["nmap", "-sS", "-p", "1-1000", "--max-rate", "70", ip]
    cmd  = base if system == "Windows" else ["sudo"] + base

    # Popen = lancé en arrière-plan, Flask n'attend pas la fin
    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print("✅ Scan lancé en arrière-plan")