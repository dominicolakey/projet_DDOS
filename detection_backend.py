import subprocess
import joblib
import pandas as pd
import os
import time
import requests
from threading import Thread, Lock
from datetime import datetime
from mapping import mapping
import ipaddress
from dotenv import load_dotenv
import netifaces
import socket
import logging
import re
import shutil

load_dotenv()

# === Configuration Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ddos_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Chemins ===
CICFLOWMETER_DIR = "cicflowmeter"
MODEL_FILE = "xgb_model.joblib"
SCALER_FILE = "scaler.joblib"
COLUMNS_FILE = "columns_used.joblib"
ENCODER_FILE = "label_encoder.joblib"
CSV_FILE = os.path.join(CICFLOWMETER_DIR, "flows.csv")
BLOCKED_IPS_FILE = "blocked_ips.txt"

# === Chargement modèle ===
try:
    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    expected_columns = joblib.load(COLUMNS_FILE)
    label_encoder = joblib.load(ENCODER_FILE)
    logger.info("Modèles ML chargés avec succès")
except Exception as e:
    logger.error(f"Erreur chargement modèles ML: {e}")
    raise

data_lock = Lock()
predicted_data = []
attack_ip_counts = {}
ip_detection_counts = {}
blocked_ips = set()
running = False
cic_thread = None
detect_thread = None

protocol_map = {
    "6": "TCP",
    "17": "UDP",
    "1": "ICMP"
}

def load_blocked_ips():
    """Charge la liste des IPs bloquées depuis le fichier"""
    global blocked_ips
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                blocked_ips = set(line.strip() for line in f if line.strip())
            logger.info(f"Chargé {len(blocked_ips)} IPs bloquées depuis le fichier")
        except Exception as e:
            logger.error(f"Erreur lecture fichier IPs bloquées: {e}")

def save_blocked_ip(ip):
    """Sauvegarde une IP bloquée dans le fichier"""
    try:
        with open(BLOCKED_IPS_FILE, 'a') as f:
            f.write(f"{ip}\n")
        blocked_ips.add(ip)
    except Exception as e:
        logger.error(f"Erreur sauvegarde IP {ip}: {e}")

def remove_blocked_ip(ip):
    """Retire une IP de la liste des bloquées"""
    try:
        blocked_ips.discard(ip)
        # Réécrire le fichier sans cette IP
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                ips = [line.strip() for line in f if line.strip() != ip]
            with open(BLOCKED_IPS_FILE, 'w') as f:
                f.write('\n'.join(ips) + '\n')
    except Exception as e:
        logger.error(f"Erreur suppression IP {ip} du fichier: {e}")

def validate_ip(ip):
    """Valide strictement une adresse IP"""
    if not ip or not isinstance(ip, str):
        return False
    
    # Pattern IP basique
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if not re.match(ip_pattern, ip):
        return False
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_ip_blocked_in_iptables(ip):
    """Vérifie si une IP est déjà bloquée dans iptables"""
    try:
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n"],
            capture_output=True, text=True, timeout=10
        )
        return ip in result.stdout
    except Exception as e:
        logger.error(f"Erreur vérification iptables pour {ip}: {e}")
        return False

def get_server_ip():
    """Récupération de l'IP locale du serveur"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.error(f"Impossible de récupérer l'IP du serveur: {e}")
        return None

SERVER_IP = get_server_ip()
logger.info(f"IP du serveur surveillé: {SERVER_IP}")

def is_private_ip(ip):
    """Vérifie si une IP est privée"""
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def block_ip(ip):
    """Bloque une adresse IP avec iptables - VERSION ROBUSTE"""
    
    # 1. Validation de l'IP
    if not validate_ip(ip):
        logger.error(f"IP invalide pour blocage: {ip}")
        return False
    
    # 2. Éviter de bloquer des IPs critiques
    if ip == SERVER_IP:
        logger.warning(f"Refus de bloquer l'IP du serveur: {ip}")
        return False
    
    if ip in ["127.0.0.1", "localhost"]:
        logger.warning(f"Refus de bloquer IP locale: {ip}")
        return False
    
    # 3. Vérifier si déjà bloquée
    if ip in blocked_ips or is_ip_blocked_in_iptables(ip):
        logger.info(f"IP {ip} déjà bloquée")
        return True
    
    try:
        # 4. Commande de blocage iptables
        logger.info(f"Tentative de blocage de {ip}...")
        
        result = subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            check=True, 
            capture_output=True, 
            text=True,
            timeout=15
        )
        
        # 5. Vérification post-blocage
        if is_ip_blocked_in_iptables(ip):
            save_blocked_ip(ip)
            logger.info(f"✅ IP {ip} bloquée avec succès")
            
            # 6. Optionnel: Sauvegarder la règle iptables de façon persistante
            try:
                subprocess.run(["iptables-save"], check=True, timeout=10)
            except:
                logger.warning("Impossible de sauvegarder les règles iptables")
            
            return True
        else:
            logger.error(f"❌ Blocage échoué pour {ip} - règle non trouvée après ajout")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout lors du blocage de {ip}")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur iptables lors du blocage de {ip}: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Erreur inattendue lors du blocage de {ip}: {e}")
        return False

def unblock_ip(ip):
    """Débloque une adresse IP"""
    if not validate_ip(ip):
        logger.error(f"IP invalide pour déblocage: {ip}")
        return False
    
    try:
        logger.info(f"Tentative de déblocage de {ip}...")
        
        # Supprimer toutes les règles pour cette IP
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        
        # Supprimer de notre liste
        remove_blocked_ip(ip)
        
        logger.info(f"✅ IP {ip} débloquée")
        return True
        
    except Exception as e:
        logger.error(f"Erreur déblocage {ip}: {e}")
        return False

def get_blocked_ips_list():
    """Retourne la liste des IPs bloquées avec statut"""
    blocked_list = []
    for ip in blocked_ips:
        status = "🔴 Bloquée" if is_ip_blocked_in_iptables(ip) else "⚠️ Règle manquante"
        blocked_list.append({
            "ip": ip,
            "status": status,
            "in_iptables": is_ip_blocked_in_iptables(ip)
        })
    return blocked_list

def preprocess_and_predict(flow_dict):
    """Preprocessing et prédiction ML"""
    try:
        mapped = {mapping[k]: v for k, v in flow_dict.items() if k in mapping}
        df = pd.DataFrame([mapped])
        for col in expected_columns:
            if col not in df.columns:
                df[col] = 0
        df = df[expected_columns].copy()
        df = df.apply(pd.to_numeric, errors='coerce').fillna(0)
        X = scaler.transform(df)
        pred_encoded = model.predict(X)[0]
        pred_label = label_encoder.inverse_transform([pred_encoded])[0]
        return pred_label
    except Exception as e:
        logger.error(f"Erreur prédiction ML: {e}")
        return "ERROR"

def tail_csv(file_path):
    """Lecture en temps réel du fichier CSV"""
    with open(file_path, "r") as f:
        f.readline()  # Skip header
        while running:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def wait_for_header():
    """Attendre que le header CSV soit disponible"""
    while True:
        try:
            with open(CSV_FILE, "r") as f:
                header = f.readline().strip()
                if "," in header and "src_ip" in header:
                    return [h.strip() for h in header.split(",")]
        except:
            pass
        time.sleep(0.5)

def launch_cicflowmeter(interface):
    """Lancement de CICFlowMeter"""
    command = f"cd {CICFLOWMETER_DIR} && source .venv/bin/activate && cicflowmeter -i {interface} -c flows.csv"
    try:
        subprocess.call(['/bin/bash', '-c', command])
    except Exception as e:
        logger.error(f"Erreur lancement CICFlowMeter: {e}")

def detection_loop(interface):
    """Boucle principale de détection"""
    global running
    logger.info(f"Démarrage détection sur interface {interface}")
    
    while not os.path.exists(CSV_FILE) and running:
        time.sleep(1)

    if not running:
        return

    header = wait_for_header()
    
    for line in tail_csv(CSV_FILE):
        if not running:
            break
            
        values = [v.strip() for v in line.split(",")]
        if len(values) != len(header):
            continue
            
        flow_dict = dict(zip(header, values))

        # Filtrer uniquement les flux destinés au serveur
        dst_ip = flow_dict.get("dst_ip", "???")
        if SERVER_IP and dst_ip != SERVER_IP:
            continue

        result = preprocess_and_predict(flow_dict)
        classe = "NORMAL" if result == "Benign" else "ATTAQUE"

        timestamp = flow_dict.get("timestamp", "N/A")
        try:
            timestamp = datetime.fromisoformat(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass

        src_ip = flow_dict.get("src_ip", "???")
        proto = flow_dict.get("protocol", "N/A")
        protocol = protocol_map.get(proto, proto)

        with data_lock:
            # Limiter la taille des données en mémoire (garder seulement les 1000 dernières)
            if len(predicted_data) > 1000:
                predicted_data.pop(0)
                
            predicted_data.append({
                "Date-Heure": timestamp,
                "IP Source": src_ip,
                "IP Destination": dst_ip,
                "Protocole": protocol,
                "Prédiction": classe
            })

            if classe == "ATTAQUE" and validate_ip(src_ip):
                ip_detection_counts[src_ip] = ip_detection_counts.get(src_ip, 0) + 1
                
                # Seuil d'attaque atteint
                if ip_detection_counts[src_ip] >= 3:
                    attack_ip_counts[src_ip] = attack_ip_counts.get(src_ip, 0) + 1
                    logger.warning(f"ATTAQUE détectée depuis {src_ip} - {attack_ip_counts[src_ip]} fois")

def start_detection(interface):
    """Démarrage du système de détection"""
    global running, predicted_data, attack_ip_counts, ip_detection_counts, cic_thread, detect_thread
    
    if running:
        logger.warning("Détection déjà en cours")
        return

    # Charger les IPs bloquées
    load_blocked_ips()

    if os.path.exists(CSV_FILE):
        try:
            os.remove(CSV_FILE)
            logger.info("Ancien fichier flows.csv supprimé")
        except Exception as e:
            logger.error(f"Erreur suppression flows.csv: {e}")
            return

    running = True
    predicted_data.clear()
    attack_ip_counts.clear()
    ip_detection_counts.clear()
    
    cic_thread = Thread(target=launch_cicflowmeter, args=(interface,))
    detect_thread = Thread(target=detection_loop, args=(interface,))
    cic_thread.daemon = True
    detect_thread.daemon = True
    cic_thread.start()
    detect_thread.start()
    
    logger.info(f"✅ Détection démarrée sur interface {interface}")

def stop_detection():
    """Arrêt du système de détection"""
    global running
    running = False
    logger.info("🛑 Détection arrêtée")

def get_latest_data():
    """Récupération des dernières données"""
    with data_lock:
        return list(predicted_data)

def get_attack_ips():
    """Récupération des IPs attaquantes"""
    with data_lock:
        return dict(sorted(attack_ip_counts.items(), key=lambda x: x[1], reverse=True))

def is_detection_running():
    """Statut de la détection"""
    return running

def get_ip_info(ip):
    """Analyse IP via AbuseIPDB"""
    if not validate_ip(ip):
        return "Adresse IP invalide"
        
    if is_private_ip(ip):
        return "Adresse IP privée ou locale, aucune analyse disponible."

    API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    if not API_KEY:
        return "Clé API AbuseIPDB manquante dans .env"

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        
        logger.info(f"Requête AbuseIPDB pour {ip}")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()["data"]
        info = (
            f"Adresse IP : {data['ipAddress']}\n"
            f"Abus signalés : {data['totalReports']}\n"
            f"Score d'abus : {data['abuseConfidenceScore']}%\n"
            f"Pays : {data.get('countryCode','N/A')}\n"
            f"ISP : {data.get('isp','N/A')}\n"
            f"Domaine : {data.get('domain','N/A')}\n"
            f"Dernière activité : {data.get('lastReportedAt','N/A')}"
        )
        return info
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur requête AbuseIPDB pour {ip}: {e}")
        return f"Erreur réseau lors de l'analyse AbuseIPDB : {e}"
    except Exception as e:
        logger.error(f"Erreur analyse AbuseIPDB pour {ip}: {e}")
        return f"Erreur lors de l'analyse AbuseIPDB : {e}"

def get_network_interfaces():
    """Liste des interfaces réseau disponibles"""
    try:
        interfaces = netifaces.interfaces()
        return [iface for iface in interfaces if iface != 'lo']
    except Exception as e:
        logger.error(f"Erreur récupération interfaces: {e}")
        return ['eth0', 'ens33', 'enp0s3']

# Initialisation au démarrage
load_blocked_ips()
logger.info(f"Backend de détection DDoS initialisé - {len(blocked_ips)} IPs bloquées chargées")
