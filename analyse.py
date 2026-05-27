# - Détection d’anomalies à partir de `log_requetes` et `access_logs`
# - Insertion des anomalies du **jour même** dans `anomalies_detectees`
# - Génération du rapport CSV + envoi e‑mail à partir de
#   toutes les anomalies déjà **enregistrées aujourd’hui** dans
#   `anomalies_detectees` (et non plus depuis les DataFrames en mémoire)


import os
import logging
from dotenv import load_dotenv
from datetime import datetime, timedelta, date
from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import smtplib
import pandas as pd
import mysql.connector

# ───────────────────────────────
# Journalisation
# ───────────────────────────────
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
_handler = logging.FileHandler("analyseur.log", mode="a", encoding="utf-8")
_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger.handlers = []  # supprime les éventuels doublons
logger.addHandler(_handler)

# ───────────────────────────────
# Configuration
# ───────────────────────────────
load_dotenv()   # lit le fichier .env local
# ───────────────────────────────
# Helper – connexion MySQL
# ───────────────────────────────

def get_connection(buffered: bool = False):
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST"),
        port=int(os.getenv("MYSQL_PORT", 3306)),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DATABASE"),
        buffered=buffered,
    )

# ───────────────────────────────
# Helper – envoi d’e‑mail
# ───────────────────────────────

def envoyer_email(chemin_fichier: str) -> None:
    # Envoie le CSV en pièce jointe
    try:
        email_from = os.getenv("EMAIL_FROM")
    email_to   = os.getenv("EMAIL_TO")
    email_pwd  = os.getenv("EMAIL_PASSWORD")
    email_smtp = os.getenv("EMAIL_SMTP", "smtp.gmail.com")
    email_port = int(os.getenv("EMAIL_PORT", 587))

    msg["From"]    = email_from
    msg["To"]      = email_to
    msg["Subject"] = "Rapport quotidien…"

        with open(chemin_fichier, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={os.path.basename(chemin_fichier)}",
            )
        msg.attach(part)

        logger.info("Tentative d'envoi du mail à %s", MAIL_CFG["to"])
        with smtplib.SMTP(email_smtp, email_port) as server:
            server.starttls()
            server.login(email_from, email_pwd)
            server.send_message(msg)
        logger.info("E-mail envoyé avec succès.")
    except Exception:
        logger.exception("Échec lors de l'envoi de l'e-mail :")

# ───────────────────────────────
# Étape 1 : détecter les nouvelles anomalies et les stocker
# ───────────────────────────────

def detecter_et_stocker():
    # Analyse les logs, insère les anomalies du jour dans anomalies_detectees
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    logger.info("Connexion MySQL réussie.")

    # Charger les logs
    cursor.execute("SELECT * FROM log_requetes")
    df_log = pd.DataFrame(cursor.fetchall(), columns=[c[0].lower() for c in cursor.description])
    logger.info("%d lignes log_requetes chargées.", len(df_log))

    cursor.execute("SELECT * FROM access_logs")
    df_access = pd.DataFrame(cursor.fetchall(), columns=[c[0].lower() for c in cursor.description])
    logger.info("%d lignes access_logs chargées.", len(df_access))

    # Vérifier les colonnes essentielles
    def check_cols(df: pd.DataFrame, cols: list[str]):
        for col in cols:
            if col not in df.columns:
                raise ValueError(f"Colonne manquante : {col}")
            if df[col].isnull().all():
                logger.warning("Colonne %s entièrement vide", col)

    check_cols(df_log, ["horodatage"])
    check_cols(df_access, ["horodatage"])

    # Colonnes utilisateur dynamiques
    user_col_log = "id_utilisateur" if "id_utilisateur" in df_log.columns else "utilisateur"
    user_col_acc = "utilisateur" if "utilisateur" in df_access.columns else "id_utilisateur"

    # Dictionnaire id‑>email
    cursor.execute("SELECT id_utilisateur, email FROM utilisateurs")
    dict_id_to_email = {
        row["id_utilisateur"]: row["email"] for row in cursor.fetchall()
    }

    anomalies: list[dict] = []
    AUJ = date.today()

    # ── Accès hors horaires (22h‑6h)
    for _, row in df_log.iterrows():
        ts = row["horodatage"]
        if pd.notnull(ts) and (ts.hour >= 22 or ts.hour < 6):
            anomalies.append(
                {
                    "utilisateur": row.get(user_col_log),
                    "horodatage": ts,
                    "type_incident": "Accès hors horaires",
                    "description": f"Requête à {ts}",
                    "gravite": "moyenne",
                }
            )
    for _, row in df_access.iterrows():
        ts = row["horodatage"]
        if pd.notnull(ts) and (ts.hour >= 22 or ts.hour < 6):
            anomalies.append(
                {
                    "utilisateur": row.get(user_col_acc),
                    "horodatage": ts,
                    "type_incident": "Accès hors horaires (access_logs)",
                    "description": f"Accès {row.get('table_accedee', 'inconnu')} à {ts}",
                    "gravite": "moyenne",
                }
            )

    # ── Requêtes répétées (10 en ≤ 10 min) sur consultations
    df_consult = df_log[df_log.get("commentaire", "").str.lower().str.contains("consultation", na=False)]
    user_times: dict = defaultdict(list)
    for _, row in df_consult.iterrows():
        uid, ts = row.get(user_col_log), row["horodatage"]
        if pd.notnull(uid) and pd.notnull(ts):
            user_times[uid].append(ts)
    for uid, times in user_times.items():
        times.sort()
        for i in range(len(times) - 10):
            if times[i + 10] - times[i] <= timedelta(minutes=10):
                anomalies.append(
                    {
                        "utilisateur": uid,
                        "horodatage": times[i + 10],
                        "type_incident": "Requêtes répétées",
                        "description": f"10+ requêtes entre {times[i]} et {times[i+10]}",
                        "gravite": "élevée",
                    }
                )
                break

    # ── Tentatives refusées multiples (access_logs → statut_acces = refuse)
    if "statut_acces" in df_access.columns:
        df_refuse = df_access[df_access["statut_acces"].str.lower() == "refuse"]
        fails: dict = defaultdict(list)
        for _, row in df_refuse.iterrows():
            uid, ts = row.get(user_col_acc), row["horodatage"]
            if pd.notnull(uid) and pd.notnull(ts):
                fails[uid].append(ts)
        for uid, times in fails.items():
            times.sort()
            for i in range(len(times) - 4):
                if times[i + 4] - times[i] <= timedelta(minutes=5):
                    anomalies.append(
                        {
                            "utilisateur": uid,
                            "horodatage": times[i + 4],
                            "type_incident": "Tentatives refusées multiples",
                            "description": f"5 échecs entre {times[i]} et {times[i+4]}",
                            "gravite": "élevée",
                        }
                    )
                    break

    # ── Tentatives échouées multiples (log_requetes → succes = False)
    if "succes" in df_log.columns:
        df_fail = df_log[df_log["succes"] == False]
        fails: dict = defaultdict(list)
        for _, row in df_fail.iterrows():
            uid, ts = row.get(user_col_log), row["horodatage"]
            if pd.notnull(uid) and pd.notnull(ts):
                fails[uid].append(ts)
        for uid, times in fails.items():
            times.sort()
            for i in range(len(times) - 4):
                if times[i + 4] - times[i] <= timedelta(minutes=5):
                    anomalies.append(
                        {
                            "utilisateur": uid,
                            "horodatage": times[i + 4],
                            "type_incident": "Tentatives échouées multiples",
                            "description": f"5 échecs entre {times[i]} et {times[i+4]}",
                            "gravite": "moyenne",
                        }
                    )
                    break

    # Garder uniquement les anomalies du jour pour insertion
    anomalies_today = [a for a in anomalies if a["horodatage"].date() == AUJ]
    logger.info("%d anomalies détectées aujourd'hui.", len(anomalies_today))

    # Insertion dans la table
    insert_sql = """
        INSERT INTO anomalies_detectees (utilisateur, description, gravite, horodatage)
        VALUES (%s, %s, %s, %s)
    """
    for a in anomalies_today:
        uid = a["utilisateur"]
        email = dict_id_to_email.get(uid) if isinstance(uid, int) else None
        utilisateur = email if email else str(uid)
        cursor.execute(insert_sql, (
            utilisateur,
            a["description"],
            a["gravite"],
            a["horodatage"],
        ))

    conn.commit()
    cursor.close()
    conn.close()

# ───────────────────────────────
# Étape 2 : créer le rapport CSV & envoyer
# ───────────────────────────────

def generer_rapport_et_envoyer():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT utilisateur, description, gravite, horodatage
        FROM anomalies_detectees
        WHERE DATE(horodatage) = CURDATE()
        ORDER BY horodatage DESC
        """
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if not rows:
        logger.warning("Aucune anomalie enregistrée aujourd'hui dans anomalies_detectees.")
        return

    df = pd.DataFrame(rows)
    os.makedirs("exports", exist_ok=True)
    fname = f"exports/rapport_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(fname, index=False, encoding="utf-8-sig")
    logger.info("%d anomalies du jour exportées dans %s", len(df), fname)

    envoyer_email(fname)

# ───────────────────────────────
# Main
# ───────────────────────────────

if __name__ == "__main__":
    try:
        detecter_et_stocker()
        generer_rapport_et_envoyer()
    except mysql.connector.Error:
        logger.exception("Erreur MySQL :")
    except Exception:
        logger.exception("Erreur inattendue :")
    finally:
        _handler.flush()
        _handler.close()
