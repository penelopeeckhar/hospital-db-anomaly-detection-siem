# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, Blueprint
import subprocess, shlex, tempfile, os, sys
import pandas as pd
import mysql.connector, configparser   
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ───────────────────────────────
# Chemins
# ───────────────────────────────
from dotenv import load_dotenv
load_dotenv() 

# ───────────────────────────────
# Connexion MySQL utilitaire
# ───────────────────────────────
def get_connection(buffered=False):
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST"),
        port=int(os.getenv("MYSQL_PORT", 3306)),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DATABASE"),
        buffered=buffered,
    )

# ───────────────────────────────
# Envoi d’alerte e-mail
# ───────────────────────────────
def send_alert_email(vuln_type, target_url):
    email_from = os.getenv("EMAIL_FROM")
    email_to   = os.getenv("EMAIL_TO")
    email_pwd  = os.getenv("EMAIL_PASSWORD")
    email_smtp = os.getenv("EMAIL_SMTP", "smtp.gmail.com")
    email_port = int(os.getenv("EMAIL_PORT", 587))
    db_name    = os.getenv("MYSQL_DATABASE")

    msg = MIMEMultipart()
    msg['From'] = cfg["email"]["from"]
    msg['To'] = cfg["email"]["to"]
    msg['Subject'] = f" ALERTE SÉCURITÉ - SQL Injection Détectée - Niveau: MOYEN"

    body = f"""
ALERTE SÉCURITÉ SYSTÈME
==============================

URL testée: {target_url}
Base de données: db_name
Niveau de risque: MOYEN
Date/Heure: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}

VULNÉRABILITÉ DÉTECTÉE: {vuln_type}

Actions recommandées:
- Vérifier immédiatement la sécurité du site
- Corriger les vulnérabilités SQL
- Mettre à jour les protections

Ce message a été généré automatiquement par le système de détection.
"""
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(email_smtp, email_port) as server:
        server.login(email_from, email_pwd)
        server.send_message(msg)

# ───────────────────────────────
# Flask
# ───────────────────────────────
app = Flask(__name__)
app.secret_key = "change-me"

# Tableau de bord
@app.route("/")
def dashboard():
    conn = get_connection(buffered=True)
    cur  = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM patients")
    nb_patients = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM anomalies_detectees")
    nb_anomalies = cur.fetchone()[0]
    cur.close(); conn.close()
    return render_template(
        "dashboard.html",
        nb_patients=nb_patients,
        nb_anomalies=nb_anomalies,
    )

# Liste des anomalies
@app.route("/anomalies")
def anomalies():
    conn = get_connection()
    df   = pd.read_sql(
        "SELECT * FROM anomalies_detectees ORDER BY horodatage DESC",
        conn,
    )
    conn.close()
    return render_template(
        "anomalies.html",
        tables=[df.to_html(classes="table table-sm", index=False)],
    )

# Lancer une nouvelle analyse (appelle analyse.py)
@app.route("/analyse", methods=["POST"])
def analyse():
    cmd = [sys.executable, ANALYSE_PY]          # python analyse.py
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        flash("Analyse terminée - consulte la liste des anomalies.", "success")
    else:
        flash("Erreur pendant l'analyse:\n" + res.stderr, "danger")
    return redirect(url_for("anomalies"))


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        target = request.form["url"]
        with tempfile.TemporaryDirectory() as tmp:
            sqlmap_path = os.getenv(
    "SQLMAP_PATH",
    os.path.join(BASE_DIR, "..", "sqlmap", "sqlmap.py")
)

            sorties = []

            sorties.append("Étape 1 : Test de vulnérabilité SQL sur l'URL cible…")
            cmd_test  = f'"{sys.executable}" "{sqlmap_path}" -u {shlex.quote(target)} --batch --risk=3 --level=5'
            res_test = subprocess.run(shlex.split(cmd_test), capture_output=True, text=True, timeout=300)

            sorties.append("Résultat du test de vulnérabilité :\n" + res_test.stdout + res_test.stderr)

            # Analyse du résultat
            if any(keyword in res_test.stdout.lower() for keyword in ["boolean-based blind", "union query", "error-based", "time-based", "out-of-band"]):
                # sorties.append("Vulnérabilité détectée ! Lancement du dump de la base…")
                if "union query" in res_test.stdout.lower():
                    vuln_type = "Injection SQL classique (In-band SQLi)"
                elif "out-of-band" in res_test.stdout.lower():
                    vuln_type = "Injection SQL hors bande (Out-of-band SQLi)"
                elif "boolean-based blind" in res_test.stdout.lower():
                    vuln_type = "Injection SQL aveugle (Blind SQLi)"
                else:
                    vuln_type = "Type inconnu"
                
                # Envoi d'email
                send_alert_email(vuln_type, target)
                sorties.append(f"Vulnérabilité détectée : {vuln_type}. Un e-mail d'alerte a été envoyé.")
                
                # Dump
                cmd_dump  = f'"{sys.executable}" "{sqlmap_path}" -u {shlex.quote(target)} --batch --dump-all'
                res_dump = subprocess.run(shlex.split(cmd_dump), capture_output=True, text=True, timeout=1800)

                sorties.append("Résultat du dump de la base de données :\n" + res_dump.stdout + res_dump.stderr)
            else:
                sorties.append("Aucune vulnérabilité détectée dans la base. Le dump est annulé.")

            output = "\n\n".join(sorties)

        return render_template("scan.html", target=target, output=output)

    return render_template("scan.html", target=None, output=None)


@app.route("/patient")
def patient():
    id_patient = request.args.get("id", "")
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM patients WHERE id_patient = %s", (id_patient,))
    patient = cursor.fetchone()

    cursor.close()
    conn.close()

    if patient:
        return f"""
        <h1>Données patient pour ID {id_patient}</h1>
        <p>Nom: {patient['nom']}</p>
        <p>Prénom: {patient['prenom']}</p>
        """
    else:
        return f"<p>Aucun patient avec ID {id_patient}</p>"

@app.route("/patient-insecure")
def patient_insecure():
    id_patient = request.args.get("id", "")
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # VULNÉRABLE À L'INJECTION SQL
    query = f"SELECT * FROM patients WHERE id_patient = {id_patient}"
    cursor.execute(query)
    patient = cursor.fetchone()
    cursor.close()
    conn.close()

    if patient:
        return f"""
        <h1>[INSECURE] Données patient pour ID {id_patient}</h1>
        <p>Nom: {patient['nom']}</p>
        <p>Prénom: {patient['prenom']}</p>
        """
    else:
        return f"<p>...............Aucun patient avec ID {id_patient}</p>"

# http://127.0.0.1:5000/patient-insecure?id=1

# ───────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
