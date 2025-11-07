import os
import sys
import json
from datetime import timedelta

# Externe Bibliotheken (müssen in requirements.txt sein)
from flask import Flask, redirect, url_for, session, render_template, request, jsonify
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv

# Firebase/Firestore
import firebase_admin
from firebase_admin import credentials, firestore, auth

# Umgebungsvariablen laden
# Auf Render werden diese direkt geladen, aber lokal benötigen wir diese Zeile.
load_dotenv()

# --- 1. SETUP UND INITIALISIERUNG ---

# Firestore- und Firebase-Initialisierung
try:
    # 1. Firebase Admin SDK initialisieren
    # Der Service Account Key wird von Render über die Variable GCP_SERVICE_ACCOUNT_KEY bereitgestellt.
    service_account_info = json.loads(os.getenv("GCP_SERVICE_ACCOUNT_KEY"))
    cred = credentials.Certificate(service_account_info)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("INFO: Firestore-Client erfolgreich initialisiert.")
except Exception as e:
    # Wenn die Initialisierung fehlschlägt, ist dies ein schwerwiegender Fehler.
    print(f"ERROR: Firestore-Initialisierung fehlgeschlagen: {e}", file=sys.stderr)
    db = None # Setze db auf None, um Fehler in Funktionen abzufangen

# Flask App Initialisierung
app = Flask(__name__)
# WICHTIG: SECRET_KEY MUSS in Render als Umgebungsvariable gesetzt sein!
app.secret_key = os.getenv("SECRET_KEY")
app.config['SESSION_COOKIE_NAME'] = 'discord_oauth_session'
# Session-Lebensdauer für 7 Tage (Optional)
app.permanent_session_lifetime = timedelta(days=7)

# Discord OAuth Konfiguration
# Die CLIENT_ID und CLIENT_SECRET MÜSSEN in Render gesetzt sein!
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")

if not all([CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, app.secret_key]):
    print("FATAL ERROR: Eine oder mehrere Discord- oder SECRET_KEY-Umgebungsvariablen fehlen!", file=sys.stderr)

# OAuth Endpunkte
AUTHORIZATION_BASE_URL = 'https://discord.com/api/oauth2/authorize'
TOKEN_URL = 'https://discord.com/api/oauth2/token'
USER_API_URL = 'https://discord.com/api/users/@me'

# Discord Scopes, die wir benötigen (z.B. um den User-Namen und die ID zu sehen)
# Wenn Sie Guilds/Server sehen möchten, fügen Sie 'guilds' hinzu.
SCOPE = ['identify']

# --- 2. HILFSFUNKTIONEN ---

def get_discord_session():
    """Erstellt und gibt eine OAuth2Session zurück."""
    return OAuth2Session(
        CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope=SCOPE
    )

def fetch_discord_user(session):
    """Ruft die Benutzerinformationen von Discord ab."""
    try:
        r = session.get(USER_API_URL)
        r.raise_for_status() # Löst HTTPError für schlechte Antworten aus
        return r.json()
    except Exception as e:
        print(f"ERROR: Fehler beim Abrufen des Discord-Benutzers: {e}", file=sys.stderr)
        return None

# --- 3. FLASK ROUTEN ---

@app.route("/")
def index():
    """Startseite des Dashboards."""
    
    # 1. Prüfen, ob der Benutzer bereits eingeloggt ist
    if 'discord_token' not in session:
        return render_template("index.html", logged_in=False)

    # 2. Wenn eingeloggt, versuchen, Benutzerdaten abzurufen
    try:
        # Session mit gespeichertem Token wiederherstellen
        discord = get_discord_session()
        token = session.get('discord_token')
        discord.token = token
        
        # Benutzerdaten abrufen
        user = fetch_discord_user(discord)
        
        if user:
            # Wenn der Benutzer gefunden wird, zeigen Sie das Dashboard an
            return render_template("dashboard.html", logged_in=True, user=user)
        else:
            # Falls das Token abgelaufen ist oder ungültig, ausloggen
            session.pop('discord_token', None)
            return redirect(url_for('index'))
            
    except Exception as e:
        print(f"ERROR: Fehler beim Laden der Session oder des Benutzers: {e}", file=sys.stderr)
        session.pop('discord_token', None)
        return redirect(url_for('index'))

@app.route("/login")
def login():
    """Leitet den Benutzer zur Discord-Autorisierungsseite weiter."""
    
    # 1. OAuth-Sitzung erstellen
    discord = get_discord_session()
    
    # 2. Autorisierungs-URL generieren
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    
    # 3. Den 'state' für die spätere Überprüfung in der Session speichern
    session['oauth_state'] = state
    session.permanent = True # Macht die Session permanent
    
    # 4. Weiterleiten
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    """Wird nach erfolgreicher Discord-Anmeldung aufgerufen (Redirect URI)."""
    
    # 1. Zustand (state) prüfen
    # Die 'state'-Variable, die von Discord zurückgegeben wird, muss mit der
    # in der Session gespeicherten übereinstimmen, um CSRF-Angriffe zu verhindern.
    if request.values.get('state') != session.get('oauth_state'):
        # Wenn der State nicht übereinstimmt, ist es ein ungültiger/bösartiger Request
        return "Ungültiger State-Parameter", 403
    
    # 2. Token abrufen
    try:
        # Korrektur des Fehlers: get_discord_session() darf KEINEN 'state' als Argument bekommen
        discord = get_discord_session()
        
        token = discord.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )
        
    except Exception as e:
        print(f"ERROR: Fehler beim Abrufen des Tokens: {e}", file=sys.stderr)
        return "Fehler beim Abrufen des Discord-Tokens", 500
        
    # 3. Token in der Session speichern
    session['discord_token'] = token
    
    # 4. Benutzerdaten abrufen und Firebase Auth Token erstellen
    user_data = fetch_discord_user(discord)
    
    if user_data:
        discord_id = str(user_data['id'])
        username = user_data['username']
        
        # Erstelle oder aktualisiere den Firebase-Benutzer
        try:
            # 1. Firebase-Benutzer erstellen/aktualisieren (ID ist die Discord ID)
            # Wir verwenden die Discord ID als UID in Firebase Auth
            firebase_user = auth.get_user(discord_id)
            auth.update_user(discord_id, display_name=username)
        except auth.AuthError:
            # Benutzer existiert nicht, neu erstellen
            firebase_user = auth.create_user(
                uid=discord_id,
                email=f"{discord_id}@discord.safe-cord.com", # Verwenden Sie eine Dummy-E-Mail
                display_name=username
            )
        
        # 2. Firebase Custom Token erstellen
        custom_token = auth.create_custom_token(discord_id)
        
        # 3. Speichern Sie das Custom Token oder die UID, um es auf der Dashboard-Seite zu verwenden
        # Für die weitere Verwendung speichern wir nur die UID
        session['user_id'] = discord_id
        session['firebase_token'] = custom_token.decode('utf-8')
        
    # 5. Weiterleitung zur Startseite (jetzt ist der Benutzer eingeloggt)
    return redirect(url_for('index'))

@app.route("/logout")
def logout():
    """Loggt den Benutzer aus, indem die Session-Daten gelöscht werden."""
    session.pop('discord_token', None)
    session.pop('oauth_state', None)
    session.pop('user_id', None)
    session.pop('firebase_token', None)
    return redirect(url_for('index'))

# --- 4. FLASK START ---

# Die Flask-App muss nicht gestartet werden, wenn sie unter Gunicorn läuft.
# Diese Zeilen sind nur für den lokalen Test nützlich.
if __name__ == '__main__':
    # Beispiel für eine fehlende SECRET_KEY-Meldung beim lokalen Test
    if not app.secret_key:
        print("WARNUNG: SECRET_KEY fehlt! Session-Sicherheit ist kompromittiert.")
        
    # Lokaler Test auf Port 8080
    app.run(debug=True, port=8080)