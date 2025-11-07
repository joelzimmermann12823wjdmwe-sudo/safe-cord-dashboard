import os
import json
import tempfile
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from requests_oauthlib import OAuth2Session
from google.cloud import firestore
import requests
from requests.exceptions import HTTPError

# --- FLASK APP INITIALISIERUNG ---
app = Flask(__name__)
# Lädt den geheimen Schlüssel aus Umgebungsvariable, wichtig für Session-Sicherheit
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ein_sehr_sicherer_standardschlüssel_zur_entwicklung")

# --- DISCORD KONFIGURATION (Laden aus Umgebungsvariablen) ---
CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "http://127.0.0.1:10000/callback")
API_BASE_URL = 'https://discord.com/api/v10'
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'

# Discord Scopes: identify (Benutzername), guilds (Serverliste)
SCOPES = ['identify', 'guilds']

# --- FIRESTORE KONFIGURATION UND AUTHENTIFIZIERUNG FIX ---
db = None
try:
    # Authentifizierungs-Fix: Holt den JSON-Schlüssel aus der Render-Umgebungsvariable
    service_account_json = os.environ.get("GCP_SERVICE_ACCOUNT_KEY")
    
    if service_account_json:
        # Erstellt eine temporäre Datei (Firestore Client benötigt einen Pfad)
        temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        temp_file.write(service_account_json)
        temp_file.close()
        
        # Setzt die Umgebungsvariable auf den Pfad der temporären Datei
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = temp_file.name
        
        print("INFO: Firestore-Anmeldeinformationen aus GCP_SERVICE_ACCOUNT_KEY geladen.")

    # Firestore DB-Client initialisieren
    db = firestore.Client()
    
    if service_account_json:
        # Aufräumen: Löscht die temporäre Datei und die Umgebungsvariable
        os.unlink(temp_file.name)
        del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
        
    print("INFO: Firestore-Client erfolgreich initialisiert.")
    
except Exception as e:
    # Fehlerbehandlung, falls die Verbindung fehlschlägt
    print(f"ERROR: Fehler bei der Initialisierung von Firestore: {e}")
    db = None

# Firestore Konstante für den Pfad zur Speicherung der Gilden-Einstellungen
FIRESTORE_SETTINGS_PATH = "safe_cord_dashboard_settings" 

# --- HILFSFUNKTIONEN ---

def get_discord_session(token=None):
    """Erzeugt eine OAuth2Session-Instanz."""
    return OAuth2Session(
        CLIENT_ID,
        scope=SCOPES,
        redirect_uri=REDIRECT_URI,
        token=token
    )

def fetch_guild_data(discord_session):
    """Ruft Gilden-Daten vom Discord-API ab und filtert nach Admin-Rechten."""
    try:
        # 1. Benutzer-ID und Name abrufen
        user_response = discord_session.get(API_BASE_URL + '/users/@me')
        user_response.raise_for_status()
        user_data = user_response.json()
        session['user_id'] = user_data.get('id')
        session['user_name'] = user_data.get('username')
        
        # 2. Gilden abrufen
        guilds_response = discord_session.get(API_BASE_URL + '/users/@me/guilds')
        guilds_response.raise_for_status()
        guilds_data = guilds_response.json()
        
        # 3. Filtern und Mock-Daten hinzufügen (da User-OAuth keine Details liefert)
        admin_guilds = []
        for guild in guilds_data:
            permissions = int(guild.get('permissions', 0))
            # Prüft auf Administrator-Rechte (0x8) oder ob der Benutzer der Eigentümer ist
            if permissions & 0x8 or guild.get('owner'):
                guild_id = guild['id']
                guild['roles'] = fetch_mock_roles(guild_id)
                guild['channels'] = fetch_mock_channels(guild_id)
                admin_guilds.append(guild)
                
        return admin_guilds
        
    except HTTPError as e:
        print(f"HTTP-Fehler beim Abrufen von Discord-Daten: {e}")
        return []
    except Exception as e:
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
        return []

def fetch_mock_roles(guild_id):
    """Simuliert Rollen-Daten für das Dashboard-Template."""
    return [
        {'id': f"{guild_id}01", 'name': 'Admin'},
        {'id': f"{guild_id}02", 'name': 'Moderator'},
        {'id': f"{guild_id}03", 'name': 'Mitglied'},
    ]

def fetch_mock_channels(guild_id):
    """Simuliert Kanal-Daten für das Dashboard-Template."""
    return [
        {'id': f"{guild_id}c1", 'name': '#allgemein', 'type': 0}, # Text
        {'id': f"{guild_id}c2", 'name': '#logs', 'type': 0},      # Text
        {'id': f"{guild_id}v1", 'name': 'Voice-Chat', 'type': 2}, # Voice
    ]

def load_guild_settings(guild_id):
    """Lädt die gespeicherten Einstellungen für eine Gilde aus Firestore."""
    if not db:
        return {} 
        
    try:
        doc_ref = db.collection(FIRESTORE_SETTINGS_PATH).document(str(guild_id))
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()
        return {}
    except Exception as e:
        print(f"ERROR: Fehler beim Laden der Einstellungen für Gilde {guild_id}: {e}")
        return {}

def save_guild_settings(guild_id, setting_type, data):
    """Speichert die Einstellungen für eine Gilde in Firestore."""
    if not db:
        print("ERROR: Firestore nicht initialisiert, kann Einstellungen nicht speichern.")
        return False
        
    try:
        doc_ref = db.collection(FIRESTORE_SETTINGS_PATH).document(str(guild_id))
        # Aktualisiere nur den spezifischen Einstellungstyp (z.B. 'roles')
        update_data = {setting_type: data}
        doc_ref.set(update_data, merge=True)
        return True
    except Exception as e:
        print(f"ERROR: Fehler beim Speichern der Einstellungen für Gilde {guild_id}: {e}")
        return False

# --- FLASK ROUTEN ---

@app.route("/")
def index():
    """Startseite: Weiterleitung zur Discord-Anmeldung, falls nicht angemeldet."""
    if 'oauth_token' not in session:
        return render_template("index.html") 
        
    return redirect(url_for('dashboard'))

@app.route("/login")
def login():
    """Startet den OAuth-Flow."""
    discord = get_discord_session()
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    """Empfängt den Token von Discord und schließt den OAuth-Flow ab."""
    if request.args.get('state') != session.get('oauth_state'):
        return "Ungültiger State", 401
    
    discord = get_discord_session(state=session.get('oauth_state'))
    
    try:
        token = discord.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )
        session['oauth_token'] = token
        return redirect(url_for('dashboard'))
    except Exception as e:
        return f"Fehler beim Abrufen des Tokens: {e}", 500


@app.route("/dashboard")
def dashboard():
    """Zeigt das Dashboard mit Gilden-Einstellungen an."""
    if 'oauth_token' not in session:
        return redirect(url_for('login'))
        
    discord = get_discord_session(session.get('oauth_token'))
    
    guilds = fetch_guild_data(discord)
    
    all_settings = {}
    for guild in guilds:
        all_settings[guild['id']] = load_guild_settings(guild['id'])
        
    # 'settings' ist der Name, der im Template 'dashboard.html' verwendet wird
    return render_template("dashboard.html", 
                           user_name=session.get('user_name', 'Benutzer'),
                           guilds=guilds,
                           settings=all_settings)


@app.route("/save_settings", methods=["POST"])
def save_settings():
    """Speichert die gesendeten Einstellungen in Firestore."""
    if 'oauth_token' not in session:
        return jsonify({"success": False, "message": "Nicht angemeldet"}), 401

    guild_id = request.form.get("guild_id")
    setting_type = request.form.get("setting_type")
    
    if not guild_id or not setting_type:
        return jsonify({"success": False, "message": "Fehlende Gilden-ID oder Einstellungstyp"}), 400
    
    # 1. Bestimme die Mock-Items, um alle möglichen Schalter zu verarbeiten
    if setting_type == 'roles':
        mock_items = fetch_mock_roles(guild_id)
    elif setting_type == 'channels':
        mock_items = fetch_mock_channels(guild_id)
    else: 
        # Für 'users' oder andere globale Einstellungen (hier ein einfacher Schutzschalter)
        mock_items = [{'id': 'users_global_protection'}] 

    final_settings = {}
    
    # 2. Iteriere über alle möglichen Einstellungen und setze True/False
    for item in mock_items:
        item_id = item.get('id')
        checkbox_name = f"{setting_type}_setting_{item_id}"
        
        # Prüft, ob die Checkbox im POST-Request enthalten war (d.h. sie wurde aktiviert)
        if request.form.get(checkbox_name) == 'on' or request.form.get(item_id) == 'on':
            final_settings[item_id] = True
        else:
            final_settings[item_id] = False

    # 3. Speichere die finalen Einstellungen
    if save_guild_settings(guild_id, setting_type, final_settings):
        # Bei Erfolg zur Dashboard-Ansicht der Gilde zurückleiten
        return redirect(url_for('dashboard') + f"#{guild_id}")
    else:
        return jsonify({"success": False, "message": "Fehler beim Speichern in Firestore"}), 500


@app.route("/logout")
def logout():
    """Loggt den Benutzer aus, indem die Session gelöscht wird."""
    session.pop('oauth_token', None)
    session.pop('oauth_state', None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    # Render verwendet PORT 10000. Wir laden ihn aus der Umgebung oder nutzen 5000 für lokale Entwicklung.
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)