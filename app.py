# Importiere notwendige Bibliotheken
import os
import json
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from requests_oauthlib import OAuth2Session
from google.cloud import firestore

# Initialisiere Flask App
app = Flask(__name__)
# WICHTIG: Ersetzen Sie dies durch einen sicheren, geheimen Schlüssel in einer Produktionsumgebung
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "eine_sehr_geheime_standard_pruefung")

# Discord OAuth Konfiguration (muss mit Ihren Discord Bot Einstellungen übereinstimmen)
CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
# Die Redirect URI muss in Ihren Discord Bot Einstellungen registriert sein!
REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "http://127.0.0.1:5000/callback")
API_BASE_URL = 'https://discord.com/api/v10'
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'

# Firestore Setup
try:
    # Firestore DB-Client initialisieren
    db = firestore.Client()
    print("Firestore client initialized successfully.")
except Exception as e:
    # Wenn Firestore fehlschlägt, setzen wir db auf None
    print(f"Error initializing Firestore: {e}")
    db = None 

# Firestore Konstanten 
FIRESTORE_COLLECTION_PATH = "artifacts/safe-cord-bot/users" 

# HILFSFUNKTIONEN
# ==============================================================================

def get_discord_session(token=None):
    """Erstellt eine OAuth2Session."""
    return OAuth2Session(
        CLIENT_ID,
        scope=['identify', 'guilds'],
        redirect_uri=REDIRECT_URI,
        token=token
    )

def fetch_user_info(discord):
    """Ruft die Benutzerinformationen von Discord ab."""
    try:
        user_response = discord.get(API_BASE_URL + '/users/@me')
        user_response.raise_for_status()
        user = user_response.json()
        
        guilds_response = discord.get(API_BASE_URL + '/users/@me/guilds')
        guilds_response.raise_for_status()
        guilds = guilds_response.json()

        session['guilds'] = guilds
        return user
    except Exception as e:
        print(f"Fehler beim Abrufen der Discord-Benutzerdaten: {e}")
        session.clear()
        # Bei einem Fehler zur Fehlerseite umleiten, um die Schleife zu vermeiden
        return redirect(url_for('error_page', error_message="Fehler beim Abrufen der Discord-Daten."))

def get_user_config(user_id):
    """Lädt die Bot-Konfiguration des Benutzers aus Firestore."""
    if not db:
        return {}
    
    try:
        # Pfad: artifacts/safe-cord-bot/users/{user_id}/config/server_settings
        doc_ref = db.collection(FIRESTORE_COLLECTION_PATH).document(user_id).collection('config').document('server_settings')
        doc = doc_ref.get()
        
        config = doc.to_dict() if doc.exists else {}

        # Default-Werte hinzufügen und JSON-Strings in Listen konvertieren
        if 'log_events' in config and isinstance(config['log_events'], str):
            try:
                config['log_events'] = json.loads(config['log_events'])
            except json.JSONDecodeError:
                config['log_events'] = []
        else:
            config['log_events'] = []

        # Neue Sicherheits-Standardwerte hinzufügen, falls nicht vorhanden
        config['profanity_filter_enabled'] = config.get('profanity_filter_enabled', False)
        config['antispam_enabled'] = config.get('antispam_enabled', False)
        config['invitation_filter_enabled'] = config.get('invitation_filter_enabled', False)
        config['antilink_enabled'] = config.get('antilink_enabled', False)
        config['anti_nuke_enabled'] = config.get('anti_nuke_enabled', False)
        config['antivirus_enabled'] = config.get('antivirus_enabled', False)
        
        return config
    except Exception as e:
        print(f"Fehler beim Laden der Konfiguration für {user_id}: {e}")
        return {}

def save_user_config(user_id, form_data):
    """Speichert die Bot-Konfiguration des Benutzers in Firestore."""
    if not db:
        return False
        
    try:
        doc_ref = db.collection(FIRESTORE_COLLECTION_PATH).document(user_id).collection('config').document('server_settings')
        
        update_data = {}
        config_type = form_data.get('config_type')

        for key, value in form_data.items():
            if key in ['profanity_filter_enabled', 'antispam_enabled', 'invitation_filter_enabled', 'antilink_enabled', 'anti_nuke_enabled', 'antivirus_enabled']:
                # Boolean-Werte werden unten explizit gesetzt, um deaktivierte Checkboxen zu erfassen
                pass 
            elif key == 'log_events':
                # Speichere als JSON-String in Firestore
                update_data[key] = json.dumps(value)
            elif key != 'config_type': # config_type ist nur für die interne Verarbeitung
                update_data[key] = value

        # Spezieller Check für Checkboxen
        if config_type == 'moderation':
            update_data['profanity_filter_enabled'] = 'profanity_filter_enabled' in form_data
        
        elif config_type == 'security':
            update_data['antispam_enabled'] = 'antispam_enabled' in form_data
            update_data['invitation_filter_enabled'] = 'invitation_filter_enabled' in form_data
            update_data['antilink_enabled'] = 'antilink_enabled' in form_data
        
        elif config_type == 'anti-nuke':
            update_data['anti_nuke_enabled'] = 'anti_nuke_enabled' in form_data
            update_data['antivirus_enabled'] = 'antivirus_enabled' in form_data

        # Die Konfiguration in Firestore setzen/aktualisieren
        doc_ref.set(update_data, merge=True)
        print(f"Konfiguration erfolgreich gespeichert für {user_id}: {update_data}")
        return True
    except Exception as e:
        print(f"Fehler beim Speichern der Konfiguration für {user_id}: {e}")
        return False

# FLASK ROUTEN (Routen bleiben gleich)
# ==============================================================================

@app.route("/")
def index():
    """Startseite: Überprüft, ob der Benutzer eingeloggt ist, andernfalls zeigt es die Login-Seite."""
    if 'user_id' in session and 'token' in session:
        return redirect(url_for('dashboard', _external=True))
    return render_template('index.html')

@app.route("/login")
def login():
    """Leitet den Benutzer zur Discord-Autorisierungsseite weiter."""
    discord = get_discord_session()
    authorization_url, state = discord.authorization_url(
        AUTHORIZATION_BASE_URL
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    """Verarbeitet die Rückkehr vom Discord OAuth-Server."""
    if request.values.get('error'):
        return redirect(url_for('error_page', error_message="Discord Autorisierung abgelehnt."))

    if request.values.get('state') != session.get('oauth_state'):
        return redirect(url_for('error_page', error_message="State mismatch. Mögliche CSRF."))

    discord = get_discord_session(state=session.get('oauth_state'))
    try:
        token = discord.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )
    except Exception as e:
        print(f"Token-Austauschfehler: {e}")
        return redirect(url_for('error_page', error_message="Konnte Token nicht von Discord abrufen."))

    session['token'] = token
    user = fetch_user_info(discord)
    
    # Sicherstellen, dass die Benutzerdaten erfolgreich abgerufen wurden, bevor auf das Dashboard zugegriffen wird
    if isinstance(user, Flask.Response):
        return user # Ist bereits eine Umleitung zur Fehlerseite, falls fetch_user_info fehlschlägt.

    session['user_id'] = user['id']
    session['username'] = user['username']

    return redirect(url_for('dashboard', _external=True))

@app.route("/dashboard")
def dashboard():
    """Dashboard-Seite: Zeigt die Bot-Einstellungen an."""
    if 'user_id' not in session or 'token' not in session:
        return redirect(url_for('index', _external=True))
        
    discord = get_discord_session(session.get('token'))
    user_info = fetch_user_info(discord) 
    
    # Sicherstellen, dass die Benutzerdaten erfolgreich abgerufen wurden
    if isinstance(user_info, Flask.Response):
        return user_info

    current_config = get_user_config(session['user_id'])
    
    message = session.pop('message', None)

    return render_template(
        'dashboard.html',
        user_info=user_info,
        current_config=current_config,
        message=message
    )

@app.route("/save_config", methods=["POST"])
def save_config():
    """Speichert die über das Dashboard gesendeten Konfigurationseinstellungen."""
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Nicht autorisiert"}), 401
    
    user_id = session['user_id']
    # request.form.to_dict(flat=False) gibt alle Werte als Listen zurück
    form_data = request.form.to_dict(flat=False)

    # Bereinigen der Daten: Einzelne Elemente als String, Multi-Select als Liste beibehalten
    clean_data = {}
    for key, values in form_data.items():
        if key == 'log_events':
            # log_events muss als Liste bleiben (auch wenn sie leer ist)
            clean_data[key] = values
        else:
            # Alle anderen Felder sind Einzelelemente
            clean_data[key] = values[0] if values else ''
            
    success = save_user_config(user_id, clean_data)

    if success:
        session['message'] = "Einstellungen erfolgreich gespeichert!"
    else:
        session['message'] = "Fehler beim Speichern der Einstellungen."
    
    # Ermittle den aktiven Tab, um nach dem Speichern dorthin zurückzukehren
    config_type = clean_data.get('config_type')
    target_tab = 'overview'
    if config_type == 'welcome':
        target_tab = 'welcome'
    elif config_type == 'moderation':
        target_tab = 'moderation'
    elif config_type == 'security':
        target_tab = 'security'
    elif config_type == 'anti-nuke':
        target_tab = 'antinuke' # Tab-ID ist 'antinuke'
    elif config_type == 'logging':
        target_tab = 'logging'
        
    # Verwende 'tab' in den URL-Parametern
    return redirect(url_for('dashboard', tab=target_tab, _external=True))

@app.route("/error_page")
def error_page():
    """Zeigt die Fehlerseite an."""
    error_message = request.args.get('error_message', 'Ein unbekannter Fehler ist aufgetreten.')
    return render_template('error.html', error_message=error_message)

@app.route("/logout")
def logout():
    """Löscht die Session und loggt den Benutzer aus."""
    session.clear()
    return redirect(url_for('index', _external=True))

if __name__ == "__main__":
    app.run(debug=True)
