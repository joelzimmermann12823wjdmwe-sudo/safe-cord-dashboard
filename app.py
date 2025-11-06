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
    # Die Umgebungsvariable GOOGLE_APPLICATION_CREDENTIALS muss korrekt gesetzt sein
    db = firestore.Client()
    print("Firestore client initialized successfully.")
except Exception as e:
    # Wenn Firestore fehlschlägt, setzen wir db auf None, um Fehler zu vermeiden.
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
        return render_template('error.html', error_message=f"Fehler beim Abrufen der Discord-Daten: {e}")

def get_user_config(user_id):
    """Lädt die Bot-Konfiguration des Benutzers aus Firestore."""
    if not db:
        return {}
    
    try:
        doc_ref = db.collection(FIRESTORE_COLLECTION_PATH).document(user_id).collection('config').document('server_settings')
        doc = doc_ref.get()
        
        if doc.exists:
            config = doc.to_dict()
            
            if 'log_events' in config and isinstance(config['log_events'], str):
                try:
                    config['log_events'] = json.loads(config['log_events'])
                except json.JSONDecodeError:
                    config['log_events'] = []

            if 'profanity_filter_enabled' not in config:
                 config['profanity_filter_enabled'] = False

            return config
        else:
            return {}
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
        for key, value in form_data.items():
            if key == 'profanity_filter_enabled':
                pass 
            elif key == 'log_events':
                if isinstance(value, list):
                     update_data[key] = json.dumps(value)
                else:
                     update_data[key] = json.dumps([value]) 
            elif key != 'config_type': 
                update_data[key] = value

        # Spezieller Check für Checkboxen
        if form_data.get('config_type') == 'moderation':
            update_data['profanity_filter_enabled'] = 'profanity_filter_enabled' in form_data

        doc_ref.set(update_data, merge=True)
        print(f"Konfiguration erfolgreich gespeichert für {user_id}: {update_data}")
        return True
    except Exception as e:
        print(f"Fehler beim Speichern der Konfiguration für {user_id}: {e}")
        return False

# FLASK ROUTEN
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
        return render_template('error.html', error_message="Discord Autorisierung abgelehnt.")

    if request.values.get('state') != session.get('oauth_state'):
        return render_template('error.html', error_message="State mismatch. Mögliche CSRF.")

    discord = get_discord_session(state=session.get('oauth_state'))
    try:
        token = discord.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )
    except Exception as e:
        print(f"Token-Austauschfehler: {e}")
        return render_template('error.html', error_message="Konnte Token nicht von Discord abrufen.")

    session['token'] = token
    user = fetch_user_info(discord)
    
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
    form_data = request.form.to_dict(flat=False)

    clean_data = {}
    for key, values in form_data.items():
        if key == 'log_events':
            clean_data[key] = values
        else:
            clean_data[key] = values[0] if values else ''
            
    success = save_user_config(user_id, clean_data)

    if success:
        session['message'] = "Einstellungen erfolgreich gespeichert!"
    else:
        session['message'] = "Fehler beim Speichern der Einstellungen."
    
    config_type = clean_data.get('config_type')
    target_tab = 'overview'
    if config_type == 'welcome':
        target_tab = 'welcome'
    elif config_type == 'moderation':
        target_tab = 'moderation'
    elif config_type == 'logging':
        target_tab = 'logging'
        
    return redirect(url_for('dashboard', tab=target_tab, _external=True))


@app.route("/logout")
def logout():
    """Löscht die Session und loggt den Benutzer aus."""
    session.clear()
    return redirect(url_for('index', _external=True))

if __name__ == "__main__":
    app.run(debug=True)