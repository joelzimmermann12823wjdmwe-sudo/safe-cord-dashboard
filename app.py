import os
import requests
from flask import Flask, redirect, url_for, session, render_template, request
from dotenv import load_dotenv

# Lade Umgebungsvariablen aus .env (nur für lokale Entwicklung)
load_dotenv() 

# Flask App Initialisierung
app = Flask(__name__)

# Konfiguration (Wird von Render Environment oder .env geladen)
# ACHTUNG: SECRET_KEY muss in den Render Environment Variables gesetzt werden!
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret_key_bitte_ersetzen")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
# Die Redirect URI muss exakt mit der in Discord übereinstimmen!
REDIRECT_URI = "https://safe-cord-dashboard.onrender.com/callback" 

# Discord API Endpunkte
DISCORD_API_BASE = 'https://discord.com/api/v10'

# Temporärer Speicher für die Konfiguration (ersetze dies später durch eine Datenbank)
# Schlüssel ist Server-ID, Wert ist das Konfigurations-Objekt
server_config = {}

# --- ROUTEN ---

# Startseite
@app.route('/')
def index():
    if 'user_info' in session:
        # Benutzer ist eingeloggt: Zeige Dashboard
        # Da wir keine echte Server-ID haben, nehmen wir einen Platzhalter
        current_server_id = "test_server_alpha"
        
        # Lade die aktuelle Konfiguration für das Rendering
        config = server_config.get(current_server_id, {})
        
        return render_template('dashboard.html', 
                               user_info=session['user_info'],
                               current_config=config,
                               current_tab=request.args.get('tab', 'overview'))
    else:
        # Benutzer ist nicht eingeloggt: Zeige Login-Seite
        return render_template('index.html')

# Leitet zu Discord OAUTH weiter
@app.route('/login')
def login():
    # Definiere die Berechtigungen (scopes): identify (Benutzerinfo), guilds (Serverliste)
    scope = 'identify email guilds'
    discord_login_url = (
        f'{DISCORD_API_BASE}/oauth2/authorize'
        f'?client_id={CLIENT_ID}'
        f'&redirect_uri={REDIRECT_URI}'
        f'&response_type=code'
        f'&scope={scope}'
    )
    return redirect(discord_login_url)

# Callback Route nach erfolgreicher Autorisierung bei Discord
@app.route('/callback')
def callback():
    code = request.args.get('code')
    
    if not code:
        return redirect(url_for('index'))
        
    # Tausche den Code gegen ein Access Token
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'scope': 'identify email guilds'
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    token_response = requests.post(f'{DISCORD_API_BASE}/oauth2/token', data=data, headers=headers)
    token_json = token_response.json()

    if 'access_token' not in token_json:
        # Fehlerbehandlung für den 401 Fehler
        print(f"Token Fehler: {token_json}")
        # Zeige den 401 Fehler direkt an den Benutzer
        error_msg = ("Fehler beim Abrufen des Tokens. "
                     "BITTE PRÜFEN SIE CLIENT_SECRET und CLIENT_ID in den Render-Variablen, "
                     "sowie die REDIRECT_URI in Discord. (Möglicher 401 Unauthorized Fehler)")
        return render_template('error.html', error_message=error_msg), 401

    access_token = token_json['access_token']

    # Verwende das Access Token, um Benutzerinformationen abzurufen
    user_headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    user_response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=user_headers)
    user_info = user_response.json()
    
    # Speichere Benutzerinformationen in der Session
    session['user_info'] = user_info
    
    # Weiterleitung zum Dashboard (index-Route)
    return redirect(url_for('index'))

# Route zur Speicherung der Bot-Konfiguration
@app.route('/save_config', methods=['POST'])
def save_config():
    if 'user_info' not in session:
        return redirect(url_for('index'))
    
    config_type = request.form.get('config_type')
    # Platzhalter Server-ID
    server_id = "test_server_alpha" 

    # Initialisiere oder lade die Serverkonfiguration
    config = server_config.get(server_id, {})
    
    if config_type == 'welcome':
        # Speichere Willkommens-Konfiguration
        config['welcome_channel'] = request.form.get('welcome_channel')
        config['welcome_message'] = request.form.get('welcome_message')
        config['autorole_id'] = request.form.get('autorole_id')
        message = "Willkommen/Rollen-Einstellungen erfolgreich gespeichert!"
        tab_to_show = 'welcome'
        
    elif config_type == 'logging':
        # Speichere Logging-Konfiguration
        config['logging_channel'] = request.form.get('logging_channel')
        # request.form.getlist('log_events') gibt eine Liste zurück
        config['log_events'] = request.form.getlist('log_events')
        message = "Logging-Einstellungen erfolgreich gespeichert!"
        tab_to_show = 'logging'
        
    else:
        message = "Ungültiger Konfigurationstyp."
        tab_to_show = 'overview'
        
    # Speichere die aktualisierte Konfiguration im temporären Speicher
    server_config[server_id] = config
    
    # Gehe zum Dashboard zurück, zeige Erfolgsmeldung und den richtigen Tab an
    return render_template('dashboard.html', 
                           user_info=session['user_info'], 
                           message=message,
                           current_config=config,
                           current_tab=tab_to_show)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_info', None)
    return render_template('logout.html')

if __name__ == '__main__':
    # Nur zum lokalen Testen verwenden. Auf Render wird Gunicorn verwendet.
    # app.run(debug=True)
    print("Starte Flask App. Auf Render wird Gunicorn verwendet.")