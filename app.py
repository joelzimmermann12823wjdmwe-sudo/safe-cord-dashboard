import os
import json
import requests
from flask import Flask, redirect, url_for, session, render_template, request
from dotenv import load_dotenv

# Lade Umgebungsvariablen aus .env (für lokale Tests)
load_dotenv() 

# Flask App Initialisierung
app = Flask(__name__)

# Konfiguration (Wird von Render Environment oder .env geladen)
# ACHTUNG: SECRET_KEY MUSS AUF RENDER GESETZT WERDEN
app.secret_key = os.getenv("SECRET_KEY")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
# RENDER URL (wichtig für den Redirect URI)
REDIRECT_URI = "https://safe-cord-dashboard.onrender.com/callback" 

# Discord API Endpunkte
DISCORD_API_BASE = 'https://discord.com/api/v10'

# --- ROUTEN ---

# Startseite
@app.route('/')
def index():
    if 'user_info' in session:
        # Benutzer ist eingeloggt: Zeige Dashboard
        return render_template('dashboard.html', user_info=session['user_info'])
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
        return redirect(url_for('index')) # Gehe zurück zur Startseite, wenn kein Code vorhanden
        
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
        # HIER tritt der 401 Fehler auf, wenn CLIENT_SECRET falsch ist
        print(f"Token Fehler: {token_json}")
        # Zeige den 401 Fehler direkt an den Benutzer
        return "Fehler beim Abrufen des Tokens. Bitte prüfen Sie CLIENT_SECRET und CLIENT_ID in den Render-Variablen. Details im Log.", 401

    access_token = token_json['access_token']

    # Verwende das Access Token, um Benutzerinformationen abzurufen
    user_headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    user_response = requests.get(f'{DISCORD_API_BASE}/users/@me', headers=user_headers)
    user_info = user_response.json()
    
    # Speichere Benutzerinformationen in der Session
    session['user_info'] = user_info
    
    # Weiterleitung zum Dashboard
    return redirect(url_for('index'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_info', None)
    return render_template('logout.html')

if __name__ == '__main__':
    # Nur zum lokalen Testen verwenden. Auf Render wird Gunicorn verwendet.
    # app.run(debug=True)
    print("Starte Flask App. Auf Render wird Gunicorn verwendet.")
