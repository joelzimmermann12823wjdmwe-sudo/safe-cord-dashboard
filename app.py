# app.py - Discord Dashboard Flask App
# KORRIGIERTE VERSION (Mit allen notwendigen Scopes, API-Endpoints und Fehlerbehandlung)

import os
import sys
import json
from datetime import timedelta
from requests.exceptions import HTTPError

# Externe Bibliotheken
from flask import Flask, redirect, url_for, session, render_template, request, jsonify
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv

# Firebase/Firestore
import firebase_admin
from firebase_admin import credentials, firestore, auth

# Umgebungsvariablen laden (Nur für lokale Entwicklung)
load_dotenv()

# --- 1. SETUP UND INITIALISIERUNG ---

# Firebase-Initialisierung
GCP_SERVICE_ACCOUNT_KEY = os.getenv("GCP_SERVICE_ACCOUNT_KEY")
if GCP_SERVICE_ACCOUNT_KEY:
    try:
        # 1. Firebase Admin SDK initialisieren
        service_account_info = json.loads(GCP_SERVICE_ACCOUNT_KEY)
        cred = credentials.Certificate(service_account_info)
        # Überprüfen, ob Firebase bereits initialisiert wurde, um Fehler zu vermeiden
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("INFO: Firestore-Client erfolgreich initialisiert.")
    except Exception as e:
        print(f"FATAL ERROR: Firestore-Initialisierung fehlgeschlagen: {e}", file=sys.stderr)
        db = None
        sys.exit(1)
else:
    print("FATAL ERROR: GCP_SERVICE_ACCOUNT_KEY fehlt! Firestore kann nicht initialisiert werden.", file=sys.stderr)
    db = None
    sys.exit(1)

# Flask App Initialisierung
app = Flask(__name__)
# WICHTIG: SECRET_KEY MUSS in Render als Umgebungsvariable gesetzt sein!
app.secret_key = os.getenv("SECRET_KEY")
app.config['SESSION_COOKIE_NAME'] = 'discord_oauth_session'
app.permanent_session_lifetime = timedelta(days=7)

# Discord OAuth Konfiguration
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")

if not all([CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, app.secret_key]):
    print("FATAL ERROR: Eine oder mehrere Discord- oder SECRET_KEY-Umgebungsvariablen fehlen!", file=sys.stderr)
    sys.exit(1)

# OAuth Endpunkte
AUTHORIZATION_BASE_URL = 'https://discord.com/api/oauth2/authorize'
TOKEN_URL = 'https://discord.com/api/oauth2/token'
USER_API_URL = 'https://discord.com/api/users/@me'
GUILDS_API_URL = 'https://discord.com/api/users/@me/guilds' 

# Discord Scopes: 'email' ist ZWINGEND für Firebase create_user notwendig!
SCOPE = ['identify', 'guilds', 'email'] 

# --- 2. HILFSFUNKTIONEN ---

def get_discord_session(token=None):
    """Erstellt und gibt eine OAuth2Session zurück. Kann ein optionales Token für die Session-Wiederherstellung verwenden."""
    return OAuth2Session(
        CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope=SCOPE,
        token=token # Hier wird das Token für die Wiederherstellung verwendet
    )

def fetch_discord_user(session):
    """Ruft die Benutzerinformationen von Discord ab."""
    try:
        r = session.get(USER_API_URL)
        r.raise_for_status() 
        return r.json()
    except Exception as e:
        print(f"ERROR: Fehler beim Abrufen des Discord-Benutzers: {e}", file=sys.stderr)
        return None

def fetch_discord_guilds(session):
    """Ruft die Server-Informationen (Guilds) des Benutzers von Discord ab."""
    try:
        r = session.get(GUILDS_API_URL)
        r.raise_for_status()
        # Filtert Server, bei denen der User die Berechtigung 'MANAGE_GUILD' (Bit 3 = 0x8) hat.
        return [g for g in r.json() if g.get('permissions', 0) & 0x8]
    except Exception as e:
        print(f"ERROR: Fehler beim Abrufen der Discord-Server (Guilds): {e}", file=sys.stderr)
        return []

# --- 3. FLASK ROUTEN ---

@app.route("/")
def index():
    """Startseite des Dashboards."""
    
    # 1. Prüfen, ob der Benutzer bereits eingeloggt ist
    if 'discord_token' not in session:
        return render_template("index.html", logged_in=False)

    # 2. Wenn eingeloggt, versuchen, Benutzerdaten abzurufen
    try:
        token = session.get('discord_token')
        # Session mit gespeichertem Token wiederherstellen
        discord = get_discord_session(token=token) 
        
        user = fetch_discord_user(discord)
        # Serverdaten abrufen
        guilds = fetch_discord_guilds(discord)
        
        if user and guilds is not None:
            # Übergebe Firebase Token und Guilds an das Dashboard-Template
            return render_template("dashboard.html", 
                                   logged_in=True, 
                                   user=user,
                                   guilds=guilds,
                                   firebase_token=session.get('firebase_token'))
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
    
    discord = get_discord_session()
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    
    session['oauth_state'] = state
    session.permanent = True
    
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    """Wird nach erfolgreicher Discord-Anmeldung aufgerufen (Redirect URI)."""
    
    # 1. Zustand (state) prüfen (CSRF-Schutz)
    if request.values.get('state') != session.get('oauth_state'):
        print("ERROR: Ungültiger State-Parameter (CSRF-Schutz)", file=sys.stderr)
        return render_template("error.html", message="Ungültiger State-Parameter."), 403
    
    # 2. Token abrufen
    try:
        discord = get_discord_session() 
        
        token = discord.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=request.url
        )
        
    except HTTPError as e:
        print(f"ERROR: HTTP-Fehler beim Abrufen des Tokens: {e.response.text}", file=sys.stderr)
        return render_template("error.html", message="Fehler beim Abrufen des Discord-Tokens. HTTP Error."), 500
    except Exception as e:
        print(f"ERROR: Unerwarteter Fehler beim Token-Abruf: {e}", file=sys.stderr)
        return render_template("error.html", message="Unerwarteter Fehler beim Abrufen des Discord-Tokens."), 500
        
    # 3. Token in der Session speichern
    session['discord_token'] = token
    
    # 4. Benutzerdaten abrufen und Firebase Auth Token erstellen
    user_session = get_discord_session(token=token) 
    user_data = fetch_discord_user(user_session)
    
    if user_data:
        discord_id = str(user_data['id'])
        # Discord bietet global_name ODER username an
        username = user_data.get('global_name') or user_data.get('username')
        # Die E-Mail ist dank des 'email' Scopes verfügbar
        user_email = user_data.get('email', f"{discord_id}@discord.safe-cord.com") 
        
        # Erstelle oder aktualisiere den Firebase-Benutzer
        try:
            # 1. Firebase-Benutzer abrufen (prüfen, ob er existiert)
            auth.get_user(discord_id)
            # Aktualisieren, falls Display Name oder E-Mail sich geändert haben
            auth.update_user(discord_id, display_name=username, email=user_email)
        except auth.AuthError:
            # Benutzer existiert nicht, neu erstellen
            auth.create_user(
                uid=discord_id,
                email=user_email,
                display_name=username
            )
        
        # 2. Firebase Custom Token erstellen
        custom_token = auth.create_custom_token(discord_id)
        
        # 3. Speichern des Custom Tokens für die Frontend-Authentifizierung
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
    
    # Rendere das Logout-Template
    return render_template("logout.html")

# --- 4. Firestore API-Route (Zusätzliche Funktionalität) ---

@app.route('/api/guild/<guild_id>/config', methods=['GET', 'POST'])
def handle_guild_config(guild_id):
    """
    Speichert oder ruft die Konfiguration für einen bestimmten Discord-Server ab.
    """
    if 'user_id' not in session or not db:
        return jsonify({"error": "Nicht authentifiziert oder Firestore nicht verfügbar."}), 401
    
    # Pfad: /guild_configs/{guild_id}
    doc_ref = db.collection('guild_configs').document(guild_id)
    
    if request.method == 'GET':
        # Daten abrufen
        doc = doc_ref.get()
        if doc.exists:
            return jsonify(doc.to_dict()), 200
        else:
            # Standardkonfiguration zurückgeben
            return jsonify({"status": f"No config found for {guild_id}", "welcome_message": "Willkommen!"}), 200
            
    elif request.method == 'POST':
        # Daten speichern
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Fehlende JSON-Daten"}), 400
            
            # Merge=True verhindert, dass das gesamte Dokument überschrieben wird
            doc_ref.set(data, merge=True)
            return jsonify({"status": f"Config for {guild_id} updated successfully", "data": data}), 200
        except Exception as e:
            print(f"ERROR: Fehler beim Speichern der Konfiguration: {e}", file=sys.stderr)
            return jsonify({"error": "Interner Serverfehler beim Speichern"}), 500

# --- 5. FLASK START (Nur für den lokalen Test) ---

if __name__ == '__main__':
    # Lokaler Test auf Port 8080
    app.run(debug=True, port=8080)