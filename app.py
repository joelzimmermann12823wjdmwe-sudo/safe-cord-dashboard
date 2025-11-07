import os
import json
from flask import Flask, render_template, request, redirect, url_for, session
from google.cloud import firestore
from firebase_admin import auth, credentials, initialize_app
import requests
from dotenv import load_dotenv
import tempfile

# Lade Umgebungsvariablen
load_dotenv()

# --- Globale Konstanten und Initialisierung ---
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
# HIER MUSS DIE ÖFFENTLICHE URL IHRES RENDER-SERVICES EINGETRAGEN WERDEN
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "https://localhost:8080/callback") 
FIRESTORE_SETTINGS_PATH = "safe_cord_dashboard_settings" 
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "super_geheime_schluessel_fuer_session")

app = Flask(__name__)
app.secret_key = SESSION_SECRET_KEY

# Firebase Admin SDK & Firestore Initialisierung
try:
    service_account_json = os.environ.get("GCP_SERVICE_ACCOUNT_KEY")
    if service_account_json:
        # Verwende tempfile für Render-Deployment-Sicherheit
        temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        temp_file.write(service_account_json) 
        temp_file.close()

        cred = credentials.Certificate(temp_file.name)
        initialize_app(cred)
        os.unlink(temp_file.name)
    
    db = firestore.client()
except Exception as e:
    print(f"ERROR: Firebase Admin SDK Initialisierung fehlgeschlagen: {e}")
    db = None

# --- Hilfsfunktionen für Firestore ---
def get_oauth_url():
    """Generiert die Discord OAuth2 URL für den Login."""
    return (
        f"https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}&response_type=code&scope=identify%20guilds"
    )

def fetch_user_data(token):
    """Ruft Benutzer- und Gilden-Informationen von Discord ab."""
    headers = {"Authorization": f"Bearer {token}"}
    user_data = requests.get("https://discord.com/api/v10/users/@me", headers=headers).json()
    guilds_data = requests.get("https://discord.com/api/v10/users/@me/guilds", headers=headers).json()
    return user_data, guilds_data

def get_firebase_custom_token(discord_user_id):
    """Erstellt einen Firebase Custom Token für die Anmeldung des Dashboards."""
    return auth.create_custom_token(str(discord_user_id))

def get_guild_settings(guild_id):
    """Lädt die Einstellungen für eine Gilde aus Firestore und füllt fehlende Modulwerte auf."""
    if not db: return {}
    try:
        doc_ref = db.collection(FIRESTORE_SETTINGS_PATH).document(str(guild_id))
        doc = doc_ref.get()
        settings = doc.to_dict() if doc.exists else {}

        default_modules = {
            'roles_protection': {'active': False},
            'anti_nuke': {'active': True, 'limit': 5, 'time_window': 10},
            'lockdown': {'active': True},
        }
        
        settings['modules'] = settings.get('modules', {})
        for key, default in default_modules.items():
            settings['modules'][key] = settings['modules'].get(key, default)
            
        settings['roles'] = settings.get('roles', {})
            
        return settings
    except Exception as e:
        print(f"ERROR: Firestore-Laden fehlgeschlagen: {e}")
        return {}

def save_guild_settings(guild_id, data):
    """Speichert die Einstellungen für eine Gilde in Firestore."""
    if not db: return False
    try:
        doc_ref = db.collection(FIRESTORE_SETTINGS_PATH).document(str(guild_id))
        doc_ref.set(data)
        return True
    except Exception as e:
        print(f"ERROR: Firestore-Speichern fehlgeschlagen: {e}")
        return False


# --- FLASK-ROUTEN ---

@app.route("/")
def index():
    """Startseite: Zeigt Login-Link oder Dashboard-Auswahl im neuen Design."""
    if 'discord_user_id' not in session:
        return render_template("index.html", oauth_url=get_oauth_url())
    
    admin_guilds = [
        g for g in session.get('guilds', []) 
        if (int(g['permissions']) & 0x8) or (int(g['permissions']) & 0x20) # ADMINISTRATOR oder MANAGE_GUILD
    ]
    
    firebase_token = session.get('firebase_token')
    
    # Rendere das neue Design-Template
    return render_template(
        "safe_cord_select.html",  
        user=session.get('user'), 
        guilds=admin_guilds,
        firebase_token=firebase_token
    )

# ... (callback und logout Routen bleiben gleich) ...

@app.route("/callback")
def callback():
    """Verarbeitet den Discord OAuth2 Callback."""
    code = request.args.get("code")
    if not code: return redirect(url_for("index"))

    token_url = "https://discord.com/api/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "scope": "identify guilds"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        response = requests.post(token_url, data=data, headers=headers).json()
        token = response.get("access_token")
        
        if not token: return redirect(url_for("index"))

        user_data, guilds_data = fetch_user_data(token)
        
        session['discord_user_id'] = user_data['id']
        session['user'] = user_data
        session['guilds'] = guilds_data
        session['firebase_token'] = get_firebase_custom_token(user_data['id'])

        return redirect(url_for("index"))
        
    except Exception as e:
        print(f"ERROR: Beim Callback ist ein Fehler aufgetreten: {e}")
        return redirect(url_for("index"))


@app.route("/dashboard/<guild_id>", methods=["GET", "POST"])
def dashboard(guild_id):
    """Anzeige und Speicherung der Gilden-Einstellungen."""
    if 'discord_user_id' not in session:
        return redirect(url_for("index"))

    guild = next((g for g in session['guilds'] if g['id'] == guild_id), None)
    if not guild or not ((int(guild['permissions']) & 0x8) or (int(guild['permissions']) & 0x20)):
        return "Zugriff verweigert oder Gilde nicht gefunden", 403

    # Simulierte Bot-Rollen
    bot_simulated_roles = [
        {'id': '123456789012345678', 'name': '@Admins'},
        {'id': '987654321098765432', 'name': '@Mods'},
        {'id': '111222333444555666', 'name': '@Member'},
        {'id': guild_id, 'name': '@Everyone'}
    ]

    # POST: Einstellungen speichern
    if request.method == "POST":
        data = get_guild_settings(guild_id)

        # 1. Modul-Aktivierung und Limits speichern
        data['modules']['roles_protection']['active'] = 'roles_protection_active' in request.form
        data['modules']['lockdown']['active'] = 'lockdown_active' in request.form
        
        # Anti-Nuke Limits
        data['modules']['anti_nuke']['active'] = 'anti_nuke_active' in request.form
        try:
            data['modules']['anti_nuke']['limit'] = int(request.form.get('anti_nuke_limit', 5))
            data['modules']['anti_nuke']['time_window'] = int(request.form.get('anti_nuke_time_window', 10))
        except ValueError:
            data['modules']['anti_nuke']['limit'] = 5
            data['modules']['anti_nuke']['time_window'] = 10

        # 2. Rollen-Schutz speichern
        data['roles'] = {role['id']: False for role in bot_simulated_roles}
        for role_id in request.form.getlist('protected_roles'):
            if role_id in data['roles']:
                 data['roles'][role_id] = True

        if save_guild_settings(guild_id, data):
            return redirect(url_for("dashboard", guild_id=guild_id))

    # GET: Dashboard anzeigen
    settings = get_guild_settings(guild_id)

    roles_with_status = []
    for role in bot_simulated_roles:
        role['is_protected'] = settings['roles'].get(role['id'], False)
        roles_with_status.append(role)


    return render_template(
        "dashboard.html",
        guild=guild,
        settings=settings,
        roles=roles_with_status,
        bot_id=DISCORD_CLIENT_ID 
    )


@app.route("/logout")
def logout():
    """Meldet den Benutzer ab."""
    session.clear()
    return redirect(url_for("index"))

# --- START ---
if __name__ == "__main__":
    app.run(host="localhost", port=8080, debug=True)