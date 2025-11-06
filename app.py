import os
from flask import Flask, redirect, url_for, session, request
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv

# --- KONSTANTEN ---
DISCORD_API_BASE_URL = 'https://discord.com/api/v10'
DISCORD_AUTHORIZATION_URL = 'https://discord.com/oauth2/authorize'
DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token'

# --- VARIABLEN VON RENDER LADEN ---
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'https://safe-cord-dashboard.onrender.com/callback')
SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret')
SCOPES = ['identify', 'guilds']

# --- FLASK INITIALISIERUNG ---
app = Flask(__name__)
app.secret_key = SECRET_KEY

def get_discord_oauth():
    return OAuth2Session(
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope=SCOPES,
        token=session.get('oauth_token')
    )

@app.route('/')
def index():
    if 'discord_user' in session:
        return f"Hallo, {session['discord_user']['username']}! Dashboard-Funktion kommt."
    return '<p>Bitte melde dich an.</p><a href="/login">Discord Login</a>'

@app.route('/login')
def login():
    discord_oauth = get_discord_oauth()
    authorization_url, state = discord_oauth.authorization_url(DISCORD_AUTHORIZATION_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    if request.args.get('state') != session.get('oauth_state'):
        return "Ungültiger State-Parameter", 401
    discord_oauth = get_discord_oauth()
    token = discord_oauth.fetch_token(
        DISCORD_TOKEN_URL,
        client_secret=CLIENT_SECRET,
        authorization_response=request.url
    )
    session['oauth_token'] = token
    user = discord_oauth.get(f'{DISCORD_API_BASE_URL}/users/@me').json()
    session['discord_user'] = user
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
