#!/usr/bin/env python3
"""Re-autorise le connecteur Google Ads et reecrit credentials.json.

POURQUOI : le jeton de rafraichissement stocke est mort (invalid_grant, perime le
06/07/2026). Publier l'ecran de consentement OAuth rend les FUTURS jetons durables,
mais ne ressuscite pas un jeton deja revoque : il faut refaire une autorisation.

Le serveur MCP (google_ads_server.py) sait relancer ce flux tout seul, mais il tombe
avant d'y arriver : son message d'erreur reclame GOOGLE_ADS_CLIENT_ID alors que le
vrai probleme est le refresh. Ce script court-circuite ce chemin.

Usage : .venv/bin/python reauth.py
Ouvre le navigateur, attend le clic « Autoriser », puis reecrit credentials.json.
L'ancien fichier est sauvegarde en credentials.json.bak avant ecriture.
"""
import json
import pathlib
import shutil
import sys

from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://www.googleapis.com/auth/adwords"]
ICI = pathlib.Path(__file__).parent
CIBLE = ICI / "credentials.json"

if not CIBLE.exists():
    sys.exit(f"credentials.json introuvable dans {ICI}")

ancien = json.loads(CIBLE.read_text())
client_id = ancien.get("client_id")
client_secret = ancien.get("client_secret")
if not client_id or not client_secret:
    sys.exit("client_id ou client_secret absent de credentials.json")

config = {
    "installed": {
        "client_id": client_id,
        "client_secret": client_secret,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"],
    }
}

print("Ouverture du navigateur. Choisis le compte Google qui gere le compte "
      "administrateur Ads 9280743954, puis clique sur Autoriser.", flush=True)
flow = InstalledAppFlow.from_client_config(config, SCOPES)
creds = flow.run_local_server(port=0, prompt="consent", access_type="offline")

if not creds.refresh_token:
    sys.exit("ECHEC : aucun jeton de rafraichissement renvoye. Revoquer l'acces de "
             "l'application dans le compte Google, puis relancer.")

shutil.copy2(CIBLE, CIBLE.with_suffix(".json.bak"))
nouveau = json.loads(creds.to_json())
# On conserve les cles annexes que le serveur pourrait lire.
for cle in ("account", "universe_domain"):
    if cle in ancien and cle not in nouveau:
        nouveau[cle] = ancien[cle]
CIBLE.write_text(json.dumps(nouveau, indent=2))
print("OK : credentials.json reecrit, jeton de rafraichissement obtenu. "
      "Ancien fichier conserve en credentials.json.bak", flush=True)
