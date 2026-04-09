
# --- Lucius Engine / H1 Identity ---
export H1_USER="lucius-log"
export H1_HEADER="X-HackerOne-Research: lucius-log"
export H1_EMAIL="lucius-log@wearehackerone.com"

# --- API Tokens (Managed via secure env) ---
# Use 'security find-generic-password' or similar for production
export SHOPIFY_PARTNER_TOKEN=$(security find-generic-password -s "ShopifyPartnerToken" -w)
export WP_CORE_TOKEN=$(security find-generic-password -s "WPCoreToken" -w)
. "$HOME/.local/bin/env"
export GOOGLE_API_KEY="AIzaSyA6oCTF3T7Rfw5W-9RHbya3rovywheNk4U"
alias bountyscope="source /Users/chris-peterson/bug-bounty/bountyscope/backend/.venv/bin/activate && python /Users/chris-peterson/bug-bounty/bountyscope/cli/bountyscope.py"
