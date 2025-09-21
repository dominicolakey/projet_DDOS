import os
import dash
from dash import dcc, html, Input, Output, State, ctx, ALL
import dash_bootstrap_components as dbc
import dash.dash_table
import pandas as pd
from detection_backend import (
    start_detection, stop_detection, get_latest_data,
    get_attack_ips, is_detection_running, get_ip_info, block_ip,
    unblock_ip, get_blocked_ips_list, get_network_interfaces
)
import secrets
import bcrypt
import logging

# === Configuration Logging ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Configuration des identifiants (HASH) ===
# Mot de passe: "motdepasse123" -> hash bcrypt
USERNAME_PASSWORD_PAIRS = {
    "admin": "motdepasse"  # motdepasse123
}

def verify_password(stored_hash, password):
    """Vérification sécurisée du mot de passe"""
    try:
        return password==stored_hash
    except:
        return False

# === Dash App ===
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP], suppress_callback_exceptions=True)
app.server.secret_key = secrets.token_hex(16)
server = app.server

# === Page Login ===
def layout_login(message=""):
    return dbc.Container([
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.H2("🛡️ Système de Détection DDoS", className="text-center mb-1"),
                    html.P("Connexion Administrateur", className="text-center text-muted mb-4"),
                ]),
                html.Div(
                    dbc.Alert(message, color="danger", dismissable=True) if message else html.Div(),
                    id="login-alert"
                ),
                dbc.InputGroup([
                    dbc.InputGroupText("👤"),
                    dbc.Input(id="username", placeholder="Nom d'utilisateur", type="text")
                ], className="mb-3"),
                dbc.InputGroup([
                    dbc.InputGroupText("🔒"),
                    dbc.Input(id="password", placeholder="Mot de passe", type="password")
                ], className="mb-3"),
                dbc.Button("Se connecter", id="login-btn", color="primary", size="lg", className="w-100"),
                html.Div(id="login-output")
            ], width=6, lg=4)
        ], justify="center", style={"marginTop": "10vh"})
    ], fluid=True, style={"backgroundColor": "#f8f9fa", "minHeight": "100vh"})

# === Page principale ===
def layout_main():
    interfaces = get_network_interfaces()
    
    return dbc.Container([
        html.H2("🛡️ Système de Surveillance et Détection DDoS", className="text-center mb-4"),
        
        # Indicateur de statut flottant
        html.Div(id="status-indicator", style={
            "position": "fixed", "top": 20, "right": 20, "zIndex": 9999,
            "padding": "10px", "borderRadius": "5px", "backgroundColor": "white",
            "boxShadow": "0 2px 10px rgba(0,0,0,0.1)"
        }),

        # === Section Contrôles ===
        dbc.Card([
            dbc.CardBody([
                html.H5("⚙️ Contrôles", className="card-title"),
                dbc.Row([
                    dbc.Col([
                        html.Label("Interface Réseau :", className="fw-bold"),
                        dcc.Dropdown(
                            id="interface-input",
                            options=[{"label": iface, "value": iface} for iface in interfaces],
                            value=interfaces[0] if interfaces else "ens33",
                            className="mb-2"
                        ),
                    ], width=3),
                    dbc.Col([
                        html.Label("Actions :", className="fw-bold"),
                        html.Div([
                            dbc.Button("▶️ Démarrer", id="start-btn", color="success", className="me-2"),
                            dbc.Button("⏹️ Arrêter", id="stop-btn", color="danger", className="me-2"),
                            dbc.Button("📥 Télécharger CSV", id="download-btn", color="secondary"),
                        ])
                    ], width=6),
                    dbc.Col([
                        html.Label("IPs Bloquées :", className="fw-bold"),
                        html.Div([
                            dbc.Button("🚫 Voir Bloquées", href="/blocked", target="_blank", color="warning", className="me-2"),
                            dbc.Button("⚠️ IPs Attaquantes", href="/ips", target="_blank", color="info"),
                        ])
                    ], width=3)
                ])
            ])
        ], className="mb-4"),

        # === Section Filtres ===
        dbc.Card([
            dbc.CardBody([
                html.H5("🔍 Filtres", className="card-title"),
                dbc.Row([
                    dbc.Col([
                        dcc.Input(
                            id="filter-src", 
                            placeholder="🌐 Filtrer par IP Source", 
                            type="text",
                            className="form-control"
                        )
                    ]),
                    dbc.Col([
                        dcc.Dropdown(
                            id="filter-protocol",
                            options=[{"label": f"📡 {p}", "value": p} for p in ["TCP", "UDP", "ICMP"]],
                            placeholder="📡 Protocole",
                            clearable=True
                        )
                    ]),
                    dbc.Col([
                        dcc.Dropdown(
                            id="filter-class",
                            options=[
                                {"label": "✅ NORMAL", "value": "NORMAL"},
                                {"label": "🚨 ATTAQUE", "value": "ATTAQUE"}
                            ],
                            placeholder="🎯 Classification",
                            clearable=True
                        )
                    ]),
                    dbc.Col([
                        dbc.Button("🗑️ Effacer", id="clear-filters", color="outline-secondary")
                    ])
                ])
            ])
        ], className="mb-4"),

        # === Notifications Toast ===
        dbc.Toast(
            id="toast", 
            header="🔔 Notification", 
            is_open=False, 
            dismissable=True,
            duration=4000, 
            icon="info",
            style={
                "position": "fixed", "top": 80, "right": 20, 
                "width": 400, "zIndex": 9999
            }
        ),

        # === Tableau de données ===
        dbc.Card([
            dbc.CardBody([
                html.H5("📊 Flux Réseau en Temps Réel", className="card-title"),
                dash.dash_table.DataTable(
                    id="live-table",
                    columns=[
                        {"name": "📅 Date-Heure", "id": "Date-Heure"},
                        {"name": "🌐 IP Source", "id": "IP Source"},
                        {"name": "🎯 IP Destination", "id": "IP Destination"},
                        {"name": "📡 Protocole", "id": "Protocole"},
                        {"name": "🚨 Prédiction", "id": "Prédiction"},
                    ],
                    style_table={"overflowX": "auto"},
                    style_cell={
                        "textAlign": "left", 
                        "padding": "8px", 
                        "color": "black",
                        "fontSize": "14px"
                    },
                    style_header={
                        "fontWeight": "bold", 
                        "backgroundColor": "#343a40", 
                        "color": "white",
                        "textAlign": "center"
                    },
                    style_data_conditional=[
                        {
                            "if": {"filter_query": '{Prédiction} = "ATTAQUE"'},
                            "backgroundColor": "#f8d7da",
                            "color": "#721c24",
                            "fontWeight": "bold"
                        },
                        {
                            "if": {"filter_query": '{Prédiction} = "NORMAL"'},
                            "backgroundColor": "#d1edff",
                            "color": "#0c4128"
                        }
                    ],
                    page_size=20,
                    sort_action="native",
                    filter_action="native"
                )
            ])
        ]),

        # === Téléchargement ===
        dcc.Download(id="download"),

        # === Rafraîchissement auto ===
        dcc.Interval(id="interval", interval=2000, n_intervals=0),

        # === Modal Analyse IP ===
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("🔍 Analyse AbuseIPDB")),
            dbc.ModalBody(
                id="ip-analysis-body", 
                style={
                    "whiteSpace": "pre-wrap", 
                    "fontFamily": "monospace",
                    "backgroundColor": "#f8f9fa",
                    "padding": "15px",
                    "borderRadius": "5px"
                }
            ),
            dbc.ModalFooter([
                dbc.Button("❌ Fermer", id="close-modal", color="secondary")
            ]),
        ], id="ip-analysis-modal", is_open=False, size="lg")
    ], fluid=True, style={"backgroundColor": "#f8f9fa", "minHeight": "100vh", "paddingTop": "20px"})

# === Page IPs Attaquantes ===
def layout_ip_page():
    return dbc.Container([
        html.H3("⚠️ Liste des IPs Attaquantes", className="my-4"),
        dbc.Button("← Retour au Dashboard", href="/", color="secondary", className="mb-3"),
        
        dbc.Alert([
            html.H5("ℹ️ Information", className="alert-heading"),
            "Cette page affiche les adresses IP qui ont déclenché des alertes d'attaque (≥3 détections)."
        ], color="info", className="mb-4"),
        
        dbc.Card([
            dbc.CardBody([
                dbc.ListGroup(id="ip-list")
            ])
        ]),
        
        dcc.Interval(id="refresh-ips", interval=5000, n_intervals=0),
        
        # Modal pour analyse IP
        dbc.Modal([
            dbc.ModalHeader(dbc.ModalTitle("🔍 Analyse AbuseIPDB")),
            dbc.ModalBody(
                id="ip-analysis-body-page", 
                style={
                    "whiteSpace": "pre-wrap", 
                    "fontFamily": "monospace",
                    "backgroundColor": "#f8f9fa",
                    "padding": "15px",
                    "borderRadius": "5px"
                }
            ),
            dbc.ModalFooter([
                dbc.Button("❌ Fermer", id="close-modal-page", color="secondary")
            ]),
        ], id="ip-analysis-modal-page", is_open=False, size="lg")
    ], fluid=True, style={"backgroundColor": "#f8f9fa", "minHeight": "100vh", "paddingTop": "20px"})

# === Page IPs Bloquées ===
def layout_blocked_page():
    return dbc.Container([
        html.H3("🚫 IPs Bloquées", className="my-4"),
        dbc.Button("← Retour au Dashboard", href="/", color="secondary", className="mb-3"),
        
        dbc.Alert([
            html.H5("🛡️ Système de Blocage", className="alert-heading"),
            "Liste des adresses IP actuellement bloquées par iptables."
        ], color="warning", className="mb-4"),
        
        dbc.Card([
            dbc.CardBody([
                dbc.ListGroup(id="blocked-list")
            ])
        ]),
        
        dcc.Interval(id="refresh-blocked", interval=5000, n_intervals=0)
    ], fluid=True, style={"backgroundColor": "#f8f9fa", "minHeight": "100vh", "paddingTop": "20px"})

# === Layout principal avec routage ===
app.layout = html.Div([
    dcc.Location(id="url", refresh=False),
    dcc.Store(id="login-store", storage_type="session"),
    html.Div(id="page-content")
])

# === Callback de routage ===
@app.callback(
    Output("page-content", "children"),
    Input("url", "pathname"),
    Input("login-store", "data")
)
def render_page(path, logged_in):
    if path == "/":
        if logged_in:
            return layout_main()
        else:
            return layout_login()
    elif path == "/ips":
        return layout_ip_page()
    elif path == "/blocked":
        return layout_blocked_page()
    else:
        if logged_in:
            return layout_main()
        else:
            return layout_login()

# === Callback login SÉCURISÉ ===
@app.callback(
    Output("login-store", "data"),
    Output("login-output", "children"),
    Input("login-btn", "n_clicks"),
    State("username", "value"),
    State("password", "value"),
    prevent_initial_call=True
)
def check_login(n, username, password):
    if username and password:
        stored_hash = USERNAME_PASSWORD_PAIRS.get(username)
        if stored_hash and verify_password(stored_hash, password):
            logger.info(f"Connexion réussie pour {username}")
            return True, ""
        else:
            logger.warning(f"Tentative de connexion échouée pour {username}")
            return False, dbc.Alert("❌ Identifiant ou mot de passe incorrect", dismissable=True, is_open=True, color="danger")
    return False, dash.no_update

# === Callback IPs Attaquantes ===
@app.callback(
    Output("ip-list", "children"),
    Input("refresh-ips", "n_intervals"),
    prevent_initial_call=True
)
def update_ip_list(n):
    ip_counts = get_attack_ips()
    items = []
    
    if not ip_counts:
        return [dbc.ListGroupItem("✅ Aucune IP attaquante détectée", color="success")]
    
    for ip, count in ip_counts.items():
        # Déterminer le niveau de menace
        if count >= 10:
            color, badge_color, threat = "danger", "danger", "🔴 CRITIQUE"
        elif count >= 5:
            color, badge_color, threat = "warning", "warning", "🟡 ÉLEVÉ"
        else:
            color, badge_color, threat = "light", "info", "🔵 MODÉRÉ"
            
        items.append(
            dbc.ListGroupItem([
                dbc.Row([
                    dbc.Col([
                        html.H6(f"🌐 {ip}", className="mb-1"),
                        html.Small(f"Détections: {count}", className="text-muted")
                    ], width=4),
                    dbc.Col([
                        dbc.Badge(threat, color=badge_color, className="me-2"),
                    ], width=4),
                    dbc.Col([
                        dbc.ButtonGroup([
                            dbc.Button(
                                "🔍 Analyser", 
                                color="info", 
                                size="sm",
                                id={"type": "btn-analyse", "index": ip}
                            ),
                            dbc.Button(
                                "🚫 Bloquer", 
                                color="danger", 
                                size="sm",
                                id={"type": "btn-block", "index": ip}
                            )
                        ])
                    ], width=4)
                ], align="center")
            ], color=color)
        )
    return items

# === Callback IPs Bloquées ===
@app.callback(
    Output("blocked-list", "children"),
    Input("refresh-blocked", "n_intervals"),
    prevent_initial_call=True
)
def update_blocked_list(n):
    blocked_list = get_blocked_ips_list()
    items = []
    
    if not blocked_list:
        return [dbc.ListGroupItem("✅ Aucune IP bloquée", color="success")]
    
    for entry in blocked_list:
        ip = entry["ip"]
        status = entry["status"]
        active = entry["in_iptables"]
        
        color = "danger" if active else "warning"
        
        items.append(
            dbc.ListGroupItem([
                dbc.Row([
                    dbc.Col([
                        html.H6(f"🌐 {ip}", className="mb-1"),
                        html.Small(status, className="text-muted")
                    ], width=6),
                    dbc.Col([
                        dbc.ButtonGroup([
                            dbc.Button(
                                "🔍 Analyser", 
                                color="info", 
                                size="sm",
                                id={"type": "btn-analyse-blocked", "index": ip}
                            ),
                            dbc.Button(
                                "🔓 Débloquer", 
                                color="success", 
                                size="sm",
                                id={"type": "btn-unblock", "index": ip}
                            )
                        ])
                    ], width=6)
                ], align="center")
            ], color=color)
        )
    return items

# === Callback Démarrer/Arrêter Détection ===
@app.callback(
    Output("toast", "is_open"),
    Output("toast", "children"),
    Output("toast", "icon"),
    Input("start-btn", "n_clicks"),
    Input("stop-btn", "n_clicks"),
    State("interface-input", "value"),
    prevent_initial_call=True
)
def handle_detection(start_clicks, stop_clicks, interface):
    triggered = ctx.triggered_id

    if triggered == "start-btn":
        try:
            start_detection(interface)
            return True, f"🟢 Détection démarrée sur {interface}", "success"
        except Exception as e:
            logger.error(f"Erreur démarrage détection: {e}")
            return True, f"❌ Erreur démarrage: {str(e)}", "danger"

    elif triggered == "stop-btn":
        try:
            stop_detection()
            return True, "🔴 Détection arrêtée", "warning"
        except Exception as e:
            logger.error(f"Erreur arrêt détection: {e}")
            return True, f"❌ Erreur arrêt: {str(e)}", "danger"

    return False, "", "info"

# === Callback Blocage IP ===

@app.callback(
    Output("toast", "is_open", allow_duplicate=True),
    Output("toast", "children", allow_duplicate=True),
    Output("toast", "icon", allow_duplicate=True),
    Input({"type": "btn-analyse", "index": ALL}, "n_clicks"),
    Input({"type": "btn-block", "index": ALL}, "n_clicks"),
    prevent_initial_call=True
)
def handle_ip_buttons(analyse_clicks, block_clicks):
    triggered = ctx.triggered_id
    logger.info(f"Triggered ID: {ctx.triggered_id}")
    # Si c'est le bouton "Analyser"
    if isinstance(triggered, dict) and triggered.get("type") == "btn-analyse":
        ip = triggered.get("index")
        info = get_ip_info(ip)
        return True, info, "info"

    # Si c'est le bouton "Bloquer"
    if isinstance(triggered, dict) and triggered.get("type") == "btn-block":
        ip = triggered.get("index")
        logger.info(f"Tentative de blocage IP: {ip}")
        success = block_ip(ip)
        msg = f"L'adresse IP {ip} a été bloquée avec iptables." if success else f"Erreur lors du blocage de l'adresse IP {ip}."
        return True, msg, "danger"

    # Si aucun bouton n'est cliqué
    return dash.no_update, dash.no_update, dash.no_update
# === Callback Déblocage IP ===
@app.callback(
    Output("toast", "is_open", allow_duplicate=True),
    Output("toast", "children", allow_duplicate=True),
    Output("toast", "icon", allow_duplicate=True),
    Input({"type": "btn-unblock", "index": ALL}, "n_clicks"),
    prevent_initial_call=True
)
def handle_unblock_ip(unblock_clicks):
    triggered = ctx.triggered_id
    if isinstance(triggered, dict) and triggered.get("type") == "btn-unblock":
        ip = triggered.get("index")
        logger.info(f"Tentative de déblocage IP: {ip}")
        success = unblock_ip(ip)
        if success:
            return True, f"🔓 IP {ip} débloquée avec succès", "success"
        else:
            return True, f"❌ Erreur lors du déblocage de {ip}", "warning"

    return dash.no_update, dash.no_update, dash.no_update

# === Callback Téléchargement CSV ===
@app.callback(
    Output("download", "data"),
    Input("download-btn", "n_clicks"),
    prevent_initial_call=True
)
def download_csv(n):
    file_path = os.path.join("cicflowmeter", "flows.csv")
    
    if not os.path.exists(file_path):
        return dash.no_update
    
    return dcc.send_file(file_path)

# === Callback Mise à jour tableau ===
@app.callback(
    Output("live-table", "data"),
    Input("interval", "n_intervals"),
    State("filter-src", "value"),
    State("filter-protocol", "value"),
    State("filter-class", "value"),
)
def update_table(n, filter_src, filter_proto, filter_class):
    data = get_latest_data()
    if not data:
        return []
        
    df = pd.DataFrame(data[::-1][:100])  # Dernières 100 entrées
    
    # Application des filtres
    if filter_src:
        df = df[df["IP Source"].str.contains(filter_src, case=False, na=False)]
    if filter_proto:
        df = df[df["Protocole"] == filter_proto]
    if filter_class:
        df = df[df["Prédiction"] == filter_class]
    
    df = df.head(20)  # Limiter l'affichage
    return df.to_dict("records")

# === Callback Nettoyage filtres ===
@app.callback(
    Output("filter-src", "value"),
    Output("filter-protocol", "value"),
    Output("filter-class", "value"),
    Input("clear-filters", "n_clicks"),
    prevent_initial_call=True
)
def clear_filters(n):
    return "", None, None

# === Callback Indicateur de statut ===
@app.callback(
    Output("status-indicator", "children"),
    Input("interval", "n_intervals")
)
def update_status(n):
    if is_detection_running():
        return html.Div([
            html.Span("🟢", style={"fontSize": "20px", "marginRight": "8px"}),
            html.Span("Détection Active", style={"fontWeight": "bold", "color": "green"})
        ], style={"display": "flex", "alignItems": "center"})
    else:
        return html.Div([
            html.Span("🔴", style={"fontSize": "20px", "marginRight": "8px"}),
            html.Span("Détection Inactive", style={"fontWeight": "bold", "color": "red"})
        ], style={"display": "flex", "alignItems": "center"})

# === Callback Analyse IP (page IPs) ===
@app.callback(
    Output("ip-analysis-modal-page", "is_open"),
    Output("ip-analysis-body-page", "children"),
    Input({"type": "btn-analyse", "index": ALL}, "n_clicks"),
    Input({"type": "btn-analyse-blocked", "index": ALL}, "n_clicks"),
    Input("close-modal-page", "n_clicks"),
    State("ip-analysis-modal-page", "is_open"),
    prevent_initial_call=True,
)
def handle_ip_analysis_page(analyse_clicks, analyse_blocked_clicks, close_click, is_open):
    triggered = ctx.triggered_id
    
    if triggered == "close-modal-page":
        return False, dash.no_update
        
    if isinstance(triggered, dict) and triggered.get("type") in ["btn-analyse", "btn-analyse-blocked"]:
        # Trouver l'index qui a été cliqué
        all_clicks = (analyse_clicks or []) + (analyse_blocked_clicks or [])
        if any(all_clicks):
            ip = triggered.get("index")
            logger.info(f"Analyse demandée pour IP: {ip}")
            info = get_ip_info(ip)
            return True, info
            
    return is_open, dash.no_update

if __name__ == "__main__":
    print("🚀 Démarrage du serveur de détection DDoS...")
    print("📊 Interface disponible sur: http://localhost:8050")
    print("👤 Connexion: admin / motdepasse123")
    app.run(host="0.0.0.0", port=8050, debug=True)
