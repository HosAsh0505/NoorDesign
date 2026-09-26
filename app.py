from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session
)

import os
import re
import ipaddress
import time
import threading
import csv
import io
import urllib.request
import urllib.error
import json


# ============================================================
# Flask
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "CHANGE_THIS_SECRET_KEY"
)


# ============================================================
# Network / Agent Configuration
# ============================================================

FIREWALL_IP = "10.9.9.111"

AGENT_TOKEN = os.getenv(
    "NOOR_AGENT_TOKEN",
    "CHANGE_THIS_AGENT_TOKEN"
)


# ============================================================
# Global Discovery State
# ============================================================

devices = []

discovery_finished = False

discovery_error = None

discovery_lock = threading.Lock()


# ============================================================
# Agent State
# ============================================================

agent_status = {
    "online": False,
    "agent_id": None,
    "hostname": None,
    "last_seen": 0,
    "registered_at": 0
}

agent_jobs = []

agent_results = {}

agent_lock = threading.Lock()


# ============================================================
# Live Router Sessions
#
# IMPORTANT:
# These are now maintained by agent.py.
# app.py only sends commands to the agent.
# ============================================================

# Kept here only for compatibility / future usage.
live_sessions = {}


# ============================================================
# Google Sheet Router Inventory
# ============================================================

GOOGLE_SHEET_ID = (
    "1ymyplhGKoGxXpqQpK68sZMVTLHua7-MqrKars93QOTg"
)

GOOGLE_SHEET_GID = "0"

GOOGLE_SHEET_CSV_URL = (
    f"https://docs.google.com/spreadsheets/d/"
    f"{GOOGLE_SHEET_ID}/export?format=csv&gid={GOOGLE_SHEET_GID}"
)

ROUTERS_JSON_FILE = "routers.json"

router_inventory = []

router_inventory_lock = threading.Lock()


# ============================================================
# Vendor Normalization
# ============================================================

def normalize_vendor(vendor):

    if not vendor:
        return "Unknown"

    v = str(vendor).strip().lower()

    if (
        "forti" in v
        or "fortigate" in v
    ):
        return "Forti"

    if (
        "juniper" in v
        or "junos" in v
        or "mx" == v
        or v.startswith("mx")
    ):
        return "Juniper"

    if (
        "huawei" in v
        or "vrp" in v
        or "ne40" in v
        or "ar" == v
    ):
        return "Huawei"

    if (
        "ios xr" in v
        or v == "xr"
        or "xrv" in v
        or "iosxr" in v
    ):
        return "XR"

    if (
        "ios xe" in v
        or v == "xe"
        or "cisco xe" in v
        or "asr" in v
        or "isr" in v
    ):
        return "XE"

    return str(vendor).strip()


# ============================================================
# Google Sheet Loader
# ============================================================

def load_routers_from_google_sheet():

    try:

        print("[ROUTER DB] Loading Google Sheet...")

        with urllib.request.urlopen(
            GOOGLE_SHEET_CSV_URL,
            timeout=15
        ) as response:

            data = response.read().decode(
                "utf-8-sig",
                errors="replace"
            )

        reader = csv.DictReader(
            io.StringIO(data)
        )

        if not reader.fieldnames:
            raise RuntimeError(
                "Google Sheet has no headers"
            )

        headers = [
            str(h).strip()
            for h in reader.fieldnames
            if h
        ]

        ip_column = None
        vendor_column = None

        for h in headers:

            hl = h.lower()

            if hl in (
                "ip",
                "ip address",
                "router ip",
                "address"
            ):
                ip_column = h

            if hl in (
                "vendor",
                "platform",
                "device vendor",
                "type"
            ):
                vendor_column = h

        if not ip_column:

            # Try fuzzy detection
            for h in headers:

                if "ip" in h.lower():
                    ip_column = h
                    break

        if not vendor_column:

            for h in headers:

                if (
                    "vendor" in h.lower()
                    or "platform" in h.lower()
                ):
                    vendor_column = h
                    break

        if not ip_column:

            raise RuntimeError(
                "Could not find IP column in Google Sheet"
            )

        routers = []

        seen = set()

        for row in reader:

            ip = str(
                row.get(ip_column, "")
            ).strip()

            if not ip:
                continue

            try:

                ipaddress.ip_address(ip)

            except ValueError:

                print(
                    f"[ROUTER DB] Invalid IP skipped: {ip}"
                )

                continue

            if ip in seen:
                continue

            seen.add(ip)

            vendor = "Unknown"

            if vendor_column:
                vendor = normalize_vendor(
                    row.get(vendor_column, "")
                )

            routers.append({
                "ip": ip,
                "vendor": vendor
            })

        if not routers:

            raise RuntimeError(
                "Google Sheet returned zero routers"
            )

        print(
            f"[ROUTER DB] Loaded {len(routers)} routers from Google Sheet"
        )

        return routers

    except Exception as e:

        print(
            f"[ROUTER DB] Google Sheet error: {e}"
        )

        return []


# ============================================================
# JSON Router Inventory
# ============================================================

def load_routers_from_json():

    try:

        if not os.path.exists(
            ROUTERS_JSON_FILE
        ):
            return []

        with open(
            ROUTERS_JSON_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        if not isinstance(data, list):
            return []

        routers = []

        seen = set()

        for item in data:

            if not isinstance(item, dict):
                continue

            ip = str(
                item.get("ip", "")
            ).strip()

            if not ip:
                continue

            try:

                ipaddress.ip_address(ip)

            except ValueError:
                continue

            if ip in seen:
                continue

            seen.add(ip)

            routers.append({
                "ip": ip,
                "vendor": normalize_vendor(
                    item.get("vendor", "Unknown")
                )
            })

        print(
            f"[ROUTER DB] Loaded {len(routers)} routers from JSON"
        )

        return routers

    except Exception as e:

        print(
            f"[ROUTER DB] JSON error: {e}"
        )

        return []


# ============================================================
# Main Router Inventory Loader
# ============================================================

def load_router_inventory():

    global router_inventory

    routers = load_routers_from_google_sheet()

    if not routers:

        print(
            "[ROUTER DB] Google Sheet failed."
            " Falling back to routers.json"
        )

        routers = load_routers_from_json()

    with router_inventory_lock:

        router_inventory = routers

    return routers


# ============================================================
# Config Parsing
# ============================================================

def extract_hostname(cfg, username=""):

    patterns = [

        r"(?im)^\s*hostname\s+(\S+)",

        r"(?im)^\s*set\s+system\s+host-name\s+(\S+)",

        r"(?im)^\s*sysname\s+(\S+)",

        r"(?im)^\s*config\s+system\s+global[\s\S]*?^\s*set\s+hostname\s+(\S+)",

        r"(?im)^\s*Hostname:\s*(\S+)",

    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            cfg
        )

        if match:

            return match.group(1).strip()

    return username or "Unknown"


# ============================================================

def extract_version(cfg):

    patterns = [

        # Cisco XE
        r"(?im)^Cisco IOS XE Software.*",

        r"(?im)^Cisco IOS Software.*",

        # Cisco XR
        r"(?im)^Cisco IOS XR Software.*",

        # Juniper
        r"(?im)^JUNOS.*",

        r"(?im)^Junos:.*",

        # Huawei
        r"(?im)^Huawei Versatile Routing Platform Software.*",

        r"(?im)^VRP.*",

        # FortiGate
        r"(?im)^Version:\s*(.+)$",

    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            cfg
        )

        if match:

            return match.group(0).strip()

    return "Unknown"


# ============================================================

def extract_loopback(cfg):

    patterns = [

        # Cisco XE/XR
        r"(?im)interface\s+Loopback\d+[\s\S]*?ip address\s+(\d+\.\d+\.\d+\.\d+)\s+255\.255\.255\.255",

        # Cisco alternate
        r"(?im)interface\s+Loopback\d+[\s\S]*?ipv4 address\s+(\d+\.\d+\.\d+\.\d+)/32",

        # Juniper
        r"(?im)set interfaces lo0 unit \d+ family inet address (\d+\.\d+\.\d+\.\d+)/32",

        # Huawei
        r"(?im]interface LoopBack\d+[\s\S]*?ip address\s+(\d+\.\d+\.\d+\.\d+)\s+255\.255\.255\.255",

        # FortiGate
        r"(?im)set ip\s+(\d+\.\d+\.\d+\.\d+)\s+255\.255\.255\.255",

    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            cfg
        )

        if match:

            return match.group(1)

    return None


# ============================================================

def extract_nsap(cfg):

    patterns = [

        # Cisco
        r"(?im)net\s+([0-9A-Fa-f.]+)",

        # Juniper
        r"(?im)set protocols isis interface lo0.*",

        # Generic NSAP
        r"(?im)\b49\.[0-9A-Fa-f.]+\b",

    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            cfg
        )

        if match:

            value = match.group(1) if match.lastindex else match.group(0)

            value = value.strip()

            if value.lower().startswith("49."):
                return value

    return None


# ============================================================
# Interface Normalization
# ============================================================

def normalize_interface(name):

    if not name:
        return name

    n = name.strip()

    replacements = {

        "Gi": "GigabitEthernet",
        "Te": "TenGigabitEthernet",
        "Fo": "FortyGigabitEthernet",
        "Hu": "HundredGigE",
        "Eth": "Ethernet",
        "GE": "GigabitEthernet",
        "XGE": "TenGigabitEthernet",
    }

    for old, new in replacements.items():

        if n.startswith(old):

            return new + n[len(old):]

    return n


# ============================================================
# ISIS Parser
# ============================================================

def parse_isis_interfaces(
    cfg,
    vendor
):

    interfaces = []

    vendor = normalize_vendor(vendor)

    # ========================================================
    # Cisco XE
    # ========================================================

    if vendor == "XE":

        blocks = re.findall(
            r"(?ims)^interface\s+(\S+)(.*?)(?=^interface\s+|\Z)",
            cfg
        )

        for interface, body in blocks:

            if re.search(
                r"(?im)^\s*ip router isis",
                body
            ):

                interfaces.append(
                    normalize_interface(interface)
                )

            elif re.search(
                r"(?im)^\s*isis\s+enable",
                body
            ):

                interfaces.append(
                    normalize_interface(interface)
                )

    # ========================================================
    # Cisco XR
    # ========================================================

    elif vendor == "XR":

        blocks = re.findall(
            r"(?ims)^interface\s+(\S+)(.*?)(?=^interface\s+|\Z)",
            cfg
        )

        for interface, body in blocks:

            if re.search(
                r"(?im)isis\s+\S+",
                body
            ):

                interfaces.append(
                    normalize_interface(interface)
                )

    # ========================================================
    # Juniper
    # ========================================================

    elif vendor == "Juniper":

        patterns = [

            r"(?im)^set protocols isis interface (\S+)",

            r"(?im)^set protocols isis interface (\S+)\s",

        ]

        for pattern in patterns:

            matches = re.findall(
                pattern,
                cfg
            )

            for interface in matches:

                interface = interface.strip()

                if interface not in interfaces:

                    interfaces.append(
                        normalize_interface(interface)
                    )

    # ========================================================
    # Huawei
    # ========================================================

    elif vendor == "Huawei":

        blocks = re.findall(
            r"(?ims)^interface\s+(\S+)(.*?)(?=^interface\s+|\Z)",
            cfg
        )

        for interface, body in blocks:

            if re.search(
                r"(?im)isis\s+enable",
                body
            ):

                interfaces.append(
                    normalize_interface(interface)
                )

    # ========================================================
    # FortiGate
    # ========================================================

    elif vendor == "Forti":

        blocks = re.findall(
            r"(?ims)edit\s+\"([^\"]+)\"(.*?)(?=^\s*edit\s+\"|\Z)",
            cfg
        )

        for interface, body in blocks:

            if re.search(
                r"(?im)set\s+network-type\s+point-to-point",
                body
            ):

                interfaces.append(interface)

    return list(
        dict.fromkeys(interfaces)
    )


# ============================================================
# Build ISIS Links
# ============================================================

def build_links(devices_list):

    links = []

    # --------------------------------------------------------
    # First attempt:
    # Match interfaces that have common ISIS network metadata
    # --------------------------------------------------------

    network_map = {}

    for device in devices_list:

        isis_interfaces = device.get(
            "isis_interfaces",
            []
        )

        for interface in isis_interfaces:

            key = interface.strip()

            if not key:
                continue

            network_map.setdefault(
                key,
                []
            ).append(
                device
            )

    # --------------------------------------------------------
    # Create links
    # --------------------------------------------------------

    seen = set()

    for key, members in network_map.items():

        if len(members) < 2:
            continue

        for i in range(
            len(members)
        ):

            for j in range(
                i + 1,
                len(members)
            ):

                a = members[i]
                b = members[j]

                a_id = (
                    a.get("loopback")
                    or a.get("ip")
                    or a.get("hostname")
                )

                b_id = (
                    b.get("loopback")
                    or b.get("ip")
                    or b.get("hostname")
                )

                if not a_id or not b_id:
                    continue

                pair = tuple(
                    sorted(
                        [str(a_id), str(b_id)]
                    )
                )

                if pair in seen:
                    continue

                seen.add(pair)

                links.append({
                    "source": a_id,
                    "target": b_id,
                    "network": key
                })

    return links


# ============================================================
# Agent Authentication
# ============================================================

def verify_agent_token(req):

    token = req.headers.get(
        "X-Agent-Token",
        ""
    )

    if not token:

        auth = req.headers.get(
            "Authorization",
            ""
        )

        if auth.startswith("Bearer "):

            token = auth[
                len("Bearer "):
            ].strip()

    return (
        token
        and token == AGENT_TOKEN
    )


# ============================================================
# Agent Job Creation
# ============================================================

def create_agent_job(
    job_type,
    payload
):

    job_id = (
        f"{int(time.time() * 1000)}"
        f"-{os.urandom(4).hex()}"
    )

    job = {
        "job_id": job_id,
        "type": job_type,
        "payload": payload,
        "created_at": time.time()
    }

    with agent_lock:

        agent_jobs.append(job)

    return job_id


# ============================================================
# Wait For Agent Result
# ============================================================

def wait_for_agent_result(
    job_id,
    timeout=300
):

    started = time.time()

    while (
        time.time() - started
        < timeout
    ):

        with agent_lock:

            result = agent_results.get(
                job_id
            )

            if result is not None:

                # Remove after consuming
                agent_results.pop(
                    job_id,
                    None
                )

                return result

        time.sleep(0.5)

    return {
        "success": False,
        "error": "Agent job timeout"
    }


# ============================================================
# Agent Register
# ============================================================

@app.route(
    "/agent/register",
    methods=["POST"]
)
def agent_register():

    if not verify_agent_token(request):

        return jsonify({
            "success": False,
            "error": "Unauthorized"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    agent_id = data.get(
        "agent_id"
    )

    hostname = data.get(
        "hostname"
    )

    with agent_lock:

        agent_status["online"] = True

        agent_status["agent_id"] = agent_id

        agent_status["hostname"] = hostname

        agent_status["last_seen"] = time.time()

        agent_status["registered_at"] = time.time()

    print(
        f"[AGENT] Registered: {agent_id}"
    )

    return jsonify({
        "success": True,
        "message": "Agent registered",
        "server_time": time.time()
    })


# ============================================================
# Agent Poll
# ============================================================

@app.route(
    "/agent/poll",
    methods=["GET"]
)
def agent_poll():

    if not verify_agent_token(request):

        return jsonify({
            "success": False,
            "error": "Unauthorized"
        }), 401

    with agent_lock:

        agent_status["online"] = True

        agent_status["last_seen"] = time.time()

        if agent_jobs:

            job = agent_jobs.pop(
                0
            )

        else:

            job = None

    if job:

        return jsonify({
            "success": True,
            "job": job
        })

    return jsonify({
        "success": True,
        "job": None
    })


# ============================================================
# Agent Result
# ============================================================

@app.route(
    "/agent/result",
    methods=["POST"]
)
def agent_result():

    if not verify_agent_token(request):

        return jsonify({
            "success": False,
            "error": "Unauthorized"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    job_id = data.get(
        "job_id"
    )

    if not job_id:

        return jsonify({
            "success": False,
            "error": "Missing job_id"
        }), 400

    result = data.get(
        "result",
        {}
    )

    with agent_lock:

        agent_results[job_id] = result

        agent_status["online"] = True

        agent_status["last_seen"] = time.time()

    return jsonify({
        "success": True
    })


# ============================================================
# Agent Status
# ============================================================

@app.route(
    "/agent/status",
    methods=["GET"]
)
def get_agent_status():

    with agent_lock:

        status = dict(
            agent_status
        )

    # Consider agent offline after 15 seconds
    if (
        time.time()
        - status["last_seen"]
        > 15
    ):

        status["online"] = False

    return jsonify(
        status
    )


# ============================================================
# Network Discovery Worker
# ============================================================

def network_discovery_worker(
    username,
    password
):

    global devices
    global discovery_finished
    global discovery_error

    discovery_finished = False
    discovery_error = None

    try:

        print(
            "[DISCOVERY] Starting discovery through Agent..."
        )

        # ----------------------------------------------------
        # Check Agent
        # ----------------------------------------------------

        with agent_lock:

            last_seen = agent_status.get(
                "last_seen",
                0
            )

            is_online = (
                agent_status.get(
                    "online",
                    False
                )
                and
                (
                    time.time()
                    - last_seen
                    <= 15
                )
            )

        if not is_online:

            raise RuntimeError(
                "Network Agent is offline"
            )

        # ----------------------------------------------------
        # Load Router Inventory
        # ----------------------------------------------------

        routers = load_router_inventory()

        if not routers:

            raise RuntimeError(
                "Router inventory is empty"
            )

        print(
            f"[DISCOVERY] Sending {len(routers)} routers to Agent"
        )

        # ----------------------------------------------------
        # Create Discovery Job
        # ----------------------------------------------------

        payload = {
            "firewall_ip": FIREWALL_IP,
            "username": username,
            "password": password,
            "routers": routers
        }

        job_id = create_agent_job(
            "discovery",
            payload
        )

        print(
            f"[DISCOVERY] Job ID: {job_id}"
        )

        # ----------------------------------------------------
        # Wait
        # ----------------------------------------------------

        result = wait_for_agent_result(
            job_id,
            timeout=900
        )

        if not result:

            raise RuntimeError(
                "Empty Agent result"
            )

        if not result.get(
            "success",
            False
        ):

            raise RuntimeError(
                result.get(
                    "error",
                    "Agent discovery failed"
                )
            )

        raw_devices = result.get(
            "devices",
            []
        )

        if not isinstance(
            raw_devices,
            list
        ):

            raise RuntimeError(
                "Invalid discovery result"
            )

        # ----------------------------------------------------
        # Parse returned configurations
        # ----------------------------------------------------

        discovered = []

        for item in raw_devices:

            try:

                ip = item.get(
                    "ip"
                )

                vendor = normalize_vendor(
                    item.get(
                        "vendor",
                        "Unknown"
                    )
                )

                config = item.get(
                    "config",
                    ""
                )

                logs = item.get(
                    "logs",
                    ""
                )

                forced_hostname = item.get(
                    "forced_hostname"
                )

                if not ip:
                    continue

                hostname = (
                    forced_hostname
                    or extract_hostname(
                        config,
                        username
                    )
                )

                version = extract_version(
                    config
                )

                loopback = extract_loopback(
                    config
                )

                nsap = extract_nsap(
                    config
                )

                isis_interfaces = (
                    parse_isis_interfaces(
                        config,
                        vendor
                    )
                )

                device_data = {

                    "ip": ip,

                    "vendor": vendor,

                    "hostname": hostname,

                    "version": version,

                    "loopback": loopback,

                    "nsap": nsap,

                    "isis_interfaces":
                        isis_interfaces,

                    "isis_logs": logs,

                    # Keep raw config
                    # useful for debugging
                    "config": config
                }

                discovered.append(
                    device_data
                )

                print(
                    f"[DISCOVERY] "
                    f"{ip} -> "
                    f"{hostname} -> "
                    f"{vendor} -> "
                    f"{loopback}"
                )

            except Exception as e:

                print(
                    f"[DISCOVERY] Parse error "
                    f"for {item.get('ip')}: {e}"
                )

        # ----------------------------------------------------
        # Build topology
        # ----------------------------------------------------

        links = build_links(
            discovered
        )

        # Store links in every response cycle
        # by keeping them as a global property
        for device in discovered:

            device.setdefault(
                "links",
                []
            )

        # ----------------------------------------------------
        # Update global devices
        # ----------------------------------------------------

        with discovery_lock:

            devices = discovered

        print(
            f"[DISCOVERY] Completed. "
            f"Devices: {len(discovered)}, "
            f"Links: {len(links)}"
        )

        discovery_finished = True

    except Exception as e:

        discovery_error = str(e)

        discovery_finished = True

        print(
            f"[DISCOVERY] ERROR: {e}"
        )


# ============================================================
# Root
# ============================================================

@app.route("/")
def index():

    return redirect(
        url_for("login")
    )


# ============================================================
# Login
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "GET":

        return render_template(
            "login.html"
        )

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    if not username or not password:

        return render_template(
            "login.html",
            error="Username and password are required."
        )

    # --------------------------------------------------------
    # Check Agent
    # --------------------------------------------------------

    with agent_lock:

        last_seen = agent_status.get(
            "last_seen",
            0
        )

        agent_online = (
            agent_status.get(
                "online",
                False
            )
            and
            time.time() - last_seen <= 15
        )

    if not agent_online:

        return render_template(
            "login.html",
            error=(
                "Network Agent is offline. "
                "Start agent.py on the device connected "
                "to FortiClient VPN."
            )
        )

    # --------------------------------------------------------
    # Send SSH Test to Agent
    # --------------------------------------------------------

    job_id = create_agent_job(
        "test_ssh",
        {
            "firewall_ip": FIREWALL_IP,
            "username": username,
            "password": password
        }
    )

    result = wait_for_agent_result(
        job_id,
        timeout=30
    )

    if not result:

        return render_template(
            "login.html",
            error="No response from Network Agent."
        )

    if not result.get(
        "success",
        False
    ):

        return render_template(
            "login.html",
            error=result.get(
                "error",
                "SSH authentication failed."
            )
        )

    # --------------------------------------------------------
    # Store Session
    #
    # TEMPORARY design:
    # Password is stored in Flask session.
    #
    # Later we should replace this with a short-lived
    # server-side credential/session mechanism.
    # --------------------------------------------------------

    session["ssh_user"] = username

    session["ssh_pass"] = password

    session["logged_in"] = True

    # --------------------------------------------------------
    # Start Discovery
    # --------------------------------------------------------

    discovery_thread = threading.Thread(
        target=network_discovery_worker,
        args=(
            username,
            password
        ),
        daemon=True
    )

    discovery_thread.start()

    return redirect(
        url_for("topology")
    )


# ============================================================
# Topology
# ============================================================

@app.route(
    "/topology"
)
def topology():

    if not session.get(
        "logged_in",
        False
    ):

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


# ============================================================
# Topology API
# ============================================================

@app.route(
    "/api/topology"
)
@app.route(
    "/topology/data"
)
def topology_data():

    links = build_links(
        devices
    )

    nodes = []

    for device in devices:

        node_id = (
            device.get("loopback")
            or device.get("ip")
            or device.get("hostname")
        )

        nodes.append({

            "id": node_id,

            "ip": device.get(
                "ip"
            ),

            "hostname": device.get(
                "hostname"
            ),

            "vendor": device.get(
                "vendor"
            ),

            "version": device.get(
                "version"
            ),

            "loopback": device.get(
                "loopback"
            ),

            "nsap": device.get(
                "nsap"
            ),

            "isis_interfaces":
                device.get(
                    "isis_interfaces",
                    []
                )
        })

    return jsonify({

        "nodes": nodes,

        "links": links,

        "finished":
            discovery_finished,

        "error":
            discovery_error
    })


# ============================================================
# Router Database
# ============================================================

@app.route(
    "/router_database"
)
def router_database():

    if not session.get(
        "logged_in",
        False
    ):

        return redirect(
            url_for("login")
        )

    with router_inventory_lock:

        data = list(
            router_inventory
        )

    return jsonify(
        data
    )


# ============================================================
# Helper:
# Find Vendor by Router IP
# ============================================================

def helper_get_vendor_by_ip(ip):

    # --------------------------------------------------------
    # First discovered devices
    # --------------------------------------------------------

    for device in devices:

        if device.get(
            "ip"
        ) == ip:

            return normalize_vendor(
                device.get(
                    "vendor"
                )
            )

        if device.get(
            "loopback"
        ) == ip:

            return normalize_vendor(
                device.get(
                    "vendor"
                )
            )

    # --------------------------------------------------------
    # Router Inventory
    # --------------------------------------------------------

    with router_inventory_lock:

        inventory = list(
            router_inventory
        )

    for router in inventory:

        if router.get(
            "ip"
        ) == ip:

            return normalize_vendor(
                router.get(
                    "vendor"
                )
            )

    # --------------------------------------------------------
    # Reload inventory
    # --------------------------------------------------------

    inventory = load_router_inventory()

    for router in inventory:

        if router.get(
            "ip"
        ) == ip:

            return normalize_vendor(
                router.get(
                    "vendor"
                )
            )

    return "Unknown"


# ============================================================
# Telnet Page
# ============================================================

@app.route(
    "/telnet"
)
def telnet():

    if not session.get(
        "logged_in",
        False
    ):

        return redirect(
            url_for("login")
        )

    return render_template(
        "telnet.html"
    )


# ============================================================
# Execute Router Command
# ============================================================

@app.route(
    "/execute_command",
    methods=["POST"]
)
def execute_command():

    if not session.get(
        "logged_in",
        False
    ):

        return jsonify({
            "success": False,
            "error": "Not authenticated"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    router_ip = str(
        data.get(
            "ip",
            ""
        )
    ).strip()

    command = str(
        data.get(
            "command",
            ""
        )
    )

    is_break = bool(
        data.get(
            "is_break",
            False
        )
    )

    if not router_ip:

        return jsonify({
            "success": False,
            "error": "Missing router IP"
        }), 400

    username = session.get(
        "ssh_user"
    )

    password = session.get(
        "ssh_pass"
    )

    if not username or password is None:

        return jsonify({
            "success": False,
            "error": "Session credentials missing"
        }), 401

    vendor = helper_get_vendor_by_ip(
        router_ip
    )

    # --------------------------------------------------------
    # Send command to Agent
    # --------------------------------------------------------

    job_id = create_agent_job(
        "router_command",
        {

            "firewall_ip":
                FIREWALL_IP,

            "router_ip":
                router_ip,

            "username":
                username,

            "password":
                password,

            "vendor":
                vendor,

            "command":
                command,

            "is_break":
                is_break
        }
    )

    # --------------------------------------------------------
    # Wait for Agent
    # --------------------------------------------------------

    result = wait_for_agent_result(
        job_id,
        timeout=60
    )

    if not result:

        return jsonify({
            "success": False,
            "error": "Agent timeout"
        }), 504

    if not result.get(
        "success",
        False
    ):

        return jsonify({
            "success": False,
            "error": result.get(
                "error",
                "Router command failed"
            )
        }), 500

    # --------------------------------------------------------
    # Raw output from Agent
    # --------------------------------------------------------

    output = str(
        result.get(
            "output",
            ""
        )
    )

    # --------------------------------------------------------
    # Clean output
    # --------------------------------------------------------

    output = output.replace(
        "\x08",
        ""
    )

    output = output.replace(
        "\r",
        ""
    )

    output = re.sub(
        r"--More--",
        "",
        output,
        flags=re.IGNORECASE
    )

    # --------------------------------------------------------
    # Detect More
    # --------------------------------------------------------

    is_more = bool(
        re.search(
            r"--More--",
            output,
            re.IGNORECASE
        )
    )

    # --------------------------------------------------------
    # Detect hostname from prompt
    # --------------------------------------------------------

    prompt_hostname = None

    prompt_patterns = [

        r"(?m)^([A-Za-z0-9_.\-]+)[>#]\s*$",

        r"(?m)^([A-Za-z0-9_.\-]+)\([^)]*\)[>#]\s*$",

        r"(?m)^<([^>]+)>\s*$",

    ]

    for pattern in prompt_patterns:

        matches = re.findall(
            pattern,
            output
        )

        if matches:

            prompt_hostname = (
                matches[-1]
            )

            break

    # --------------------------------------------------------
    # Vendor prompt
    # --------------------------------------------------------

    if not prompt_hostname:

        prompt_hostname = router_ip

    prompt_html = ""

    if vendor == "XE":

        prompt_html = (
            f"<span class='prompt'>"
            f"{prompt_hostname}# "
            f"</span>"
        )

    elif vendor == "XR":

        prompt_html = (
            f"<span class='prompt'>"
            f"{prompt_hostname}# "
            f"</span>"
        )

    elif vendor == "Juniper":

        prompt_html = (
            f"<span class='prompt'>"
            f"{prompt_hostname}@router&gt; "
            f"</span>"
        )

    elif vendor == "Huawei":

        prompt_html = (
            f"<span class='prompt'>"
            f"&lt;{prompt_hostname}&gt; "
            f"</span>"
        )

    elif vendor == "Forti":

        prompt_html = (
            f"<span class='prompt'>"
            f"{prompt_hostname} # "
            f"</span>"
        )

    else:

        prompt_html = (
            f"<span class='prompt'>"
            f"{prompt_hostname}&gt; "
            f"</span>"
        )

    # --------------------------------------------------------
    # Return
    # --------------------------------------------------------

    return jsonify({

        "success": True,

        "output": output,

        "is_more": is_more,

        "vendor": vendor,

        "hostname":
            prompt_hostname,

        "prompt_html":
            prompt_html
    })


# ============================================================
# Logout
# ============================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# Health Check
# ============================================================

@app.route(
    "/health"
)
def health():

    with agent_lock:

        status = dict(
            agent_status
        )

    online = (
        status.get(
            "online",
            False
        )
        and
        time.time()
        - status.get(
            "last_seen",
            0
        )
        <= 15
    )

    return jsonify({

        "server": "online",

        "agent": (
            "online"
            if online
            else "offline"
        ),

        "agent_id":
            status.get(
                "agent_id"
            ),

        "agent_hostname":
            status.get(
                "hostname"
            ),

        "last_seen":
            status.get(
                "last_seen"
            )
    })


# ============================================================
# Load Router Inventory on Startup
# ============================================================

try:

    load_router_inventory()

except Exception as e:

    print(
        f"[STARTUP] Router inventory error: {e}"
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "NOOR NETWORK TOPOLOGY SERVER"
    )

    print("=" * 60)

    print(
        f"Firewall IP: {FIREWALL_IP}"
    )

    print(
        "Agent architecture: ENABLED"
    )

    print(
        "Listening on: 0.0.0.0:5000"
    )

    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "5000"
            )
        ),
        debug=False,
        threaded=True
    )
