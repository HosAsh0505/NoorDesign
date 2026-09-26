from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import re
import ipaddress
import paramiko
import time
import threading
import csv
import io
import urllib.request
import urllib.error
import json

app = Flask(__name__)
app.secret_key = "NET_ENGINE_SUPER_SECRET_KEY_1992"

devices = []
discovery_finished = False
FIREWALL_IP = "10.9.9.111"

live_sessions = {}

# =====================================================
# Google Sheets / Routers Database
# =====================================================

GOOGLE_SHEET_ID = "1ymyplhGKoGxXpqQpK68sZMVTLHua7-MqrKars93QOTg"
GOOGLE_SHEET_GID = "0"

GOOGLE_SHEET_CSV_URL = (
    f"https://docs.google.com/spreadsheets/d/"
    f"{GOOGLE_SHEET_ID}/export?format=csv&gid={GOOGLE_SHEET_GID}"
)

ROUTERS_JSON_FILE = "routers.json"

# Cached router inventory
router_inventory = []
router_inventory_lock = threading.Lock()


def normalize_vendor(vendor):
    """
    Converts different vendor names from Google Sheet
    into the exact vendor names used by the application.
    """

    if not vendor:
        return ""

    v = vendor.strip().lower()

    # Normalize separators
    v_normalized = re.sub(r"[^a-z0-9]+", " ", v).strip()
    parts = v_normalized.split()

    # FortiGate
    if (
        "forti" in v_normalized
        or "fortigate" in v_normalized
    ):
        return "Forti"

    # Juniper / Junos
    if (
        "juniper" in v_normalized
        or "junos" in v_normalized
    ):
        return "Juniper"

    # Huawei / VRP
    if (
        "huawei" in v_normalized
        or "vrp" in v_normalized
    ):
        return "Huawei"

    # Cisco IOS XR
    if (
        "xr" in parts
        or "ios xr" in v_normalized
        or "cisco xr" in v_normalized
    ):
        return "XR"

    # Cisco IOS XE
    if (
        "xe" in parts
        or "ios xe" in v_normalized
        or "cisco xe" in v_normalized
    ):
        return "XE"

    # Already correct names
    if v_normalized == "forti":
        return "Forti"

    if v_normalized == "juniper":
        return "Juniper"

    if v_normalized == "huawei":
        return "Huawei"

    if v_normalized == "xr":
        return "XR"

    if v_normalized == "xe":
        return "XE"

    # Unknown vendor:
    # Keep original value so it can still be seen/debugged.
    return vendor.strip()


def load_routers_from_google_sheet():
    """
    Loads router inventory from Google Sheets CSV export.

    Expected columns:
        ip
        vendor

    Also supports headers such as:
        IP
        IP Address
        ip address
        Vendor
        vendor name
    """

    print("\n=====================================================")
    print("[ROUTER DB] Trying to load routers from Google Sheet")
    print("=====================================================")

    try:
        req = urllib.request.Request(
            GOOGLE_SHEET_CSV_URL,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "Chrome/154.0 Safari/537.36"
                )
            }
        )

        with urllib.request.urlopen(req, timeout=15) as response:
            raw_data = response.read().decode("utf-8-sig")

        if not raw_data.strip():
            raise ValueError("Google Sheet returned an empty response.")

        reader = csv.DictReader(io.StringIO(raw_data))

        if not reader.fieldnames:
            raise ValueError("Google Sheet does not contain a header row.")

        # Normalize header names
        header_map = {}

        for header in reader.fieldnames:
            if header is None:
                continue

            clean_header = header.strip().lower()
            header_map[clean_header] = header

        # Find IP column
        ip_column = None

        for clean_header, original_header in header_map.items():
            if (
                clean_header == "ip"
                or clean_header.startswith("ip ")
                or clean_header.startswith("ip_")
            ):
                ip_column = original_header
                break

        # Find Vendor column
        vendor_column = None

        for clean_header, original_header in header_map.items():
            if (
                clean_header == "vendor"
                or clean_header.startswith("vendor ")
                or clean_header.startswith("vendor_")
            ):
                vendor_column = original_header
                break

        if not ip_column:
            raise ValueError(
                "Google Sheet does not contain an IP column."
            )

        if not vendor_column:
            raise ValueError(
                "Google Sheet does not contain a Vendor column."
            )

        print(f"[ROUTER DB] IP column     : {ip_column}")
        print(f"[ROUTER DB] Vendor column : {vendor_column}")

        routers = []
        seen_ips = set()

        for row_number, row in enumerate(reader, start=2):

            ip = (row.get(ip_column) or "").strip()
            vendor_raw = (row.get(vendor_column) or "").strip()

            # Ignore completely empty rows
            if not ip and not vendor_raw:
                continue

            if not ip:
                print(
                    f"[ROUTER DB] WARNING: Row {row_number} "
                    f"has no IP. Skipping."
                )
                continue

            if not vendor_raw:
                print(
                    f"[ROUTER DB] WARNING: Row {row_number} "
                    f"has no Vendor. Skipping."
                )
                continue

            # Validate IPv4 / IPv6 address
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(
                    f"[ROUTER DB] WARNING: Row {row_number} "
                    f"has invalid IP: {ip}. Skipping."
                )
                continue

            # Avoid duplicate IPs
            if ip in seen_ips:
                print(
                    f"[ROUTER DB] WARNING: Duplicate IP {ip}. "
                    f"Skipping duplicate row."
                )
                continue

            seen_ips.add(ip)

            vendor = normalize_vendor(vendor_raw)

            routers.append(
                {
                    "ip": ip,
                    "vendor": vendor
                }
            )

        if not routers:
            raise ValueError(
                "Google Sheet was accessible, "
                "but no valid routers were found."
            )

        print(
            f"[ROUTER DB] SUCCESS: Loaded "
            f"{len(routers)} router(s) from Google Sheet."
        )

        for router in routers:
            print(
                f"[ROUTER DB]   {router['ip']} -> "
                f"{router['vendor']}"
            )

        print("=====================================================\n")

        return routers

    except urllib.error.HTTPError as e:
        print(
            f"[ROUTER DB] Google Sheet HTTP Error: "
            f"{e.code} - {e.reason}"
        )

    except urllib.error.URLError as e:
        print(
            f"[ROUTER DB] Google Sheet URL Error: "
            f"{e.reason}"
        )

    except Exception as e:
        print(
            f"[ROUTER DB] Google Sheet Error: "
            f"{str(e)}"
        )

    print(
        "[ROUTER DB] Google Sheet failed. "
        "Will fallback to routers.json."
    )

    return []


def load_routers_from_json():
    """
    Fallback database.

    Used ONLY when Google Sheet cannot be loaded
    or contains no valid routers.
    """

    print("\n=====================================================")
    print("[ROUTER DB] Loading fallback routers.json")
    print("=====================================================")

    try:
        with open(
            ROUTERS_JSON_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            routers_list = json.load(f)

        if not isinstance(routers_list, list):
            raise ValueError(
                "routers.json must contain a JSON array."
            )

        routers = []
        seen_ips = set()

        for router in routers_list:

            if not isinstance(router, dict):
                continue

            ip = str(router.get("ip", "")).strip()
            vendor_raw = str(router.get("vendor", "")).strip()

            if not ip or not vendor_raw:
                continue

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(
                    f"[ROUTER DB] WARNING: Invalid IP in "
                    f"routers.json: {ip}"
                )
                continue

            if ip in seen_ips:
                continue

            seen_ips.add(ip)

            vendor = normalize_vendor(vendor_raw)

            routers.append(
                {
                    "ip": ip,
                    "vendor": vendor
                }
            )

        if not routers:
            raise ValueError(
                "routers.json contains no valid routers."
            )

        print(
            f"[ROUTER DB] FALLBACK SUCCESS: Loaded "
            f"{len(routers)} router(s) from routers.json."
        )

        for router in routers:
            print(
                f"[ROUTER DB]   {router['ip']} -> "
                f"{router['vendor']}"
            )

        print("=====================================================\n")

        return routers

    except FileNotFoundError:
        print(
            f"[ROUTER DB] ERROR: {ROUTERS_JSON_FILE} "
            f"was not found."
        )

    except json.JSONDecodeError as e:
        print(
            f"[ROUTER DB] ERROR: Invalid JSON in "
            f"{ROUTERS_JSON_FILE}: {e}"
        )

    except Exception as e:
        print(
            f"[ROUTER DB] Error reading {ROUTERS_JSON_FILE}: "
            f"{str(e)}"
        )

    return []


def load_router_inventory():
    """
    Main router database loader.

    Priority:
        1. Google Sheet
        2. routers.json fallback
    """

    global router_inventory

    # =================================================
    # FIRST: Google Sheet
    # =================================================

    routers = load_routers_from_google_sheet()

    # =================================================
    # FALLBACK: routers.json
    # =================================================

    if not routers:
        routers = load_routers_from_json()

    # =================================================
    # Save in memory
    # =================================================

    with router_inventory_lock:
        router_inventory = routers

    if routers:
        print(
            f"[ROUTER DB] Active router database contains "
            f"{len(routers)} router(s)."
        )
    else:
        print(
            "[ROUTER DB] CRITICAL: No router database "
            "is available."
        )

    return routers


# =====================================================
# دالات الـ Parsing الأصلية
# =====================================================

def extract_hostname(cfg, username):
    patterns = [
        r"hostname\s+(\S+)",
        r"sysname\s+(.+)",
        r"Hostname:\s*(\S+)",
        r"root@([\w\-.]+)",
        r"host-name\s+(\S+)",
        r"RP/0/\S+/CPU0:([^#\s\r\n]+)#",
        rf"{re.escape(username)}@([^>\s:]+)>",
        r"^[^@\s]+@([^>\r\n]+)>$"
    ]

    for p in patterns:
        m = re.search(p, cfg)

        if m:
            return m.group(1).strip()

    return "UNKNOWN"


def extract_version(cfg):
    m = re.search(r"Version\s+([\S]+)", cfg)

    if m:
        return m.group(1)

    m = re.search(r"Junos:\s+([\S]+)", cfg)

    if m:
        return m.group(1)

    m = re.search(
        r"!! IOS XR Configuration ([\S]+)",
        cfg
    )

    if m:
        return m.group(1)

    m = re.search(
        r"\[V(\d+R\d+C\d+)\]",
        cfg
    )

    if m:
        return m.group(1)

    return "Unknown"


def extract_loopback(cfg):
    m = re.search(
        r"LoopBack0.*?ipv4 address "
        r"(\d+\.\d+\.\d+\.\d+)",
        cfg,
        re.S | re.I
    )

    if m:
        return m.group(1)

    m = re.search(
        r"Loopback0.*?ip address "
        r"(\d+\.\d+\.\d+\.\d+)",
        cfg,
        re.S | re.I
    )

    if m:
        return m.group(1)

    m = re.search(
        r"lo0.*?address "
        r"(\d+\.\d+\.\d+\.\d+)",
        cfg,
        re.S
    )

    if m:
        return m.group(1)

    m = re.search(
        r'edit\s+"loopback0".*?set ip '
        r"(\d+\.\d+\.\d+\.\d+)",
        cfg,
        re.S | re.I
    )

    if m:
        return m.group(1)

    return ""


def extract_nsap(cfg):
    m = re.search(
        r"net\s+(49\..+)",
        cfg,
        re.MULTILINE
    )

    if m:
        return m.group(1)

    m = re.search(
        r"network-entity\s+([\d\.]+)",
        cfg
    )

    if m:
        return m.group(1)

    m = re.search(
        r"iso address\s+([\d\.]+)",
        cfg
    )

    if m:
        return m.group(1)

    return ""


def normalize_interface(name):
    if "." in name:
        base, sub = name.split(".", 1)
        return base, sub

    return name, None


def parse_isis_interfaces(cfg, vendor):
    interfaces = []

    # =================================================
    # Cisco IOS XE
    # =================================================

    if vendor == "XE":

        blocks = re.findall(
            r"interface (\S+)(.*?)!",
            cfg,
            re.S
        )

        for name, block in blocks:

            if "ip router isis" in block:

                m = re.search(
                    r"ip address (\S+) (\S+)",
                    block
                )

                if m:
                    ip, mask = m.group(1), m.group(2)

                    net = ipaddress.IPv4Network(
                        f"{ip}/{mask}",
                        strict=False
                    )

                    base, sub = normalize_interface(name)

                    interfaces.append(
                        {
                            "name": name,
                            "base": base,
                            "sub": sub,
                            "ip": ip,
                            "network": str(net)
                        }
                    )

    # =================================================
    # Cisco IOS XR
    # =================================================

    elif vendor == "XR":

        isis_block = re.search(
            r"router isis.*?(?=\n\S)",
            cfg,
            re.S
        )

        isis_intfs = []

        if isis_block:

            for line in isis_block.group(0).splitlines():

                line = line.strip()

                if line.startswith("interface"):
                    isis_intfs.append(
                        line.split()[1]
                    )

        blocks = re.findall(
            r"interface (\S+)(.*?)!",
            cfg,
            re.S
        )

        for name, block in blocks:

            if name in isis_intfs:

                m = re.search(
                    r"ipv4 address (\S+) (\S+)",
                    block
                )

                if m:

                    ip, mask = (
                        m.group(1),
                        m.group(2)
                    )

                    net = ipaddress.IPv4Network(
                        f"{ip}/{mask}",
                        strict=False
                    )

                    base, sub = normalize_interface(name)

                    interfaces.append(
                        {
                            "name": name,
                            "base": base,
                            "sub": sub,
                            "ip": ip,
                            "network": str(net)
                        }
                    )

    # =================================================
    # Juniper
    # =================================================

    elif vendor == "Juniper":

        iso_interfaces = re.findall(
            r"set interfaces (\S+) "
            r"unit (\S+) family iso",
            cfg
        )

        for base, unit in iso_interfaces:

            intf = f"{base}.{unit}"

            m = re.search(
                rf"set interfaces "
                rf"{re.escape(base)} "
                rf"unit {re.escape(unit)} "
                rf"family inet address (\S+)",
                cfg
            )

            if m:

                ip_net = m.group(1)

                ip = ip_net.split("/")[0]

                interfaces.append(
                    {
                        "name": intf,
                        "base": base,
                        "sub": unit,
                        "ip": ip,
                        "network": str(
                            ipaddress.ip_interface(
                                ip_net
                            ).network
                        )
                    }
                )

    # =================================================
    # Huawei
    # =================================================

    elif vendor == "Huawei":

        blocks = re.findall(
            r"interface (\S+)(.*?)#",
            cfg,
            re.S
        )

        for name, block in blocks:

            if "isis enable" in block:

                m = re.search(
                    r"ip address (\S+) (\S+)",
                    block
                )

                if m:

                    ip, mask = (
                        m.group(1),
                        m.group(2)
                    )

                    net = ipaddress.IPv4Network(
                        f"{ip}/{mask}",
                        strict=False
                    )

                    base, sub = normalize_interface(name)

                    interfaces.append(
                        {
                            "name": name,
                            "base": base,
                            "sub": sub,
                            "ip": ip,
                            "network": str(net)
                        }
                    )

    # =================================================
    # FortiGate
    # =================================================

    elif vendor == "Forti":

        isis_block = re.search(
            r"config router isis(.*?)end",
            cfg,
            re.S
        )

        isis_intfs = []

        if isis_block:
            isis_intfs = re.findall(
                r'edit\s+"(.*?)"',
                isis_block.group(1)
            )

        blocks = re.findall(
            r'edit\s+"(.*?)"(.*?)next',
            cfg,
            re.S
        )

        for name, block in blocks:

            if name in isis_intfs:

                m = re.search(
                    r"set ip "
                    r"(\d+\.\d+\.\d+\.\d+) "
                    r"(\d+\.\d+\.\d+\.\d+)",
                    block
                )

                if m:

                    ip, mask = (
                        m.group(1),
                        m.group(2)
                    )

                    net = ipaddress.IPv4Network(
                        f"{ip}/{mask}",
                        strict=False
                    )

                    base, sub = normalize_interface(name)

                    interfaces.append(
                        {
                            "name": name,
                            "base": base,
                            "sub": sub,
                            "ip": ip,
                            "network": str(net)
                        }
                    )

    return interfaces


def build_links(devices_list):

    grouped = {}

    for d1 in devices_list:

        for i1 in d1["isis_interfaces"]:

            try:
                net1 = ipaddress.ip_network(
                    i1["network"],
                    strict=False
                )
            except Exception:
                continue

            for d2 in devices_list:

                if d1["hostname"] == d2["hostname"]:
                    continue

                for i2 in d2["isis_interfaces"]:

                    try:
                        net2 = ipaddress.ip_network(
                            i2["network"],
                            strict=False
                        )
                    except Exception:
                        continue

                    if net1 != net2:
                        continue

                    pair = tuple(
                        sorted(
                            [
                                d1["hostname"],
                                d2["hostname"]
                            ]
                        )
                    )

                    if pair not in grouped:

                        grouped[pair] = {
                            "from": pair[0],
                            "to": pair[1],
                            "connections": []
                        }

                    conn = {
                        "network": str(net1),
                        "routerA": d1["hostname"],
                        "routerB": d2["hostname"],
                        "interfaceA": (
                            f'{i1["name"]} - '
                            f'{i1["ip"]}'
                        ),
                        "interfaceB": (
                            f'{i2["name"]} - '
                            f'{i2["ip"]}'
                        )
                    }

                    network_exists = False

                    for existing in grouped[pair]["connections"]:

                        if existing["network"] == conn["network"]:
                            network_exists = True
                            break

                    if network_exists:
                        continue

                    grouped[pair]["connections"].append(conn)

    return list(grouped.values())


# =====================================================
# Discovery
# =====================================================

def fetch_config_via_ssh_tunnel(
    chan,
    ip,
    vendor,
    username,
    password
):

    try:

        if chan.recv_ready():
            chan.recv(65535)

        chan.send(f"telnet {ip}\n")

        output = ""

        timeout = 10
        start_time = time.time()

        while time.time() - start_time < timeout:

            if chan.recv_ready():

                output += chan.recv(
                    65535
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

                if re.search(
                    r"[Uu]sername:|[L|l]ogin:",
                    output
                ):
                    break

            time.sleep(0.5)

        chan.send(f"{username}\n")

        time.sleep(1)

        output = ""

        start_time = time.time()

        while time.time() - start_time < timeout:

            if chan.recv_ready():

                output += chan.recv(
                    65535
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

                if (
                    "Password:" in output
                    or "password:" in output
                ):
                    break

            time.sleep(0.5)

        chan.send(f"{password}\n")

        time.sleep(3)

        if chan.recv_ready():
            chan.recv(65535)

        # =================================================
        # Prepare terminal
        # =================================================

        if vendor in ["XE", "XR"]:

            chan.send(
                "terminal length 0\n"
            )

            time.sleep(1)

            chan.send(
                "show run\n"
            )

        elif vendor == "Juniper":

            chan.send(
                "show configuration | "
                "display set | no-more\n"
            )

        elif vendor == "Huawei":

            chan.send(
                "screen-length 0 temporary\n"
            )

            time.sleep(1)

            chan.send(
                "display current-config\n"
            )

        elif vendor == "Forti":

            chan.send(
                "show\n"
            )

        # =================================================
        # Collect config
        # =================================================

        config_data = ""

        max_wait_time = 180

        start_collect = time.time()

        time.sleep(3)

        while True:

            if (
                time.time() - start_collect
                > max_wait_time
            ):
                break

            if chan.recv_ready():

                config_data += chan.recv(
                    65535
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

            else:

                last_lines = (
                    config_data[-100:]
                    if len(config_data) > 100
                    else config_data
                )

                if (
                    len(config_data) > 500
                    and (
                        last_lines.strip().endswith("#")
                        or last_lines.strip().endswith(">")
                        or "end" in last_lines.lower()
                    )
                ):

                    time.sleep(1)

                    if not chan.recv_ready():
                        break

                time.sleep(1)

        extracted_name = extract_hostname(
            config_data,
            username
        )

        # =================================================
        # ISIS logs
        # =================================================

        log_command = ""

        if vendor in ["XE", "XR"]:

            log_command = (
                "show logging | include ISIS\n"
            )

        elif vendor == "Juniper":

            log_command = (
                'show log messages | '
                'match "ISIS" | no-more\n'
            )

        elif vendor == "Huawei":

            log_command = (
                "display logbuffer | include ISIS\n"
            )

        log_data = ""

        if log_command:

            if chan.recv_ready():
                chan.recv(65535)

            chan.send(log_command)

            time.sleep(4)

            start_collect_logs = time.time()

            max_log_wait = 25

            while (
                time.time() - start_collect_logs
                < max_log_wait
            ):

                if chan.recv_ready():

                    log_data += chan.recv(
                        65535
                    ).decode(
                        "utf-8",
                        errors="ignore"
                    )

                    start_collect_logs = time.time()

                else:

                    time.sleep(1.0)

                    if not chan.recv_ready():
                        break

            log_data = log_data.replace(
                log_command.strip(),
                ""
            )

        # =================================================
        # Exit Telnet
        # =================================================

        chan.send("exit\n")

        time.sleep(1)

        if chan.recv_ready():
            chan.recv(65535)

        return {
            "config": config_data,
            "logs": log_data,
            "forced_hostname": extracted_name
        }

    except Exception as e:

        print(
            f"Error tunneling telnet for "
            f"{ip}: {e}"
        )

        return None


def network_discovery_worker(
    username,
    password
):

    global devices
    global discovery_finished

    discovery_finished = False

    # =================================================
    # Load router database
    #
    # Google Sheet first
    # routers.json fallback
    # =================================================

    routers_list = load_router_inventory()

    if not routers_list:

        print(
            "[DISCOVERY] No routers available "
            "from Google Sheet or routers.json."
        )

        discovery_finished = True
        return

    try:

        ssh = paramiko.SSHClient()

        ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        ssh.connect(
            FIREWALL_IP,
            username=username,
            password=password,
            timeout=10
        )

        chan = ssh.invoke_shell()

        time.sleep(1)

        if chan.recv_ready():
            chan.recv(65535)

        # =================================================
        # Discover each router
        # =================================================

        for router in routers_list:

            ip = router["ip"]
            vendor = router["vendor"]

            print(
                f"[DISCOVERY] Connecting to "
                f"{ip} ({vendor})"
            )

            res = fetch_config_via_ssh_tunnel(
                chan,
                ip,
                vendor,
                username,
                password
            )

            if res and res.get("config"):

                cfg_content = res["config"]
                log_content = res["logs"]

                hostname = res.get(
                    "forced_hostname",
                    "UNKNOWN"
                )

                if (
                    hostname == "UNKNOWN"
                    and (
                        "hostname"
                        in cfg_content.lower()
                        or "sysname"
                        in cfg_content.lower()
                        or "set"
                        in cfg_content.lower()
                        or "config"
                        in cfg_content.lower()
                    )
                ):

                    hostname = extract_hostname(
                        cfg_content,
                        username
                    )

                if hostname == "UNKNOWN":

                    hostname = (
                        f"Router_"
                        f"{ip.replace('.', '_')}"
                    )

                device_data = {

                    "hostname": hostname,

                    "vendor": vendor,

                    "version": extract_version(
                        cfg_content
                    ),

                    "loopback": extract_loopback(
                        cfg_content
                    ),

                    "nsap": extract_nsap(
                        cfg_content
                    ),

                    "isis_interfaces":
                        parse_isis_interfaces(
                            cfg_content,
                            vendor
                        ),

                    "isis_logs":
                        (
                            log_content.strip()
                            if log_content.strip()
                            else
                            "No recent ISIS logs "
                            "found in buffer."
                        )
                }

                # Remove old copy of same hostname
                devices = [
                    d
                    for d in devices
                    if d["hostname"] != hostname
                ]

                devices.append(device_data)

                print(
                    f"[DISCOVERY] SUCCESS: "
                    f"{hostname} "
                    f"({vendor})"
                )

            else:

                print(
                    f"[DISCOVERY] FAILED: "
                    f"{ip} ({vendor})"
                )

            time.sleep(2)

        ssh.close()

    except Exception as e:

        print(
            f"[DISCOVERY] Discovery error: {e}"
        )

    finally:

        discovery_finished = True

        print(
            "[DISCOVERY] Discovery process finished."
        )


# =====================================================
# Helper: Vendor by Router IP
# =====================================================

def helper_get_vendor_by_ip(ip):

    # =================================================
    # First: already discovered device
    # =================================================

    for d in devices:

        if d.get("loopback") == ip:

            return d.get(
                "vendor",
                "XE"
            )

    # =================================================
    # Second: cached router inventory
    # =================================================

    with router_inventory_lock:

        current_inventory = list(
            router_inventory
        )

    for router in current_inventory:

        if router.get("ip") == ip:

            return router.get(
                "vendor",
                "XE"
            )

    # =================================================
    # Third: refresh database if cache is empty
    # =================================================

    if not current_inventory:

        routers_list = load_router_inventory()

        for router in routers_list:

            if router.get("ip") == ip:

                return router.get(
                    "vendor",
                    "XE"
                )

    return "XE"


# =====================================================
# Flask Routes
# =====================================================

@app.route("/")
def check_session():

    return redirect(
        url_for("login_page")
    )


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login_page():

    if request.method == "POST":

        username = request.form.get(
            "username"
        )

        password = request.form.get(
            "password"
        )

        try:

            # =================================================
            # Validate firewall credentials
            # =================================================

            ssh_test = paramiko.SSHClient()

            ssh_test.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )

            ssh_test.connect(
                FIREWALL_IP,
                username=username,
                password=password,
                timeout=5
            )

            ssh_test.close()

            # =================================================
            # Store session
            # =================================================

            session["ssh_user"] = username
            session["ssh_pass"] = password

            # =================================================
            # Start discovery
            #
            # Router DB:
            # Google Sheet -> routers.json fallback
            # =================================================

            t = threading.Thread(
                target=network_discovery_worker,
                args=(
                    username,
                    password
                )
            )

            t.daemon = True
            t.start()

            return render_template(
                "index.html"
            )

        except Exception as e:

            print(
                f"[LOGIN] Login failed: {e}"
            )

            return render_template(
                "login.html",
                error="Login failed. Access Denied."
            )

    return render_template(
        "login.html"
    )


@app.route("/topology")
def topology():

    return jsonify(
        {
            "nodes": devices,
            "links": build_links(devices),
            "finished": discovery_finished
        }
    )


# =====================================================
# Optional Router Database Status
# =====================================================

@app.route("/router_database")
def router_database():

    with router_inventory_lock:

        current_inventory = list(
            router_inventory
        )

    return jsonify(
        {
            "count": len(current_inventory),
            "routers": current_inventory
        }
    )


# =====================================================
# Stateful Telnet Engine
# =====================================================

def get_or_create_router_channel(
    router_ip,
    username,
    password,
    vendor
):

    session_key = (
        f"{username}_{router_ip}"
    )

    # =================================================
    # Existing session
    # =================================================

    if session_key in live_sessions:

        ssh, chan = live_sessions[
            session_key
        ]

        if (
            chan.get_transport()
            and chan.get_transport().is_active()
        ):

            return chan

    # =================================================
    # New firewall SSH session
    # =================================================

    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    ssh.connect(
        FIREWALL_IP,
        username=username,
        password=password,
        timeout=5
    )

    chan = ssh.invoke_shell()

    time.sleep(0.5)

    if chan.recv_ready():
        chan.recv(65535)

    # =================================================
    # Telnet to router
    # =================================================

    chan.send(
        f"telnet {router_ip}\n"
    )

    time.sleep(1)

    output_gate = ""

    if chan.recv_ready():

        output_gate = chan.recv(
            65535
        ).decode(
            "utf-8",
            errors="ignore"
        )

    if re.search(
        r"[Uu]sername:|[L|l]ogin:",
        output_gate
    ):

        chan.send(
            f"{username}\n"
        )

        time.sleep(0.5)

        chan.send(
            f"{password}\n"
        )

        time.sleep(1)

    elif "password:" in output_gate.lower():

        chan.send(
            f"{password}\n"
        )

        time.sleep(1)

    # =================================================
    # Terminal settings
    # =================================================

    if vendor in ["XE", "XR"]:

        chan.send(
            "terminal length 0\n"
        )

        time.sleep(0.3)

    elif vendor == "Huawei":

        chan.send(
            "screen-length 0 temporary\n"
        )

        time.sleep(0.3)

    if chan.recv_ready():
        chan.recv(65535)

    live_sessions[
        session_key
    ] = (
        ssh,
        chan
    )

    return chan


# =====================================================
# Telnet Page
# =====================================================

@app.route("/telnet")
def telnet_page():

    hostname = request.args.get(
        "hostname",
        "Unknown-Router"
    )

    ip = request.args.get(
        "ip",
        "127.0.0.1"
    )

    vendor = helper_get_vendor_by_ip(
        ip
    )

    welcome_banner = (

        "Microsoft Windows "
        "[Version 10.0.19045.6466]\n"

        "(c) Microsoft Corporation. "
        "All rights reserved.\n\n"

        f"C:\\Users\\CompuMisr>"
        f"ssh {session.get('ssh_user')}"
        f"@{FIREWALL_IP}\n"

        "Linux Kerberos-Slave "
        "Terminal Active...\n"

        f"{session.get('ssh_user')}"
        f"@Kerberos-Slave:~$ "
        f"telnet {ip}\n"

        f"Trying {ip}...\n"

        f"Connected to {ip}.\n"

        "Escape character is '^]'.\n"
    )

    return render_template(
        "telnet.html",
        hostname=hostname,
        ip=ip,
        vendor=vendor,
        initial_banner=welcome_banner.replace(
            "\n",
            "<br>"
        )
    )


# =====================================================
# Execute Telnet Command
# =====================================================

@app.route(
    "/execute_command",
    methods=["POST"]
)
def execute_command():

    username = session.get(
        "ssh_user"
    )

    password = session.get(
        "ssh_pass"
    )

    if not username or not password:

        return jsonify(
            {
                "output":
                    "\n"
                    "<span style='color:red;'>"
                    "[Session Expired]"
                    "</span>\n"
            }
        )

    data = request.json

    router_ip = data.get(
        "ip"
    )

    command = data.get(
        "command",
        ""
    )

    is_break_action = data.get(
        "is_break",
        False
    )

    vendor = helper_get_vendor_by_ip(
        router_ip
    )

    try:

        chan = get_or_create_router_channel(
            router_ip,
            username,
            password,
            vendor
        )

        # =================================================
        # Break / More
        # =================================================

        if is_break_action:

            chan.send("q")

            chan.send("\x03")

            time.sleep(0.5)

        else:

            if command != " ":

                chan.send(
                    f"{command}\n"
                )

            else:

                chan.send(" ")

            if (
                vendor == "Juniper"
                and (
                    "show"
                    in command.lower()
                    or command == " "
                )
            ):

                time.sleep(1.2)

            else:

                time.sleep(0.5)

        # =================================================
        # Collect output
        # =================================================

        raw_output = ""

        start_wait = time.time()

        max_idle = (
            1.0
            if vendor == "Juniper"
            else 0.3
        )

        while True:

            if chan.recv_ready():

                raw_output += chan.recv(
                    65535
                ).decode(
                    "utf-8",
                    errors="ignore"
                )

                start_wait = time.time()

            else:

                time.sleep(0.05)

                if (
                    time.time() - start_wait
                    > max_idle
                ):
                    break

        # =================================================
        # Clean output
        # =================================================

        clean_output = raw_output.replace(
            f"telnet {router_ip}\n",
            ""
        )

        clean_output = re.sub(
            r".\x08+",
            "",
            clean_output
        )

        clean_output = clean_output.replace(
            "\x08",
            ""
        )

        lines = clean_output.splitlines()

        main_body = (
            "<br>".join(lines[:-1])
            if len(lines) > 1
            else clean_output
        )

        last_line = (
            lines[-1]
            if lines
            else ""
        )

        # =================================================
        # More detection
        # =================================================

        is_waiting_more = bool(
            re.search(
                r"---.*more.*---|more",
                last_line,
                re.IGNORECASE
            )
        )

        # =================================================
        # Prompt hostname
        # =================================================

        clean_hostname = last_line.strip()

        for char in [
            "#",
            ">",
            "<",
            "$",
            "@",
            " "
        ]:

            clean_hostname = (
                clean_hostname.replace(
                    char,
                    ""
                )
            )

        if (
            "master"
            in clean_hostname.lower()
        ):

            clean_hostname = (
                clean_hostname.lower()
                .replace(
                    "{master}",
                    ""
                )
                .strip()
            )

        if (
            not clean_hostname
            or is_waiting_more
        ):

            clean_hostname = "Router"

        # =================================================
        # Build prompt
        # =================================================

        if is_waiting_more:

            custom_prompt = (
                "<span style='color: "
                "#00ffaa; "
                "background: #222; "
                "padding: 2px 5px; "
                "font-weight: bold;'>"
                "-- More "
                "(Space: Page, Enter: Line, "
                "Any Key: Exit) --"
                "</span>"
            )

        else:

            if vendor == "Juniper":

                custom_prompt = (
                    "{master}<br>"
                    "<span style='color: "
                    "#00ffaa;'>"
                    f"{username}@"
                    f"{clean_hostname}"
                    "</span>&gt; "
                )

            elif vendor == "Huawei":

                custom_prompt = (
                    "&lt;"
                    "<span style='color: "
                    "#00ffaa;'>"
                    f"{clean_hostname}"
                    "</span>&gt; "
                )

            elif vendor == "Forti":

                custom_prompt = (
                    "<span style='color: "
                    "#00ffaa;'>"
                    f"{clean_hostname}"
                    "</span> $ "
                )

            else:

                custom_prompt = (
                    "<span style='color: "
                    "#00ffaa;'>"
                    f"{clean_hostname}"
                    "</span># "
                )

        return jsonify(
            {
                "output":
                    f"{main_body}"
                    f"<br>"
                    f"{custom_prompt}",

                "is_more":
                    is_waiting_more
            }
        )

    except Exception as e:

        return jsonify(
            {
                "output":
                    "\n"
                    "<span style='color:#ff4444;'>"
                    "[Session Tunnel Error: "
                    f"{str(e)}"
                    "]"
                    "</span>\n"
            }
        )


# =====================================================
# Start Flask
# =====================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )