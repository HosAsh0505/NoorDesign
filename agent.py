import os
import time
import uuid
import socket
import threading
import requests
import paramiko

# ============================================================
# CONFIG
# ============================================================

SERVER_URL = os.getenv(
    "NOOR_SERVER_URL",
    "https://upgraded-adventure-6v5ww9rqj5wqcx4jj-5000.app.github.dev/login"
).rstrip("/")

AGENT_TOKEN = os.getenv(
    "NOOR_AGENT_TOKEN",
    "CHANGE_THIS_AGENT_TOKEN"
)

AGENT_ID = os.getenv(
    "NOOR_AGENT_ID",
    socket.gethostname()
)

POLL_INTERVAL = 2

# Internal target
FIREWALL_IP = "10.9.9.111"
SSH_PORT = 22


# ============================================================
# STATE
# ============================================================

running = True

jobs = {}
jobs_lock = threading.Lock()


# ============================================================
# HTTP HELPERS
# ============================================================

def headers():
    return {
        "Authorization": f"Bearer {AGENT_TOKEN}",
        "Content-Type": "application/json"
    }


def register_agent():
    """
    Register this agent with the public Flask server.
    """

    payload = {
        "agent_id": AGENT_ID,
        "hostname": socket.gethostname()
    }

    try:
        response = requests.post(
            f"{SERVER_URL}/agent/register",
            json=payload,
            headers=headers(),
            timeout=15
        )

        print(
            f"[REGISTER] HTTP {response.status_code}: "
            f"{response.text}"
        )

        return response.ok

    except Exception as e:
        print(f"[REGISTER ERROR] {e}")
        return False


def poll_job():
    """
    Ask the public server whether there is a job for this agent.
    """

    try:
        response = requests.get(
            f"{SERVER_URL}/agent/poll",
            params={
                "agent_id": AGENT_ID
            },
            headers=headers(),
            timeout=30
        )

        if response.status_code != 200:
            print(
                f"[POLL] HTTP {response.status_code}: "
                f"{response.text}"
            )
            return None

        data = response.json()

        return data

    except requests.exceptions.Timeout:
        return None

    except Exception as e:
        print(f"[POLL ERROR] {e}")
        return None


def send_result(job_id, success, result=None, error=None):
    """
    Send job result back to the public Flask server.
    """

    payload = {
        "agent_id": AGENT_ID,
        "job_id": job_id,
        "success": success,
        "result": result,
        "error": error
    }

    try:
        response = requests.post(
            f"{SERVER_URL}/agent/result",
            json=payload,
            headers=headers(),
            timeout=15
        )

        print(
            f"[RESULT] job={job_id} "
            f"HTTP={response.status_code}"
        )

        return response.ok

    except Exception as e:
        print(f"[RESULT ERROR] {e}")
        return False


# ============================================================
# NETWORK FUNCTIONS
# ============================================================

def check_tcp_connection(
    host,
    port=22,
    timeout=5
):
    """
    Basic TCP test.

    IMPORTANT:
    This executes on the LOCAL machine where FortiClient
    is running.

    Therefore the route to 10.9.9.111 comes from the
    local machine's routing table / FortiClient VPN.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        return {
            "reachable": True,
            "host": host,
            "port": port
        }

    except Exception as e:

        return {
            "reachable": False,
            "host": host,
            "port": port,
            "error": str(e)
        }

    finally:
        sock.close()


def ssh_test(
    host,
    username,
    password,
    port=22,
    timeout=10
):
    """
    Test SSH connection to the internal firewall/jump host.

    This function runs on the LOCAL machine.
    """

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:

        print(
            f"[SSH] Connecting to "
            f"{host}:{port}"
        )

        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False
        )

        transport = client.get_transport()

        connected = (
            transport is not None
            and transport.is_active()
        )

        if not connected:
            return {
                "success": False,
                "error": "SSH transport is not active"
            }

        return {
            "success": True,
            "host": host,
            "port": port,
            "message": "SSH connection successful"
        }

    except paramiko.AuthenticationException:

        return {
            "success": False,
            "error": "SSH authentication failed"
        }

    except paramiko.SSHException as e:

        return {
            "success": False,
            "error": f"SSH error: {str(e)}"
        }

    except socket.timeout:

        return {
            "success": False,
            "error": "Connection timeout"
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }

    finally:

        try:
            client.close()
        except Exception:
            pass


# ============================================================
# JOB HANDLERS
# ============================================================

def handle_test_connection(job):
    """
    Job:
        test_connection

    Only checks TCP reachability.
    """

    host = job.get(
        "target",
        FIREWALL_IP
    )

    port = job.get(
        "port",
        SSH_PORT
    )

    return check_tcp_connection(
        host,
        port
    )


def handle_test_ssh(job):
    """
    Job:
        test_ssh

    Tests SSH from the Local Agent to 10.9.9.111.
    """

    host = job.get(
        "target",
        FIREWALL_IP
    )

    username = job.get("username")
    password = job.get("password")

    if not username:
        raise ValueError(
            "SSH username is missing"
        )

    if not password:
        raise ValueError(
            "SSH password is missing"
        )

    return ssh_test(
        host=host,
        username=username,
        password=password
    )


def handle_execute_ssh_command(job):
    """
    Generic SSH command execution.

    This will later replace the SSH command execution
    currently living inside app.py.
    """

    host = job.get(
        "target",
        FIREWALL_IP
    )

    username = job.get("username")
    password = job.get("password")
    command = job.get("command")

    if not username:
        raise ValueError(
            "SSH username is missing"
        )

    if not password:
        raise ValueError(
            "SSH password is missing"
        )

    if not command:
        raise ValueError(
            "Command is missing"
        )

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:

        client.connect(
            hostname=host,
            port=SSH_PORT,
            username=username,
            password=password,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            look_for_keys=False,
            allow_agent=False
        )

        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=30
        )

        output = stdout.read().decode(
            "utf-8",
            errors="replace"
        )

        error = stderr.read().decode(
            "utf-8",
            errors="replace"
        )

        return {
            "success": True,
            "stdout": output,
            "stderr": error
        }

    finally:

        try:
            client.close()
        except Exception:
            pass


# ============================================================
# JOB DISPATCHER
# ============================================================

def execute_job(job):
    """
    Decide which local network operation should be executed.
    """

    job_type = job.get("type")

    print(
        f"[JOB] "
        f"id={job.get('job_id')} "
        f"type={job_type}"
    )

    if job_type == "test_connection":

        return handle_test_connection(job)

    elif job_type == "test_ssh":

        return handle_test_ssh(job)

    elif job_type == "execute_ssh_command":

        return handle_execute_ssh_command(job)

    else:

        raise ValueError(
            f"Unknown job type: {job_type}"
        )


# ============================================================
# MAIN AGENT LOOP
# ============================================================

def agent_loop():

    print("=" * 60)
    print("NOOR NETWORK AGENT")
    print("=" * 60)

    print(f"Agent ID : {AGENT_ID}")
    print(f"Hostname : {socket.gethostname()}")
    print(f"Server   : {SERVER_URL}")
    print(f"Target   : {FIREWALL_IP}")
    print("=" * 60)

    while running:

        # ----------------------------------------------------
        # Register
        # ----------------------------------------------------

        registered = register_agent()

        if not registered:

            print(
                "[AGENT] Server unavailable. "
                "Retrying..."
            )

            time.sleep(5)

            continue

        print(
            "[AGENT] Registered successfully."
        )

        # ----------------------------------------------------
        # Poll jobs
        # ----------------------------------------------------

        while running:

            try:

                data = poll_job()

                if not data:
                    time.sleep(POLL_INTERVAL)
                    continue

                job = data.get("job")

                if not job:
                    time.sleep(POLL_INTERVAL)
                    continue

                job_id = job.get(
                    "job_id",
                    str(uuid.uuid4())
                )

                try:

                    result = execute_job(job)

                    send_result(
                        job_id=job_id,
                        success=True,
                        result=result
                    )

                except Exception as e:

                    print(
                        f"[JOB ERROR] {e}"
                    )

                    send_result(
                        job_id=job_id,
                        success=False,
                        error=str(e)
                    )

                time.sleep(0.2)

            except Exception as e:

                print(
                    f"[AGENT LOOP ERROR] {e}"
                )

                break

        time.sleep(3)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        agent_loop()

    except KeyboardInterrupt:

        print(
            "\n[AGENT] Stopped by user."
        )

    except Exception as e:

        print(
            f"[AGENT FATAL] {e}"
        )
