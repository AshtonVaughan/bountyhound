"""
BountyHound VPS Manager — Vultr lifecycle management for clean-IP recon offloading.

Usage (CLI):
    python vultr.py start [--region syd] [--plan vc2-1c-2gb] [--state /path/vps-state.json]
    python vultr.py status [--state /path/vps-state.json]
    python vultr.py run "amass enum -d example.com" [--state /path/vps-state.json]
    python vultr.py upload /local/file /remote/path [--state /path/vps-state.json]
    python vultr.py download /remote/file /local/path [--state /path/vps-state.json]
    python vultr.py interactsh [--state /path/vps-state.json]
    python vultr.py destroy [--state /path/vps-state.json]
    python vultr.py list                                      # list all active BountyHound VPS instances
    python vultr.py os                                        # list available OS images
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Configuration — API key loaded from env, falls back to hardcoded default
# ---------------------------------------------------------------------------

VULTR_API_KEY = os.environ.get(
    'VULTR_API_KEY',
    'JJ6EVA3D2TKYUB35EFGYVSIBMICNLWWJF6AA'
)

API_BASE = 'https://api.vultr.com/v2'

# Default instance spec — 1 vCPU / 2GB RAM / 55GB SSD / 2TB bandwidth
# $0.017/hr (~$0.10 per 6-hour hunt). Destroy when done.
DEFAULT_PLAN = 'vc2-1c-2gb'
DEFAULT_REGION = 'syd'            # Sydney — lowest latency from AU
SSH_KEY_NAME = 'bountyhound'
SSH_KEY_PATH = Path.home() / '.ssh' / 'bountyhound_vps'

# ---------------------------------------------------------------------------
# Provisioning script — runs once after first boot
# ---------------------------------------------------------------------------

TOOLKIT_SETUP = r'''#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
export PATH=$PATH:/usr/local/go/bin:/root/go/bin

echo "[1/6] System update"
apt-get update -qq
apt-get install -y -qq curl wget unzip git python3 python3-pip nmap masscan \
    screen tmux jq libpcap-dev 2>/dev/null

echo "[2/6] Install Go 1.22"
if ! command -v go &>/dev/null; then
    wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /root/.bashrc
fi

echo "[3/6] Install Go-based recon tools"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | tail -3
go install -v github.com/ffuf/ffuf/v2@latest 2>&1 | tail -3
go install -v github.com/OJ/gobuster/v3@latest 2>&1 | tail -3
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>&1 | tail -3
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>&1 | tail -3
go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>&1 | tail -3
go install -v github.com/tomnomnom/waybackurls@latest 2>&1 | tail -3
go install -v github.com/tomnomnom/anew@latest 2>&1 | tail -3

echo "[4/6] Install amass"
go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest 2>&1 | tail -3

echo "[5/6] Install OOB / callback tools"
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>&1 | tail -3
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest 2>&1 | tail -3

echo "[6/6] Install Python tools"
pip3 install -q sqlmap requests

# Copy binaries to /usr/local/bin for PATH availability
for bin in /root/go/bin/*; do
    ln -sf "$bin" /usr/local/bin/$(basename "$bin") 2>/dev/null || true
done

# Update nuclei templates
nuclei -update-templates -silent 2>/dev/null || true

# Create working directory
mkdir -p /bh/findings /bh/wordlists /bh/tmp

# Download common wordlist for ffuf/gobuster
echo "Downloading wordlists..."
curl -s -o /bh/wordlists/directory-list-2.3-medium.txt \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt" \
  && echo "  directory-list-2.3-medium.txt done" || echo "  wordlist download failed (non-fatal)"
curl -s -o /bh/wordlists/api-endpoints.txt \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" \
  && echo "  api-endpoints.txt done" || true

echo "TOOLKIT_READY"
'''


class VultrVPS:
    """Manages a single Vultr VPS instance for BountyHound recon offloading."""

    def __init__(self, api_key: str = VULTR_API_KEY):
        self.api_key = api_key
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        }
        self.instance_id: Optional[str] = None
        self.ip: Optional[str] = None

    # ------------------------------------------------------------------
    # Internal API helpers
    # ------------------------------------------------------------------

    def _api(self, method: str, endpoint: str, **kwargs) -> dict:
        r = requests.request(
            method, f'{API_BASE}{endpoint}',
            headers=self.headers, timeout=30, **kwargs
        )
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        return r.json() if r.content else {}

    # ------------------------------------------------------------------
    # SSH key management
    # ------------------------------------------------------------------

    def _ensure_ssh_key(self) -> str:
        """Ensure ~/.ssh/bountyhound_vps keypair exists and is registered with Vultr.
        Returns the Vultr SSH key ID."""
        if not SSH_KEY_PATH.exists():
            SSH_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run([
                'ssh-keygen', '-t', 'ed25519',
                '-f', str(SSH_KEY_PATH),
                '-N', '', '-C', 'bountyhound-vps'
            ], check=True, capture_output=True)
            print(f'Generated SSH key: {SSH_KEY_PATH}')

        pub_key = SSH_KEY_PATH.with_suffix('.pub').read_text().strip()

        # Check if already registered
        existing = self._api('GET', '/ssh-keys').get('ssh_keys', [])
        for k in existing:
            if k.get('name') == SSH_KEY_NAME:
                return k['id']

        # Register the public key
        result = self._api('POST', '/ssh-keys', json={
            'name': SSH_KEY_NAME,
            'ssh_key': pub_key,
        })
        key_id = result['ssh_key']['id']
        print(f'Registered SSH key with Vultr: {key_id}')
        return key_id

    def _get_os_id(self, name: str = 'Ubuntu 22.04') -> int:
        """Look up Vultr OS ID by name fragment."""
        oses = self._api('GET', '/os').get('os', [])
        for os_entry in oses:
            if name.lower() in os_entry.get('name', '').lower() and 'x64' in os_entry.get('name', ''):
                return os_entry['id']
        # Fallback: Ubuntu 22.04 x64 is typically 1743
        print(f'Warning: OS "{name}" not found via API, using default ID 1743')
        return 1743

    # ------------------------------------------------------------------
    # SSH command helpers
    # ------------------------------------------------------------------

    def _ssh_cmd(self) -> list:
        return [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=30',
            '-i', str(SSH_KEY_PATH),
            f'root@{self.ip}',
        ]

    def _ssh_ready(self) -> bool:
        result = subprocess.run(
            self._ssh_cmd() + ['echo ok'],
            capture_output=True, timeout=15
        )
        return result.returncode == 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, region: str = DEFAULT_REGION, plan: str = DEFAULT_PLAN,
              provision: bool = True) -> str:
        """Spin up a fresh VPS, wait until ready, provision toolkit. Returns IP."""
        ssh_key_id = self._ensure_ssh_key()
        os_id = self._get_os_id()

        print(f'Creating VPS [{plan}] in [{region}]...')
        result = self._api('POST', '/instances', json={
            'region': region,
            'plan': plan,
            'os_id': os_id,
            'label': f'bountyhound-{int(time.time())}',
            'sshkey_id': [ssh_key_id],
            'backups': 'disabled',
            'ddos_protection': False,
            'activation_email': False,
        })
        self.instance_id = result['instance']['id']
        print(f'Instance created: {self.instance_id}')

        ip = self._wait_ready()
        if provision:
            self.provision()
        return ip

    def _wait_ready(self, timeout: int = 300) -> str:
        """Poll until instance is active and SSH is accepting connections."""
        print('Waiting for instance to boot...', end='', flush=True)
        start = time.time()
        while time.time() - start < timeout:
            data = self._api('GET', f'/instances/{self.instance_id}')
            inst = data.get('instance', {})
            status = inst.get('status')
            power = inst.get('power_status')

            if status == 'active' and power == 'running':
                self.ip = inst['main_ip']
                print(f' IP: {self.ip}')
                print('Waiting for SSH...', end='', flush=True)
                for _ in range(30):
                    if self._ssh_ready():
                        print(' ready.')
                        return self.ip
                    print('.', end='', flush=True)
                    time.sleep(5)
            else:
                print('.', end='', flush=True)
            time.sleep(10)

        raise TimeoutError(f'VPS not ready after {timeout}s')

    def provision(self) -> None:
        """Install the full bug bounty toolkit on the VPS."""
        print('Provisioning toolkit (this takes ~5 minutes)...')
        # Upload setup script
        result = subprocess.run(
            self._ssh_cmd() + [f'cat > /tmp/bh-setup.sh'],
            input=TOOLKIT_SETUP.encode(),
            capture_output=False,
        )
        # Run it
        subprocess.run(
            self._ssh_cmd() + ['bash /tmp/bh-setup.sh'],
            check=True
        )
        print('Toolkit provisioned.')

    def destroy(self) -> None:
        """Terminate and delete the VPS instance."""
        if not self.instance_id:
            print('No instance to destroy.')
            return
        self._api('DELETE', f'/instances/{self.instance_id}')
        print(f'VPS {self.instance_id} ({self.ip}) destroyed.')
        self.instance_id = None
        self.ip = None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, cmd: str, capture: bool = False) -> str:
        """Execute a shell command on the VPS. Streams output by default."""
        if capture:
            result = subprocess.run(
                self._ssh_cmd() + [cmd],
                capture_output=True, text=True
            )
            return result.stdout
        else:
            subprocess.run(self._ssh_cmd() + [cmd])
            return ''

    def run_background(self, cmd: str, session_name: str) -> None:
        """Run command in a named tmux session (survives disconnect)."""
        self.run(f'tmux new-session -d -s {session_name} "{cmd}" || true')
        print(f'Running in tmux session [{session_name}] — use: vps attach {session_name}')

    def run_stream_to_file(self, cmd: str, remote_out: str, local_out: str) -> None:
        """Run command on VPS, stream output to a local file."""
        Path(local_out).parent.mkdir(parents=True, exist_ok=True)
        ssh_cmd = self._ssh_cmd() + [cmd]
        with open(local_out, 'w') as f:
            proc = subprocess.Popen(ssh_cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
            proc.wait()
        print(f'Output saved to {local_out}')

    def upload(self, local_path: str, remote_path: str) -> None:
        """Upload a file to the VPS."""
        subprocess.run([
            'scp', '-o', 'StrictHostKeyChecking=no',
            '-i', str(SSH_KEY_PATH),
            local_path, f'root@{self.ip}:{remote_path}',
        ], check=True)
        print(f'Uploaded {local_path} → {remote_path}')

    def download(self, remote_path: str, local_path: str) -> None:
        """Download a file from the VPS."""
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            'scp', '-o', 'StrictHostKeyChecking=no',
            '-i', str(SSH_KEY_PATH),
            f'root@{self.ip}:{remote_path}', local_path,
        ], check=True)
        print(f'Downloaded {remote_path} → {local_path}')

    def start_interactsh(self) -> str:
        """Start interactsh-client in a persistent tmux session. Returns the OOB callback domain."""
        stdout_file = '/bh/tmp/interactsh-stdout.txt'
        interactions_file = '/bh/tmp/interactsh-log.txt'
        session = 'interactsh'

        # Kill any stale session and clear old logs
        self.run(f'tmux kill-session -t {session} 2>/dev/null || true')
        self.run(f'rm -f {stdout_file} {interactions_file}')

        # Launch interactsh-client in a background tmux session
        # -o writes each interaction as JSON; stdout shows the assigned domain
        self.run(
            f'tmux new-session -d -s {session} '
            f'"interactsh-client -server https://interactsh.com '
            f'-o {interactions_file} -v 2>&1 | tee {stdout_file}"'
        )

        # Poll stdout for the domain line (up to 20s)
        for _ in range(20):
            time.sleep(1)
            stdout = self.run(f'cat {stdout_file} 2>/dev/null || echo ""', capture=True)
            for line in stdout.splitlines():
                # interactsh prints: "INF Listening on <domain>"
                if '.oast.' in line or '.interact.sh' in line:
                    for part in line.strip().split():
                        if '.oast.' in part or '.interact.sh' in part:
                            print(f'OOB domain: {part}')
                            return part

        print('Warning: could not extract OOB domain after 20s.')
        print('Check manually: python vultr.py run "cat /bh/tmp/interactsh-stdout.txt"')
        return ''

    def poll_interactsh(self) -> list:
        """Return any interactions received by the OOB client (reads from log file)."""
        output = self.run(
            'cat /bh/tmp/interactsh-log.txt 2>/dev/null || echo "none"',
            capture=True
        )
        lines = [l for l in output.strip().splitlines() if l]
        return lines if lines else ['none']

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def save_state(self, path: str) -> None:
        """Write instance state to JSON so we can reconnect across sessions."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({
            'instance_id': self.instance_id,
            'ip': self.ip,
        }, indent=2))
        print(f'VPS state saved to {path}')

    def load_state(self, path: str) -> bool:
        """Reconnect to an existing instance. Returns True if still alive."""
        p = Path(path)
        if not p.exists():
            return False
        state = json.loads(p.read_text())
        self.instance_id = state.get('instance_id')
        self.ip = state.get('ip')
        if not self.instance_id:
            return False
        try:
            data = self._api('GET', f'/instances/{self.instance_id}')
            inst = data.get('instance', {})
            alive = inst.get('status') == 'active'
            if alive:
                print(f'Reconnected to VPS {self.instance_id} ({self.ip})')
            else:
                print(f'VPS {self.instance_id} is no longer active (status: {inst.get("status")})')
            return alive
        except Exception as e:
            print(f'Could not verify VPS state: {e}')
            return False

    def status(self) -> dict:
        """Return current instance status dict."""
        if not self.instance_id:
            return {'status': 'no instance'}
        data = self._api('GET', f'/instances/{self.instance_id}')
        return data.get('instance', {})

    # ------------------------------------------------------------------
    # Account-level helpers
    # ------------------------------------------------------------------

    def list_instances(self) -> list:
        """List all BountyHound VPS instances (those with 'bountyhound' label)."""
        data = self._api('GET', '/instances')
        instances = data.get('instances', [])
        return [i for i in instances if 'bountyhound' in i.get('label', '')]

    def list_os(self) -> list:
        """List available OS images."""
        return self._api('GET', '/os').get('os', [])


# ---------------------------------------------------------------------------
# CLI interface — called directly by the hunt skill
# ---------------------------------------------------------------------------

def _load_vps(state_path: str) -> VultrVPS:
    vps = VultrVPS()
    if not vps.load_state(state_path):
        print(f'Error: no active VPS state at {state_path}')
        print('Run: python vultr.py start --state <path>')
        sys.exit(1)
    return vps


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description='BountyHound VPS manager')
    parser.add_argument('command', choices=[
        'start', 'status', 'run', 'upload', 'download',
        'interactsh', 'poll', 'destroy', 'list', 'os',
        'bg', 'attach',
    ])
    parser.add_argument('args', nargs='*', help='Command arguments')
    parser.add_argument('--region', default=DEFAULT_REGION)
    parser.add_argument('--plan', default=DEFAULT_PLAN)
    parser.add_argument('--state', default='vps-state.json',
                        help='Path to state file for reconnection')
    parser.add_argument('--no-provision', action='store_true',
                        help='Skip toolkit installation on start')
    args = parser.parse_args()

    if args.command == 'start':
        vps = VultrVPS()
        ip = vps.start(
            region=args.region,
            plan=args.plan,
            provision=not args.no_provision,
        )
        vps.save_state(args.state)
        print(f'\nVPS ready: {ip}')
        print(f'State: {args.state}')
        print(f'SSH:   ssh -i ~/.ssh/bountyhound_vps root@{ip}')

    elif args.command == 'status':
        vps = _load_vps(args.state)
        inst = vps.status()
        print(json.dumps({
            'id': inst.get('id'),
            'ip': inst.get('main_ip'),
            'status': inst.get('status'),
            'power': inst.get('power_status'),
            'region': inst.get('region'),
            'plan': inst.get('plan'),
        }, indent=2))

    elif args.command == 'run':
        vps = _load_vps(args.state)
        cmd = ' '.join(args.args) if args.args else sys.stdin.read().strip()
        vps.run(cmd)

    elif args.command == 'bg':
        vps = _load_vps(args.state)
        if len(args.args) < 2:
            print('Usage: vultr.py bg <session-name> <command...>')
            sys.exit(1)
        session = args.args[0]
        cmd = ' '.join(args.args[1:])
        vps.run_background(cmd, session)

    elif args.command == 'attach':
        vps = _load_vps(args.state)
        session = args.args[0] if args.args else 'main'
        subprocess.run(
            vps._ssh_cmd() + [f'tmux attach -t {session}']
        )

    elif args.command == 'upload':
        vps = _load_vps(args.state)
        if len(args.args) < 2:
            print('Usage: vultr.py upload <local> <remote>')
            sys.exit(1)
        vps.upload(args.args[0], args.args[1])

    elif args.command == 'download':
        vps = _load_vps(args.state)
        if len(args.args) < 2:
            print('Usage: vultr.py download <remote> <local>')
            sys.exit(1)
        vps.download(args.args[0], args.args[1])

    elif args.command == 'interactsh':
        vps = _load_vps(args.state)
        domain = vps.start_interactsh()
        if domain:
            print(f'\nOOB domain: {domain}')
            print('Use this in payloads for blind SSRF, blind XSS, blind XXE, DNS pingback')
            print(f'Poll interactions: python vultr.py poll --state {args.state}')

    elif args.command == 'poll':
        vps = _load_vps(args.state)
        interactions = vps.poll_interactsh()
        if interactions == ['none']:
            print('No interactions yet')
        else:
            for line in interactions:
                print(line)

    elif args.command == 'destroy':
        vps = _load_vps(args.state)
        vps.destroy()
        Path(args.state).unlink(missing_ok=True)

    elif args.command == 'list':
        vps = VultrVPS()
        instances = vps.list_instances()
        if not instances:
            print('No active BountyHound VPS instances')
        for inst in instances:
            print(f"{inst['id']}  {inst['main_ip']}  {inst['status']}  {inst['label']}")

    elif args.command == 'os':
        vps = VultrVPS()
        for os_entry in vps.list_os():
            if 'ubuntu' in os_entry.get('name', '').lower():
                print(f"{os_entry['id']:6d}  {os_entry['name']}")


if __name__ == '__main__':
    main()
