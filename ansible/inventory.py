#!/usr/bin/env python3
"""
Dynamic inventory: the dns Pis + pve over SSH, every running Proxmox CT via `pct exec` on pve
(community.proxmox.proxmox_pct_remote), so CTs need no SSH/user/key of their own.

Groups:
  containers  running CTs, minus the dns secondaries and this host
  dns         dns + dns.kids Pis and their CT secondaries (playbook upgrades these one at a time)
  pve         the hypervisor
  self_host   CT102 (this host) — the playbook only touches it with -e include_self=true
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))
from _openbao import fetch_secrets

if "--host" in sys.argv:
    print("{}")
    sys.exit()

LOCAL = fetch_secrets()["LOCAL"]
PVE = f"pve.{LOCAL}"
SELF_CT = "102"
DNS_CTS = {"110", "112"}  # dns-secondary, dns-kids-secondary

out = subprocess.run(["ssh", "-o", "BatchMode=yes", f"nat@{PVE}", "sudo", "/usr/sbin/pct", "list"],
                     capture_output=True, text=True, check=True).stdout
# columns: VMID Status [Lock] Name
running = {c[0]: c[-1] for c in (l.split() for l in out.splitlines()[1:]) if c[1] == "running"}

hostvars = {
    PVE: {"ansible_user": "nat"},
    **{f"dns.{LOCAL}": {"ansible_user": "nat", "ansible_become": True},
       f"dns.kids.{LOCAL}": {"ansible_user": "nat", "ansible_become": True}},
}
groups = {"containers": [], "dns": [f"dns.{LOCAL}", f"dns.kids.{LOCAL}"], "pve": [PVE], "self_host": []}
for vmid, name in running.items():
    host = f"ct{vmid}-{name}"
    hostvars[host] = {"ansible_connection": "community.proxmox.proxmox_pct_remote",
                      "ansible_host": PVE, "ansible_user": "nat", "proxmox_vmid": int(vmid)}
    groups["self_host" if vmid == SELF_CT else "dns" if vmid in DNS_CTS else "containers"].append(host)

print(json.dumps({**{g: {"hosts": h} for g, h in groups.items()}, "_meta": {"hostvars": hostvars}}, indent=2))
