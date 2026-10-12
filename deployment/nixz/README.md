# NixZ private DNS + SNI, node1

**Status on 2026-10-12: deployed and locally verified; external encrypted DNS and device acceptance pending.**
The user executed reviewed scripts on the VPS through their Windows SSH key. Work has no direct VPS shell. Current TLS release is `/opt/nixz/releases/20261012T132120Z-13122`; both containers are healthy and the apply script passed its local DoH, DoT, UDP DNS and SNI checks before activation. External Windows SNI tests passed for the three trial domains; HTTP 403 establishes transport, not iPhone application acceptance.
The user registered `labgeo.net`. Authoritative DNS and independent public resolvers confirmed `dns1.labgeo.net` A to node1 and the domain-control TXT, with no AAAA. The Let's Encrypt certificate has the correct SAN, a trusted VPS chain and expiry 2027-01-10. UFW permits TCP 443/853 only from the locally configured client; fresh key-based SSH and external TCP 853 were confirmed. Certificate renewal and full external DoH/DoT probes remain to be verified. NextDNS, DnsConf and production hosts are unchanged. Keep PR #1 draft and unmerged until acceptance is complete.

## Architecture

* Nginx stream binds TCP 443. Exact SNI names map to **validated, pinned public IPv4 addresses**. Unknown/missing SNI reaches a loopback reject listener. No wildcard routes or runtime name resolution.
* Own DNS hostname maps to dnsdist TLS DoH at `127.0.0.1:8443`; TCP 853 maps to TLS DoT at `127.0.0.1:8853`.
* dnsdist runs as UID 65532, no capabilities; local DNS is `127.0.0.1:5300`, never public 53. Both TLS listeners also bind only loopback. No admin API or console is enabled.
* Nginx master has exactly `NET_BIND_SERVICE`, `SETUID`, `SETGID` to bind low ports and drop workers to the image's `nginx` user. Workers run unprivileged; immutable filesystem, no Docker socket, separate PID namespace. Docker host networking avoids published-port DNAT bypassing UFW. It deliberately shares the host network namespace; SSRF prevention therefore matters.
* Nginx checks source IP for **both DoH and DoT** before forwarding. Public client /32 or /128 entries live only in `/etc/nixz/node.json`; UFW independently restricts ingress. A browser's `X-Forwarded-For` has no effect. dnsdist sees loopback, so aggregate QPS limits apply.
* Upstreams: independent Cloudflare and Quad9 over authenticated DoT. NextDNS is never contacted.
* No IPv6 binding or synthesized AAAA until `ipv6_verified=true`. The published IPv6 from the VPS is stored as an inventory value, not as proof of reachability.
* Own route TTL 60 s; cache 10,000 entries, maximum TTL 300 s, no stale response serving. No DNS query-body logging. SNI logs contain timestamp, source IP, SNI, destination, status and duration only.

Android native Private DNS cannot carry a token or arbitrary login. For a private service without a VPN the compatible v1 protection is an IP ACL. On cellular or changing home IP, update the local ACL and remove old firewall entries. CGNAT shares a public IP with other subscribers: any subscriber using the same allowed address can reach this service, though SNI remains restricted. Do not open a carrier-wide network to solve mobility. This is a real tradeoff of the requested architecture.

## Source audit and engine choice

The upstream installer is **not used**: it deletes repository files, rewrites configs in place, issues certificates despite failed DNS checks, opens temporary iptables exceptions and downloads uncontrolled upstream lists. Original Compose publishes 53 and dnsdist uses universal ACLs. Original Nginx resolves permitted names dynamically and permits wildcard subdomains. It does not reject private DNS destinations. The original cache permits stale answers for an hour; its tag 2.0.5 and moving `nginx:alpine` are not used here.

dnsdist 2.0.10 and Nginx 1.30.5 are version pinned. Each applied release also records pulled RepoDigests for deterministic rollback. Route updates reuse the active image digests. To upgrade images deliberately, put reviewed pins in `/etc/nixz/images.env` and run dry-run/apply. Docker images are not silently upgraded by the host's security updater.

Blocky offers convenient ad blocking, per-client groups and YAML, but does not remove the need for the same secure SNI front end and access controls. It adds no material benefit to this minimal three-domain trial. No Blocky installation or fork changes are needed.

## 1. Windows SSH and server audit

Download `windows.ps1` from the reviewed PR commit. In PowerShell:

```powershell
Set-Location <folder-with-windows.ps1>
.\windows.ps1 -Commit <40-character-reviewed-commit-SHA> -Step Audit
```

The script uses your existing key `C:\Users\ITm\.ssh\node1_ed25519`. OpenSSH asks for its passphrase locally; Work and GitHub receive neither key nor passphrase. Strict host-key verification stays enabled. If the host-key check fails, compare the fingerprint in your provider console; do not bypass the warning.

**Recovery gate:** sign in to IT Garage yourself and test an actual usable serial/VNC console, including an administrative shell. A visible console button is insufficient: password SSH being disabled does not establish a usable console login. Keep one SSH session open and establish another after the previously executed SSH reload. If console access cannot be demonstrated, stop the firewall phase and resolve recovery first.

## 2. Prepare a reviewed commit

```powershell
.\windows.ps1 -Commit <SHA> -Step Prepare
```

This checks out a fixed commit under `/opt/nixz/repo` as root. Root owns code later used by timers. Do not give `admin` write access to that code or add admin/deploy users to the Docker group. If the directory already exists, inspect it; the wrapper does not overwrite it.

In an SSH session:

```bash
sudo nano /etc/nixz/node.json
```

Set `client_cidrs` to the actual public IP of each **personal** network, e.g. your home IPv4 followed by `/32`. This is not the VPS IP. Obtain it from your router/provider or a trusted IP-check page on that network. Keep hostname empty and `tls=false` while the domain is unresolved. `ipv6_verified` remains false. No empty ACL is deployable.

## 3. Host security and guarded firewall

```powershell
.\windows.ps1 -Commit <SHA> -Step Security -FreshSSHAndConsoleTested
```

Only use that switch after the fresh-login and console gate above. The script verifies effective SSH settings and does not rewrite SSH. It installs Ubuntu-maintained Docker/Compose, chrony, UFW, Fail2ban, security updates and diagnostics. It waits for NTP synchronization, disables automatic reboots, bounds journald, validates Fail2ban and audits ports. Existing active UFW is preserved and requires manual review rather than being reset.

For a newly enabled UFW it permits the observed SSH port first and schedules automatic `ufw disable` in 180 seconds, restoring the previous disabled state if access is lost. Immediately connect from another PowerShell window:

```powershell
ssh -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\node1_ed25519" admin@2.27.16.203
```

Only after successful login:

```bash
sudo systemctl stop nixz-firewall-rescue.timer
sudo ufw status verbose
sudo fail2ban-client status sshd
timedatectl
chronyc tracking
```

If the second connection fails, leave the timer alone; recover through the original SSH/console. Do not reboot to diagnose a firewall issue.

## 4. Deploy SNI now, before domain registration

```powershell
.\windows.ps1 -Commit <SHA> -Step DeploySNI
.\windows.ps1 -Commit <SHA> -Step Firewall -FreshSSHAndConsoleTested
.\windows.ps1 -Commit <SHA> -Step Verify
```

The dry-run resolves **only the three exact OpenAI names** through two independent public DoH resolvers, validates every returned address, rejects all our node IPs, tests their real TLS identity, generates a candidate and runs both containers' syntax checkers. Failed resolution or any unsafe address aborts the update. Neither upstream lists nor GeoHide hosts are imported.

Apply creates an immutable release, starts containers, verifies synthesized DNS, real SNI TLS and unknown-SNI rejection. On failure it restores the previous config/images or stops an unsuccessful first deployment. After local acceptance it advances `current` and `previous` symlinks. No external success is inferred.

With `tls=false`, public 443 SNI and local DNS work, but encrypted device DNS is not available. From your permitted Windows network test real TLS:

```powershell
curl.exe --noproxy "*" --resolve chatgpt.com:443:2.27.16.203 -o NUL -sS -w "%{http_code}" https://chatgpt.com/
curl.exe --noproxy "*" --resolve auth.openai.com:443:2.27.16.203 -o NUL -sS -w "%{http_code}" https://auth.openai.com/
curl.exe --noproxy "*" --resolve ios.chat.openai.com:443:2.27.16.203 -o NUL -sS -w "%{http_code}" https://ios.chat.openai.com/
```

Never add `-k`. A 403/404 establishes a TLS+HTTP response, not account availability or a working iPhone app. Check actual regional/service restrictions from this node; an IPv4 allocation alone does not prove a clean or accepted egress address.

## 5. Real domain and TLS

Register a domain you control, or use an existing owned domain. You do **not** need to buy `nixz-lab.net` specifically. Set a dedicated per-node hostname in `/etc/nixz/node.json`, keeping TLS false until issuance. Add DNS A to `2.27.16.203`; no CDN proxy in front of this record. Do not add AAAA yet.

```bash
cd /opt/nixz/repo/deployment/nixz
sudo bash certificate.sh
```

The script generates a random VPS-local TXT challenge `_nixz-owner.<actual-hostname>`. Add its displayed value to the DNS zone you control. After propagation:

```bash
sudo bash certificate.sh --issue
sudo nano /etc/nixz/node.json  # set tls to true
sudo bash deploy.sh --dry-run
sudo bash deploy.sh --apply
sudo bash firewall.sh --fresh-ssh-and-console-tested
sudo bash install-services.sh
sudo systemctl enable --now certbot.timer
sudo certbot renew --dry-run
```

Issuance requires both public resolvers to see the proof, correct A and absent/unambiguous AAAA, synchronized time and free TCP 80. Certbot's HTTP-01 validates control independently. TCP 80 is opened only for issuance/renewal and closed afterwards. Existing 80 rules must be audited before using these hooks. Renewed keys are copied into a new release with UID 65532 and mode 400. Never copy TLS keys into GitHub or your client devices.

## 6. External acceptance, then client files

On a **different allowed network**, use Linux/macOS or WSL with Python 3 and a curl build supporting HTTP/2. Fetch this same reviewed checkout and copy the active release's public configs/manifest (not certs) from the VPS:

```bash
# On the VPS, this archive contains public configs only, no TLS keys.
sudo tar -C /opt/nixz/current -czf /home/admin/nixz-public-release.tgz routes.json node.json manifest.json
sudo chown admin:admin /home/admin/nixz-public-release.tgz
# On the external host, scp that archive, extract into an empty directory, then:
python3 deployment/nixz/probe.py --release ./active-public-release --address 2.27.16.203 --external --out ./node1-external.json
python3 deployment/nixz/clients.py --release ./active-public-release --evidence ./node1-external.json --out ./node1-clients
```

`probe.py` checks real DoH/HTTP2, DoT and trust/hostname validation, every proxy A/AAAA, empty HTTPS/SVCB, block rules, normal recursive DNS, each SNI TLS+HTTP, unknown/no SNI rejection and public TCP/UDP 53 closure. Run TCP scans from an unlisted network too: 443/853 must not serve that client. UDP silence is supporting evidence; confirm binds and firewall on the server as well.

`clients.py` rejects local-only evidence, test certificates, mismatched release manifests and evidence older than a day. No fake `.mobileconfig` is included here. Profiles are generated **only after** this real acceptance.

Before relying on uptime, explicitly test container restart (with console recovery available), rerun local/external probes, and inspect automatic starts. A reboot should be a deliberate supervised test after stable networking, not an installation side effect.

### Native Windows external acceptance

Windows Python 3 can run the same probe without curl or additional packages. `--native-http` uses HTTPS with normal certificate/hostname validation and HTTP/1.1 for DoH; DoT and every positive/negative DNS/SNI check stay the same. The evidence records the HTTP client, so this does not claim an external HTTP/2 test. CI exercises both curl HTTP/2 and the native HTTP/1.1 paths.

On the VPS, package reviewed probe code and the active release's public metadata only:

```bash
sudo tar -czf /home/admin/nixz-external.tgz \
  -C /opt/nixz/repo/deployment/nixz probe.py nixz.py clients.py \
  -C /opt/nixz/current routes.json node.json manifest.json
sudo chown admin:admin /home/admin/nixz-external.tgz
sudo chmod 600 /home/admin/nixz-external.tgz
```

This archive includes the local client CIDRs and should remain private. It excludes certificates and private keys. From Windows PowerShell, use an empty extraction directory:

```powershell
$ProbeDir = Join-Path $env:USERPROFILE 'Downloads\NixZ\external-node1'
New-Item -ItemType Directory -Path $ProbeDir -ErrorAction Stop
scp -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\node1_ed25519" admin@2.27.16.203:/home/admin/nixz-external.tgz "$ProbeDir\nixz-external.tgz"
if ($LASTEXITCODE -ne 0) { throw 'SCP failed' }
tar.exe -xzf "$ProbeDir\nixz-external.tgz" -C $ProbeDir
if ($LASTEXITCODE -ne 0) { throw 'Extraction failed' }
Set-Location $ProbeDir
py .\probe.py --release . --address 2.27.16.203 --external --native-http --out .\node1-external.json
```

Only after the probe exits successfully, generate client files with `py .\clients.py --release . --evidence .\node1-external.json --out .\node1-clients`. Generating files is not authorization to install profiles or change device DNS. No network test run on the VPS qualifies as external Windows evidence.

## 7. Personal-device test

**Windows 11:** in the personal adapter's DNS settings use IPv4 `2.27.16.203`, manual DoH template `https://<actual-hostname>/dns-query`, **encrypted only**, no plaintext fallback. Use the real name from `node1-clients/connection.txt`. Only one node exists: do not add a public non-NixZ resolver as a pretend secondary, as it will bypass rewrites. Save original DNS settings before changing them.

```powershell
Get-DnsClientServerAddress
Get-DnsClientDohServerAddress
Clear-DnsClientCache
Resolve-DnsName chatgpt.com -Type A -DnsOnly
Resolve-DnsName chatgpt.com -Type AAAA -DnsOnly
Resolve-DnsName example.org -Type A -DnsOnly
```

Expected A for ChatGPT is this node IPv4, no AAAA until IPv6 enabled. `nslookup` sends ordinary DNS and will fail against this server's public port 53; it is not a DoH acceptance test. Inspect adapter DoH settings, use the external probe, and confirm encrypted connections with a packet trace if needed. Stop personal-device changes if Work is attached to a work-managed adapter; this task does not authorize modifying work-device DNS.

**iOS/iPadOS:** transfer the generated `NixZ-DNS.mobileconfig` privately, install through Settings > General > VPN & Device Management and select its DNS profile. The unsigned local configuration profile may show an unsigned-profile notice; it does not install a CA. TLS still uses public system trust. Keep the existing NextDNS profile available but select one DNS configuration at a time. Removing or deselecting the NixZ profile restores the previously selected/automatic DNS configuration; verify the selected NextDNS configuration explicitly.

Disable Windscribe and every other VPN. For this diagnostic also turn off Private Relay/Limit IP Address Tracking if it hides the permitted source or changes routing. Close/reopen ChatGPT; check login, send text, open a previous chat and view an attachment. Record time, network and error, then compare Safari vs the app. Repeat on cellular with its exact public IP authorized independently. Server success does not prove iOS success.

**macOS:** install the same profile through System Settings > Privacy & Security > Profiles (location may vary by OS). Select/remove profiles to switch to NextDNS. `scutil --dns` and `networksetup -getdnsservers Wi-Fi` help inspect state but may not alone expose encrypted DNS selection. Confirm with external probes and normal application resolution; `dig` directly queries ordinary DNS and does not exercise the OS DoH profile.

**Android:** Settings > Network & Internet > Private DNS > provider hostname = your **actual hostname only**, e.g. the value in `connection.txt`. No `https://`, `/dns-query` or `:853`. Use strict hostname mode; unavailable DoT then fails instead of silently falling back to ordinary DNS. OEM menu names vary. Save the old setting and test both Wi-Fi/cellular. No VPN application is needed.

## Routes, CI, updates and rollback

Edit `routes.json` in a feature branch and submit a PR. Exact domains only. The enabled group begins with `chatgpt.com`, `auth.openai.com`, `ios.chat.openai.com`; add more names only from actual failed SNI/DNS diagnostics. `exclude` is exact-match; `blocked` is exact NXDOMAIN. Static A/AAAA are in `records`. All outputs derive from this same config. Generated `hosts` uses our node IP, plus an independent AdGuard export. Exporting a hosts file is **not** permission to point DnsConf at it.

CI validates inputs, injection/private-IP/self-loop rejection, exclusions, IPv6 policy, shell syntax and real Docker integration with a disposable own DNS test certificate. It does not connect to the VPS. CI contains no deploy key or production secret and cannot alter NextDNS. Preserve upstream directories and pull upstream updates separately.

After review, CI success, PR merge and external acceptance:

```bash
cd /opt/nixz/repo/deployment/nixz
sudo bash routes-sync.sh --dry-run
sudo bash routes-sync.sh --apply
sudo systemctl enable --now nixz-routes.timer
sudo systemctl list-timers 'nixz-*'
sudo journalctl -u nixz-monitor.service -u nixz-routes.service --since today
```

This fetches only merged route **data** from master and refreshes public upstream IP pins every four hours. It never checks out or executes new remote code as root. Root-owned installed code/image pins update only through a reviewed fixed commit and manual SSH. Keep at most five releases, including previous; local preflight backups are protected. Add off-server encrypted backups through your own backup process. Do not prune shared Docker data or delete keys as an automatic cleanup operation.

```bash
sudo bash deploy.sh --rollback
sudo docker ps
sudo du -sh /opt/nixz/releases /var/lib/docker /var/log
df -h /
sudo bash backup.sh
```

Rollback restores config, cert copy and exact image digests and requires health to pass. It does not roll back package security patches or reset SSH/UFW. For changed CIDRs, add new UFW entries and deploy the ACL first, test new access, then remove old `nixz-clients` rules by their freshly inspected rule numbers. Stale UFW entries alone cannot override Nginx's current ACL.

`backup.sh` retains seven protected local archives of the active release, private settings and service definitions. Archives contain TLS keys and must be copied only to your own encrypted backup storage, never chat/GitHub. For recovery on the same node, audit UFW/SSH separately, restore the active release and `/etc/nixz`, then run the recorded Compose image digests and repeat probes. Preserve a trusted checkout of the reviewed commit. Local backups alone do not survive loss of the VPS.

## Verified CI result, 2026-10-12

The NixZ validate workflow passed seven route-security tests, ShellCheck, native Nginx/dnsdist syntax checks and real isolated Docker networking. DoH over HTTP/2, DoT, ordinary loopback DNS, normal recursion, A rewrites, AAAA/HTTPS/SVCB suppression, TLS passthrough to the three OpenAI names, unknown-SNI/no-SNI denial and rejection of source 127.0.0.2 all passed. Third-party peers negotiated TLS 1.3 and returned HTTP 403 from the GitHub runner. CI used a disposable self-signed certificate ONLY for its own DNS endpoint. Client generation correctly rejected that evidence. These results do not establish acceptance of VPS IP 2.27.16.203 or iPhone behavior.

**Optional push CD design, not activated:** use a separate `nixz-deploy` account, no Docker group and no ordinary shell forwarding. Authorized key must use `restrict,command="/usr/local/sbin/nixz-deploy-gateway"`, no PTY, agent/TCP forwarding or X11. A root-owned gateway should accept only a 40-character commit SHA, verify membership in the approved master history and CI success, enforce a deployment lock and invoke only the reviewed route-data updater. Restrict sudo to that gateway. Store its separate key and pinned host fingerprint in a protected GitHub environment, require manual production approval and serialize per-node deployments. This gateway/key/environment are an external access setup step; no broad deploy credential is created by these scripts. The server-pull route timer above already provides CI-to-merged-data-to-deploy without storing a VPS key in GitHub.

## Limitations and second node

* SNI passthrough cannot read ECH-hidden target names; HTTPS/SVCB suppression applies only to the exact rewritten domains. Cached or application-embedded ECH and independent DNS can still break routing. The three-domain trial may be insufficient for complete app login/attachments.
* TCP only: no HTTP/3 or QUIC proxy. UDP 443 stays blocked and most clients fall back to TCP; that behavior must be tested on the actual app. TLS is end-to-end for third-party sites. Only our own DNS TLS is terminated locally.
* SNI restrictions constrain destinations to selected public service IPs. They cannot inspect encrypted HTTP Host/content on a multi-tenant CDN or enforce application-account authorization. Pins can become stale; refresh fails closed and rolls back if peers cannot be verified.
* IP ACL mobility and CGNAT require care; without public unrestricted access or a VPN there is no universal transparent solution across arbitrary mobile source IPs with native Android DoT.
* One VPS is a single point of failure. Several hosts lines for a name are not failover.

For node2 choose another provider **and verify a different routed ASN**, a public IPv4 accepted by required services and separately controlled DNS hostname/cert. Add node2 to `nodes`, use a local `node2` configuration and run identical reviewed code on that server. Each DNS node rewrites to its own healthy local proxy; it rejects both nodes' IPs as SNI upstreams. Deploy sequentially, externally verify one before the other. Windows can register both encrypted DNS IP/templates; Apple needs a separately tested dual-node profile rather than assuming profile selection equals failover. Android accepts one Private DNS hostname, requiring a shared DNS name with a certificate valid on both nodes and tested multi-A/health-managed behavior, or explicit hostname switching. Hosts cannot implement this. Never promise seamless failover without device tests.

## Acceptance statuses

| Status | Evidence needed |
|---|---|
| PREPARED ONLY | PR and successful route/syntax/integration checks; no VPS operations |
| DEPLOYED & VERIFIED | effective SSH, NTP, UFW, binds, immutable releases, trusted external DoH/DoT/SNI and denied unlisted sources |
| DEPLOYED, CLIENT TEST PENDING | server acceptance complete, iPhone without VPN not yet confirmed |
| BLOCKED | no authorized VPS shell, missing domain control, missing real client ACLs, or console recovery not verified |

Never promote CI results or a single HTTP 403 to VPS/iPhone acceptance. Existing NextDNS profile `7437fe`, its 808 Rewrites, DnsConf ownership journal and production hosts must remain untouched.
