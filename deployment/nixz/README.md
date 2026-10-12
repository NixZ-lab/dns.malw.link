# NixZ DNS + restricted SNI, node1

**2026-10-12: DEPLOYED & VERIFIED for the tested iPhone DoH + ChatGPT scenario on home Wi-Fi, LTE and Wi-Fi/LTE handoff, without VPN.** The user confirmed normal sites, sending a ChatGPT message, sending an image with a prompt and receiving successful results, then continued operation after returning to Wi-Fi. External VPS stream logs corroborate own DoH and the exact ChatGPT SNI paths from a new client network. Android ChatGPT also worked without VPN in the earlier authorized Wi-Fi DoT trial; Android LTE is not yet confirmed.

The user executed the real VPS commands through their own SSH/IT Garage console; Work has no direct VPS shell. Active public-mode release: `/opt/nixz/releases/20261012T192545Z-9558`; manifest `8da7bbc07406304f91764edc2f1501e878486eff7340a812d75c6e5a80f7c362`. VPS code commit `48e3749ebc81544a247821c10851585d0ac79473` passed CI including actual UFW parser dry-run and real Docker source/rate/header/rollback checks. Both containers are healthy with zero restarts. Local apply acceptance verified own DoH over HTTP/2, DoT/local DNS and trusted TLS1.3 passthrough for all four OpenAI names; HTTP403 alone is not application acceptance.

UFW now exposes only IPv4 TCP443/853 for public encrypted DNS/restricted SNI, and SSH TCP22 on IPv4/IPv6. Internal DNS/relay/reject ports bind loopback; no public53, UDP443 or IPv6 proxy listener. The actual traffic guard timer is active and its service succeeds. The last supplied RX+TX reading was13,550,511 of2,147,483,648bytes. No budget-triggered production shutdown, reboot/recovery or second-node failover test is claimed. Public access is abuse-limited, not cryptographically authenticated private access.

`dns1.labgeo.net` has the real A record and trusted Let's Encrypt certificate expiring2027-01-10. Simulated renewal succeeded and removed temporary TCP80 ingress; the production renewal-triggered deploy hook has not yet been observed. Monitoring and a protected local backup are installed. NextDNS, DnsConf and production hosts remain unchanged.

Keep PR #1 draft/unmerged: native Windows/macOS DNS settings, Android LTE, fresh-login coverage, final recovery/closure checks and route-automation acceptance remain incomplete. The1,018-domain supplied catalogue is inactive; active routes remain only the four accepted OpenAI names.

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

dnsdist 2.0.10 remains pinned. The public-mode candidate pins Nginx 1.31.6-alpine, whose stream module supports PROXYv2; currently deployed private releases retain their recorded older digest until an explicit tested upgrade. Each applied release also records pulled RepoDigests for deterministic rollback. Route updates reuse the active image digests. To upgrade images deliberately, put reviewed pins in `/etc/nixz/images.env` and run dry-run/apply. Docker images are not silently upgraded by the host's security updater.

Blocky offers convenient ad blocking, per-client groups and YAML, but does not remove the need for the same secure SNI front end and access controls. It adds no material benefit to this minimal four-domain trial. No Blocky installation or fork changes are needed.

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

The dry-run resolves **only the enabled exact OpenAI names** through two independent public DoH resolvers, validates every returned address, rejects all our node IPs, tests their real TLS identity, generates a candidate and runs both containers' syntax checkers. Failed resolution or any unsafe address aborts the update. Neither upstream lists nor GeoHide hosts are imported.

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

Windows Python 3 can run the same probe without curl after installing the pinned HTTPX/HTTP2 probe dependencies in a local virtual environment. `--native-http` connects to the explicit VPS IP, sends the DNS hostname in SNI and HTTP authority, uses the system trust store and requires an actual HTTP/2 response for DoH. DoT and every positive/negative DNS/SNI check stay the same. CI exercises both curl and Python HTTP/2 paths. The dnsdist DoH listener rejects HTTP/1.1 with status 505, so a standard-library-only HTTPS probe is insufficient.

On the VPS, package reviewed probe code and the active release's public metadata only:

```bash
sudo tar -czf /home/admin/nixz-external.tgz \
  -C /opt/nixz/repo/deployment/nixz probe.py nixz.py clients.py requirements-probe.txt \
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
py -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed' }
& .\.venv\Scripts\python.exe -m pip install -r .\requirements-probe.txt
if ($LASTEXITCODE -ne 0) { throw 'Probe dependencies failed to install' }
& .\.venv\Scripts\python.exe .\probe.py --release . --address 2.27.16.203 --external --native-http --out .\node1-external.json
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

Edit `routes.json` in a feature branch and submit a PR. Exact domains only. The enabled group begins with `chatgpt.com`, `auth.openai.com`, `ios.chat.openai.com`, `android.chat.openai.com`; add more names only from actual failed SNI/DNS diagnostics. `exclude` is exact-match; `blocked` is exact NXDOMAIN. Static A/AAAA are in `records`. All outputs derive from this same config. Generated `hosts` uses our node IP, plus an independent AdGuard export. Exporting a hosts file is **not** permission to point DnsConf at it.

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

The NixZ validate workflow passed nine route-security and certificate-input tests, ShellCheck, native Nginx/dnsdist syntax checks and real isolated Docker networking. DoH over HTTP/2, DoT, ordinary loopback DNS, normal recursion, A rewrites, AAAA/HTTPS/SVCB suppression, TLS passthrough to the four OpenAI names, unknown-SNI/no-SNI denial and rejection of source 127.0.0.2 all passed. Third-party peers negotiated TLS 1.3 and returned HTTP 403 from the GitHub runner. CI used a disposable self-signed certificate ONLY for its own DNS endpoint. Client generation correctly rejected that evidence. These results do not establish acceptance of VPS IP 2.27.16.203 or iPhone behavior.

**Optional push CD design, not activated:** use a separate `nixz-deploy` account, no Docker group and no ordinary shell forwarding. Authorized key must use `restrict,command="/usr/local/sbin/nixz-deploy-gateway"`, no PTY, agent/TCP forwarding or X11. A root-owned gateway should accept only a 40-character commit SHA, verify membership in the approved master history and CI success, enforce a deployment lock and invoke only the reviewed route-data updater. Restrict sudo to that gateway. Store its separate key and pinned host fingerprint in a protected GitHub environment, require manual production approval and serialize per-node deployments. This gateway/key/environment are an external access setup step; no broad deploy credential is created by these scripts. The server-pull route timer above already provides CI-to-merged-data-to-deploy without storing a VPS key in GitHub.

## Limitations and second node

* SNI passthrough cannot read ECH-hidden target names; HTTPS/SVCB suppression applies only to the exact rewritten domains. Cached or application-embedded ECH and independent DNS can still break routing. The four-domain trial may be insufficient for complete app login/attachments.
* TCP only: no HTTP/3 or QUIC proxy. UDP 443 stays blocked and most clients fall back to TCP; that behavior must be tested on the actual app. TLS is end-to-end for third-party sites. Only our own DNS TLS is terminated locally.
* SNI restrictions constrain destinations to selected public service IPs. They cannot inspect encrypted HTTP Host/content on a multi-tenant CDN or enforce application-account authorization. Pins can become stale; refresh fails closed and rolls back if peers cannot be verified.
* IP ACL mobility and CGNAT require care; without public unrestricted access or a VPN there is no universal transparent solution across arbitrary mobile source IPs with native Android DoT.
* One VPS is a single point of failure. Several hosts lines for a name are not failover.

For node2 choose another provider **and verify a different routed ASN**, a public IPv4 accepted by required services and separately controlled DNS hostname/cert. Add node2 to `nodes`, use a local `node2` configuration and run identical reviewed code on that server. Each DNS node rewrites to its own healthy local proxy; it rejects both nodes' IPs as SNI upstreams. Deploy sequentially, externally verify one before the other. Windows can register both encrypted DNS IP/templates; Apple needs a separately tested dual-node profile rather than assuming profile selection equals failover. Android accepts one Private DNS hostname, requiring a shared DNS name with a certificate valid on both nodes and tested multi-A/health-managed behavior, or explicit hostname switching. Hosts cannot implement this. Never promise seamless failover without device tests.

## Mobile access decision: prepared only, no public ingress change

Native Android Private DNS supplies a DoT provider hostname, not a user token or client certificate selector. The Apple profile uses native DoH; protecting only its DNS URL does not authenticate third-party SNI tunnels. Those HTTPS connections are end-to-end encrypted, so the proxy cannot insert/check a custom HTTP login without breaking passthrough.

Two materially different choices remain:

1. **Private, source-granted access (recommended security default).** Keep the current CIDR checks at both UFW and Nginx. A future authenticated HTTPS access page could grant the caller's observed public /32 for a short bounded lease. It must be reachable independently of a blocked NixZ resolver, require strong authentication, never accept a client-supplied target IP/command, atomically update a separate runtime ACL and expire leases. This page/helper is NOT implemented. A shortcut may simplify renewal but is not universally automatic on both platforms. Changes of network/IP need a new grant. CGNAT can give the same source IP to unrelated people; a web grant's egress may differ from DoT/proxy egress. Do not widen to a carrier ASN/range to hide that mismatch.
2. **Publicly reachable, abuse-limited encrypted DNS and exact SNI (separate user decision required).** This best fits unattended Wi-Fi/LTE changes but is not a private authenticated service. Anyone could use recursive DoH/DoT and the allowed service destinations. Rate/connection limits reduce cost; they do not authenticate clients or prevent every abuse. Shared CDNs mean an SNI allowlist is not an HTTP-content/account restriction. A leaked/special DNS hostname is not strong authentication.

Before implementing option 2:
- Preserve real client identity at the DNS rate limiter, or enforce verified per-client query limits at a DNS-aware edge. Current dnsdist sees loopback: QPSAction(200) is aggregate; Nginx's 32-connection/source limit alone cannot stop one HTTP/2 connection from issuing many DNS queries.
- Verify protocol compatibility, not just a config directive: pinned Nginx 1.30.5's standard stream PROXY output is v1, while dnsdist's documented mechanism is PROXYv2. Current upstream Nginx docs expose v2 only from 1.31.4. Do not turn on global proxy_protocol blindly: it would also corrupt third-party TLS streams. Any adapter/routing split must apply only to own DNS, retain localhost-only backend trust and pass forged-header/source tests.
- Bound per-source/global DNS queries, new TLS connections, concurrent tunnels, transfer rates, total memory/CPU/logs and provider traffic budget. Account for legitimate CGNAT sharing. Per-connection stream transfer limits are not a global bandwidth quota.
- Keep exact SNI/public pinned destinations, reject self/private/unknown destinations, keep public53/admin ports/UDP443 closed, and do not enable untested IPv6.
- Test overload isolation and spoofed source metadata, narrow-to-public-to-narrow rollback, external unknown-SNI rejection, and native Android/iPhone Wi-Fi-to-LTE behavior. Opening firewall/ACL is a deployment step only after the risk decision and these candidate checks.

Sources: [Android configuration](https://developers.google.com/speed/public-dns/docs/using), [dnsdist source forwarding](https://www.dnsdist.org/advanced/passing-source-address.html), [Nginx stream proxy directives](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html). Documentation describes candidates, not installed capabilities.

## Adding services without changing NextDNS

Only edit `deployment/nixz/routes.json` in the infrastructure feature branch. Add a named service group with exact hostnames and opt that group into `enabled_groups`. Do not copy a broad external hosts list, add wildcard routes, or put upstream CDN addresses into `records` as proxy destinations.

Example route-data fragment (the names are explanatory placeholders, NOT installed routes):

```json
"groups": {
  "openai-test": ["chatgpt.com", "auth.openai.com", "ios.chat.openai.com", "android.chat.openai.com"],
  "new-service": ["service.example", "auth.service.example"]
},
"enabled_groups": ["openai-test", "new-service"]
```

For each requested service, record the actual website/app and platform, required actions (login/chat/files/etc.), exact documented or observed endpoints, and why proxying is necessary. Some names need normal DNS only. Existing SNI logs show routed connections, not all directly accessed domains or every DNS query; absence from those logs does not identify a missing domain. Use temporary device DNS/network metadata or official service documentation as needed, never HTTPS interception or credential/content logging.

Validate the PR/CI, then dry-run with the private node config on the VPS. The renderer independently resolves public A upstreams, rejects private/self IPs and verifies their TLS identity. Apply through the reviewed deployment script, correlate external TLS/SNI/DNS and native app behavior, and rollback on regression. Adding a name to an enabled group generates that node's A rewrite, exact SNI allowlist, hosts and AdGuard export together. AAAA stays suppressed until IPv6 is verified; HTTPS/SVCB are suppressed only for rewritten proxy names. Static `records`, exact `exclude` and `blocked` are separate controls, not alternate SNI routing methods.

While PR #1 is draft, do not run `routes-sync.sh` or enable its timer: that script reads master, which does not yet contain this deployment. Use a reviewed fixed feature commit manually. After approval/merge, the existing data-only master updater and timer apply merged route changes without executing new remote root code. Do not alter DnsConf, its ownership journal, NextDNS rewrites or production hosts for this operation.

## Acceptance statuses

| Status | Evidence needed |
|---|---|
| PREPARED ONLY | PR and successful route/syntax/integration checks; no VPS operations |
| DEPLOYED & VERIFIED | effective SSH, NTP, UFW, binds, immutable releases, trusted external DoH/DoT/SNI and denied unlisted sources |
| DEPLOYED, CLIENT TEST PENDING | server acceptance complete, iPhone without VPN not yet confirmed |
| BLOCKED | no authorized VPS shell, missing domain control, missing real client ACLs, or console recovery not verified |

Never promote CI results or a single HTTP 403 to VPS/iPhone acceptance. Existing NextDNS profile `7437fe`, its 808 Rewrites, DnsConf ownership journal and production hosts must remain untouched.

## Public-mode implementation and observed deployment

The user approved the public-mode risk decision on2026-10-12 and deployed reviewed commit48e3749ebc81544a247821c10851585d0ac79473. Native iPhone LTE/handoff acceptance is confirmed above; other clients and unobserved recovery branches remain separate gates. Existing node files default to private mode; public mode requires `access_mode: "public"`, `public_access_ack: true`, TLS enabled and IPv6 disabled. Keep nonempty private `client_cidrs` for recovery. Do not add 0.0.0.0/0 to that list.

Deployed public edge: Nginx 1.31.6 adds a PROXYv2 header to its own local DNS backends. Third-party TLS is routed through loopback port9446, which consumes the header and forwards the unchanged TLS stream to exact pinned public upstreams. Headers are never passed to third-party servers. The relay listens only on loopback; original source IPs remain in its route logs. Local UDP/TCP5300 does not require a PROXY header.

Public-mode safeguards:
- dnsdist trusts PROXYv2 only from physical peer127.0.0.1, only on its TLS frontends, with the header outside TLS. It retains a loopback physical-peer ACL, validates upstream DNS certificates and refuses ANY. A per-source 80QPS/120-burst rule returns REFUSED before route processing; the existing 200QPS aggregate action remains. Same-source DoH and DoT share the per-source budget.
- Public edge caps concurrent connections at16/source and64 globally, with 128KiB/s per connection in each direction. Shared source IPs under CGNAT share those limits. These are candidate starting values, not an audited capacity promise.
- `public-guard.py --arm --fresh-ssh-and-console-tested` defaults to a conservative 2GiB per UTC day of total host-interface RX+TX, sampled every15seconds. It opens only IPv4 TCP443/853, installs a persistent timer and leaves SSH, public53, IPv6 and UDP443 unchanged.
- Budget overrun, reboot/counter reset or a guard sampling error stops the Nginx container, including current tunnels; normal overrun also removes its public UFW rules. Narrow network rules and dnsdist remain. A sampling/error stop may leave public rules present, but Nginx is stopped: inspect and close rules before recovery. Local health monitoring reports the outage. There is no automatic reopening after a latch.
- The budget may overshoot within the sampling/stop interval and counts other host traffic. Host-side rules cannot stop provider-side ingress billing or a volumetric attack; provider quota/DDoS handling remains necessary. It is not cryptographic client authentication.
- If a private release is restored, the guard leaves private Nginx alone. Stop/disable the guard timer and inspect UFW during operator recovery. A stale/latched guard state is not silently reset by `--arm`.

Deployment gates:
1. Confirm green CI for the reviewed final commit, a fresh SSH login and a working provider console. Back up private node settings and image overrides.
2. Install the fixed reviewed feature commit as root. Upgrade the Nginx image deliberately via `/etc/nixz/images.env`; old active image digests are reused by deploy.sh unless overridden. Public syntax preflight must pass with the actual image before any activation.
3. Set the local public flags, retain private CIDRs, run `deploy.sh --dry-run` and inspect. No firewall widening is performed by dry-run.
4. Apply while UFW is still narrow, verify local evidence, trusted external DoH/DoT/SNI from an already allowed network, effective public limits, current bind ports and unchanged SSH. The ordinary Firewall helper still adds only narrow client rules.
5. Only then arm the traffic guard/open IPv4 ingress. Test native LTE, Wi-Fi-to-LTE transitions, forged headers, unknown SNI and budget-close/recovery. Log the actual active SHA, image digests, manifest and client results.
6. `public-guard.py --close` is the emergency operator stop. For recovery, disable its timer, restore the saved private flags/image override as appropriate, run reviewed private deploy dry-run/apply, inspect UFW and repeat probes. Do not manually restart a latched public container without fixing the cause and deliberately reviewing/resetting guard state.

The passing integration stage tests public DNS/TLS, source query flood/refusal, independent-client isolation, cross-transport source identity despite a forged X-Forwarded-For header, external PROXY header rejection, the16-connection source cap and public-to-private ACL restoration. It uses disposable CI TLS only, not production certificate evidence. Budget accounting/reset/latch logic has unit tests; actual UFW activation and normal systemd guard execution passed on node1. The first host activation exposed a duplicated UFW verb; it was fixed with parser preflight before state/timer changes and a real CI UFW dry-run. Its fail-closed path stopped Nginx, and private restoration was actually verified. Budget-triggered closure, reboot handling and production public-to-private recovery still require separate controlled checks.

## Supplied hosts catalogue: inactive by default

`service-candidates.json` contains101 service groups and1,018 valid exact candidate names extracted from the user's supplied hosts. All22 source IP values were discarded, repeated IP/name lines deduplicated, and four legacy local/DNS-test names excluded. Its enabled_groups is empty. `import_hosts.py` validates inputs and reproduces this conversion without enabling any route.

The supplied list is a candidate source, not ownership/need/TLS validation. Do not assume every www/API/status/telemetry/third-party name is required, or that every listed service can use a TCP443 SNI proxy. Game/voice/UDP protocols and arbitrary dynamically generated hostnames may not fit. No broad generic CDN root or wildcard is enabled. Active routes remain the four accepted OpenAI names, and the100-active-domain v1 safety gate is unchanged. Review and activate small service groups in routes.json through CI and real tests; do not lift the limit to blindly import the entire catalogue.
