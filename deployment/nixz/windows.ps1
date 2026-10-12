param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
  [ValidateSet('Audit','Prepare','Security','DeploySNI','Firewall','Verify')][string]$Step = 'Audit',
  [switch]$FreshSSHAndConsoleTested
)
$ErrorActionPreference = 'Stop'
$Key = 'C:\Users\ITm\.ssh\node1_ed25519'
if (-not (Test-Path -LiteralPath $Key)) { throw 'Local SSH key not found. Do not upload it.' }
$SSHArgs = @('-tt','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-i',$Key,'admin@2.27.16.203')
function Remote([string]$Command) {
  & ssh @SSHArgs $Command
  if ($LASTEXITCODE -ne 0) { throw "Remote command failed ($LASTEXITCODE)" }
}
# A real fresh SSH login on every invocation. Passphrase is entered in OpenSSH locally.
Remote 'id; sudo whoami; sudo sshd -T | grep -E "^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) "'
$Base = '/opt/nixz/repo/deployment/nixz'
switch ($Step) {
  'Audit' {
    Remote 'uname -a; lsb_release -ds; free -h; df -h /; timedatectl; ip -br address; sudo ss -lntup; sudo ufw status verbose; sudo systemctl --failed'
  }
  'Prepare' {
    # Clone as root; admin must not be able to edit code subsequently executed as root by timers.
    Remote 'command -v git >/dev/null || { sudo apt-get update && sudo apt-get install -y git; }'
    Remote "sudo install -d -m 755 /opt/nixz; sudo git clone --no-checkout https://github.com/NixZ-lab/dns.malw.link.git /opt/nixz/repo && sudo git -C /opt/nixz/repo checkout --detach $Commit"
    Remote "sudo install -d -m 700 /etc/nixz; sudo cp $Base/node.json.example /etc/nixz/node.json; sudo cat /etc/nixz/node.json"
    Write-Host 'Next: edit /etc/nixz/node.json via SSH with sudo nano; add your personal public client IP /32. hostname may remain empty; tls=false.'
  }
  'Security' {
    if (-not $FreshSSHAndConsoleTested) { throw 'Test a usable rescue console and a fresh SSH session, then pass -FreshSSHAndConsoleTested.' }
    Remote "cd $Base && sudo --preserve-env=SSH_CONNECTION bash bootstrap.sh --fresh-ssh-and-console-tested"
    Write-Host 'Within 180 seconds open another SSH session and stop nixz-firewall-rescue.timer AFTER successful login.'
  }
  'DeploySNI' {
    Remote "cd $Base && sudo bash deploy.sh --dry-run && sudo bash deploy.sh --apply"
    Write-Host 'Only SNI + loopback DNS if tls=false. Public access still requires Firewall step.'
  }
  'Firewall' {
    if (-not $FreshSSHAndConsoleTested) { throw 'Fresh SSH and usable console must be tested.' }
    Remote "cd $Base && sudo bash firewall.sh --fresh-ssh-and-console-tested"
  }
  'Verify' {
    Remote "sudo docker ps --format 'table {{.Names}}\t{{.Status}}'; sudo ss -lntup; sudo ufw status numbered; cd $Base && sudo python3 probe.py --release /opt/nixz/current"
    Write-Host 'These are SERVER-LOCAL checks. Run external probe.py from a different permitted network, then test iPhone.'
  }
}
