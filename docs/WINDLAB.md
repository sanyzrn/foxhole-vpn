# WindLab — phase 1 (experimental)

This fork preserves Firefox VPN and introduces a separate HTTPS CONNECT provider for manually supplied, authorized proxy credentials. It reuses the local SOCKS5/HTTP listener, with no direct fallback. It is not a full-system VPN or a proven Scorpion equivalent.

## Windows (PowerShell)

Use provider-issued proxy credentials, not your website password or TOTP. Do not sign out of Chrome or copy browser session secrets. No account login or server discovery is implemented yet.

```powershell
npm ci
npm run build
$env:WINDLAB_PROXY_HOST = Read-Host "Proxy TLS hostname"
$env:WINDLAB_PROXY_PORT = "443"
$env:WINDLAB_PROXY_USER = Read-Host "Proxy username"
$secret = Read-Host "Proxy password" -AsSecureString
$env:WINDLAB_PROXY_PASSWORD = [System.Net.NetworkCredential]::new("", $secret).Password
node dist/cli.js windscribe-check
node dist/cli.js windscribe-proxy --port 1081
Remove-Item Env:WINDLAB_PROXY_PASSWORD, Env:WINDLAB_PROXY_USER, Env:WINDLAB_PROXY_HOST, Env:WINDLAB_PROXY_PORT
Remove-Variable secret
```

In a separate PowerShell window: `curl.exe --proxy socks5h://127.0.0.1:1081 https://api.ipify.org`. Stop with Ctrl+C. Environment variables are readable by sufficiently privileged local processes; this code does not persist credentials.

## Boundaries

- TLS certificate verification; upstream ports 443 or 9443. TCP only; UDP rejected.
- Loopback only. No system routing, firewall, DNS, CA or browser-profile changes.
- No Mozilla account access or Windscribe login. Authorized proxy credentials are a prerequisite.
- A successful IP response proves this configured tunnel works, not that it matches Scorpion.
- Next: verify supported Windscribe authentication, then provider-aware TUN, DNS/leak tests and UI. Preserve the MIT license.
