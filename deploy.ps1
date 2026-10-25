param(
    [string]$RouterIp = "192.168.1.1",
    [int]$Port = 22,
    [string]$User = "admin"
)

$ErrorActionPreference = "Stop"

Write-Host "Ensuring /jffs directories exist on $RouterIp (port $Port)..."
ssh -p $Port "$User@$RouterIp" "mkdir -p /jffs/bin /jffs/etc /jffs/scripts"

Write-Host "Uploading files using legacy SCP protocol (-O) on port $Port..."
scp -O -P $Port dist/merlin-otel-agent "${User}@${RouterIp}:/jffs/bin/merlin-otel-agent"
scp -O -P $Port dist/motel.conf.example "${User}@${RouterIp}:/jffs/etc/motel.conf.example"
scp -O -P $Port dist/services-start "${User}@${RouterIp}:/jffs/scripts/services-start"

Write-Host "Seeding /jffs/etc/motel.conf (if absent) and setting executable permissions..."
ssh -p $Port "$User@$RouterIp" "[ -f /jffs/etc/motel.conf ] || cp /jffs/etc/motel.conf.example /jffs/etc/motel.conf; chmod +x /jffs/bin/merlin-otel-agent /jffs/scripts/services-start"

Write-Host "`nDeployment complete! You can start the daemon with:"
Write-Host "  ssh -p $Port $User@$RouterIp '/jffs/scripts/services-start'"
