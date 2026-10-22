<#
.SYNOPSIS
  BitForce: ejecuta el BitForce PHP Agent en varios servidores Linux desde Windows
  y junta los reportes con un resumen CSV.

.DESCRIPTION
  Usa el cliente OpenSSH incluido en Windows 10/11 (ssh y scp). No instala nada.
  Funciona en Windows PowerShell 5.1 y PowerShell 7.

.PARAMETER Servers
  Archivo con un servidor por línea:  usuario@host[:puerto]  [ruta\llave]  [alias]
  Las líneas que empiezan con # se ignoran. Usa - si no hay llave.

.PARAMETER Mode
  diagnose (por defecto), fix, plan, stage, switch o rollback.

.PARAMETER AgentArgs
  Opciones extra para el agente, por ejemplo: '--yes'  o  '--to','8.3'

.PARAMETER Interactive
  Abre una terminal por servidor (para sudo con contraseña o confirmar a mano).

.EXAMPLE
  .\bitforce-run.ps1 -Servers .\servidores.txt
.EXAMPLE
  .\bitforce-run.ps1 -Servers .\servidores.txt -Mode fix -AgentArgs '--yes'
.EXAMPLE
  .\bitforce-run.ps1 -Servers .\servidores.txt -Mode plan -AgentArgs '--to','8.3'
.EXAMPLE
  .\bitforce-run.ps1 -Servers .\servidores.txt -Mode fix -Interactive
#>
param(
  [Parameter(Mandatory = $true)][string]$Servers,
  [ValidateSet('diagnose', 'fix', 'plan', 'stage', 'switch', 'rollback')][string]$Mode = 'diagnose',
  [string[]]$AgentArgs = @(),
  [switch]$Interactive,
  [string]$Out = (Join-Path $PSScriptRoot 'reportes'),
  [string]$Agent = (Join-Path $PSScriptRoot 'bitforce-php-agent.sh')
)

$ErrorActionPreference = 'Continue'
foreach ($tool in 'ssh', 'scp') {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    Write-Host "No se encontró '$tool'. Instálalo: Configuración > Aplicaciones > Características opcionales > Cliente OpenSSH." -ForegroundColor Red
    exit 3
  }
}
if (-not (Test-Path $Servers)) { Write-Host "No existe la lista de servidores: $Servers" -ForegroundColor Red; exit 3 }
if (-not (Test-Path $Agent)) { Write-Host "No existe el agente: $Agent" -ForegroundColor Red; exit 3 }

$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
$dest = Join-Path $Out "$runId-$Mode"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

# Opciones de SSH comunes. accept-new acepta la llave del host la primera vez.
$common = @('-o', 'ConnectTimeout=15', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ServerAliveInterval=20')
if (-not $Interactive) { $common += @('-o', 'BatchMode=yes') }

# Cada opción del agente va entre comillas simples para el shell remoto.
$quoted = ''
foreach ($a in $AgentArgs) { $quoted += " '" + ($a -replace "'", "'\''") + "'" }

$results = @()
$lines = Get-Content -Path $Servers | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') }

foreach ($line in $lines) {
  $parts = $line.Trim() -split '\s+'
  $target = $parts[0]
  $key = if ($parts.Count -gt 1) { $parts[1] } else { '-' }
  $hostPart = $target; $port = '22'
  if ($target -match '^(.+):(\d+)$') { $hostPart = $Matches[1]; $port = $Matches[2] }
  $name = if ($parts.Count -gt 2) { $parts[2] } else { ($hostPart -split '@')[-1] }

  $sshOpts = $common + @('-p', $port)
  $scpOpts = $common + @('-P', $port)
  if ($key -ne '-') {
    $keyPath = $key -replace '^~', $HOME
    $sshOpts += @('-i', $keyPath); $scpOpts += @('-i', $keyPath)
  }
  $sudo = if ($hostPart -like 'root@*') { '' } elseif ($Interactive) { 'sudo' } else { 'sudo -n' }

  $folder = Join-Path $dest $name
  New-Item -ItemType Directory -Force -Path $folder | Out-Null
  Write-Host ''
  Write-Host "=== $name ($hostPart) ===" -ForegroundColor Cyan

  # 1. Copiar el agente
  $scpErr = & scp -q @scpOpts $Agent "${hostPart}:/tmp/bitforce-php-agent.sh" 2>&1
  if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: no se pudo copiar el agente: $scpErr" -ForegroundColor Red
    $results += [pscustomobject]@{ Servidor = $hostPart; Alias = $name; Codigo = 255; Veredicto = 'SIN_CONEXION'; Sistema = ''; Panel = ''; Web = ''; PHP = ''; SitiosVulnerables = ''; Indicadores = ''; Reporte = '' }
    continue
  }

  # 2. Ejecutar (sin comillas dobles: compatible con PowerShell 5.1)
  $quiet = if ($Interactive) { '' } else { ' -q' }
  $remote = "sed -i 's/\r`$//' /tmp/bitforce-php-agent.sh; $sudo bash /tmp/bitforce-php-agent.sh $Mode -o /var/tmp/bitforce$quiet$quoted"
  $consoleFile = Join-Path $folder 'consola.txt'
  if ($Interactive) {
    & ssh -t @sshOpts $hostPart $remote
    $rc = $LASTEXITCODE
  } else {
    & ssh -n @sshOpts $hostPart $remote 2>&1 | Out-File -FilePath $consoleFile -Encoding utf8
    $rc = $LASTEXITCODE
  }

  # 3. Traer el reporte más reciente de este modo
  $base = (& ssh -n @sshOpts $hostPart "ls -1t /var/tmp/bitforce/bitforce-*-$Mode.json 2>/dev/null | head -1" 2>$null | Select-Object -First 1)
  $json = $null
  if ($base) {
    $base = $base.Trim() -replace '\.json$', ''
    & scp -q @scpOpts "${hostPart}:$base*" $folder 2>$null | Out-Null
    $json = Join-Path $folder ((Split-Path $base -Leaf) + '.json')
  }

  $estado = switch ($rc) { 0 { 'OK' } 1 { 'REQUIERE ACCION' } 2 { 'SOSPECHOSO' } default { "ERROR ($rc)" } }
  $color = switch ($rc) { 0 { 'Green' } 1 { 'Yellow' } default { 'Red' } }
  Write-Host "  Resultado: $estado" -ForegroundColor $color
  if (Test-Path $consoleFile) {
    Get-Content $consoleFile | Select-String -Pattern '\[FALLA\]', '\[AVISO\]' | Select-Object -First 6 | ForEach-Object { Write-Host "    $($_.Line.Trim())" }
  }

  if ($json -and (Test-Path $json)) {
    $d = Get-Content -Raw -Encoding UTF8 -Path $json | ConvertFrom-Json
    $php = ($d.installations | ForEach-Object { "$($_.branch)=$($_.version):$($_.status)" }) -join '; '
    $vuln = @($d.sites | Where-Object { $_.php_status -in @('VULNERABLE', 'UNSUPPORTED') }).Count
    $results += [pscustomobject]@{
      Servidor = $hostPart; Alias = $name; Codigo = $rc; Veredicto = $d.verdict; Sistema = $d.os.name
      Panel = $d.panel; Web = ($d.web_servers -join ' '); PHP = $php; SitiosVulnerables = $vuln
      Indicadores = ($d.ioc.findings -join ' | '); Reporte = (Split-Path ($base + '.txt') -Leaf)
    }
  } else {
    if ($rc -gt 2 -and (Test-Path $consoleFile) -and (Select-String -Path $consoleFile -Pattern 'sudo|password' -Quiet)) {
      Write-Host '  Sugerencia: el usuario necesita sudo sin contraseña, o usa -Interactive.' -ForegroundColor Yellow
    }
    $results += [pscustomobject]@{ Servidor = $hostPart; Alias = $name; Codigo = $rc; Veredicto = 'ERROR'; Sistema = ''; Panel = ''; Web = ''; PHP = ''; SitiosVulnerables = ''; Indicadores = ''; Reporte = 'consola.txt' }
  }
}

$csv = Join-Path $dest 'resumen.csv'
$results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host ''
$ok = @($results | Where-Object { $_.Codigo -eq 0 }).Count
$act = @($results | Where-Object { $_.Codigo -eq 1 }).Count
$sus = @($results | Where-Object { $_.Codigo -eq 2 }).Count
$err = @($results | Where-Object { $_.Codigo -gt 2 }).Count
Write-Host "=== RESUMEN: $($results.Count) servidores · $ok OK · $act requieren acción · $sus sospechosos · $err con error ===" -ForegroundColor Cyan
$results | Format-Table Alias, Veredicto, PHP, SitiosVulnerables -AutoSize | Out-String -Width 200 | Write-Host
Write-Host "Resumen CSV: $csv"
Write-Host "Reportes   : $dest\<servidor>\"
