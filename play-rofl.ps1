[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ReplayPath,

    [ValidatePattern('^[A-Za-z0-9]+$')]
    [string]$PlatformId = 'HN1',

    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 40,

    [switch]$Replace
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Read-RoflVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        $header = New-Object byte[] 128
        $read = $stream.Read($header, 0, $header.Length)
    }
    finally {
        $stream.Dispose()
    }

    if ($read -lt 16 -or [System.Text.Encoding]::ASCII.GetString($header, 0, 4) -ne 'RIOT') {
        throw 'The file is not a valid RIOT ROFL replay.'
    }

    $versionLength = [int]$header[0x0e]
    if ($versionLength -lt 1 -or (0x0f + $versionLength) -gt $read) {
        throw 'The ROFL version field is invalid.'
    }

    $version = [System.Text.Encoding]::UTF8.GetString($header, 0x0f, $versionLength)
    if ($version -notmatch '^\d+(?:\.[0-9A-Za-z]+)+$') {
        throw "Unexpected ROFL version format: $version"
    }
    return $version
}

function Get-LcuConnection {
    $process = Get-CimInstance Win32_Process -Filter "Name='LeagueClientUx.exe'" |
        Where-Object { $_.CommandLine -match '--app-port=\d+' } |
        Select-Object -First 1
    if (-not $process) {
        throw 'League Client is not running. Sign in through WeGame and stay in the client lobby.'
    }

    $port = [regex]::Match($process.CommandLine, '--app-port=(\d+)').Groups[1].Value
    $token = [regex]::Match($process.CommandLine, '--remoting-auth-token=([^"\s]+)').Groups[1].Value
    if (-not $port -or -not $token) {
        throw 'Could not read the local LCU connection from League Client.'
    }

    $credentials = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes("riot:$token")
    )
    return [pscustomobject]@{
        Port = $port
        Authorization = "Basic $credentials"
    }
}

function Invoke-Lcu {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Connection,
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Body
    )

    $url = "https://127.0.0.1:$($Connection.Port)$Path"
    $arguments = @(
        '-sS', '-k',
        '-X', $Method,
        '-w', "`n__ROFL_HTTP_STATUS__%{http_code}",
        '-H', "Authorization: $($Connection.Authorization)",
        '-H', 'Content-Type: application/json'
    )

    if ($PSBoundParameters.ContainsKey('Body')) {
        $responseLines = $Body | & curl.exe @arguments --data-binary '@-' $url
    }
    else {
        $responseLines = & curl.exe @arguments $url
    }
    $curlExitCode = $LASTEXITCODE
    if ($curlExitCode -ne 0) {
        throw "LCU request failed (curl exit code $curlExitCode)."
    }

    $response = $responseLines -join "`n"
    $marker = '__ROFL_HTTP_STATUS__'
    $markerIndex = $response.LastIndexOf($marker)
    if ($markerIndex -lt 0) {
        throw 'LCU response did not include an HTTP status.'
    }

    $responseBody = $response.Substring(0, $markerIndex).Trim()
    $statusText = $response.Substring($markerIndex + $marker.Length).Trim()
    $statusCode = 0
    if (-not [int]::TryParse($statusText, [ref]$statusCode)) {
        throw "LCU returned an invalid HTTP status: $statusText"
    }

    return [pscustomobject]@{
        StatusCode = $statusCode
        Body = $responseBody
    }
}

function Assert-LcuSuccess {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Response,
        [Parameter(Mandatory = $true)][string]$Operation,
        [int[]]$AllowedStatus = @(200, 204)
    )

    if ($AllowedStatus -notcontains $Response.StatusCode) {
        $details = if ($Response.Body) { ": $($Response.Body)" } else { '' }
        throw "$Operation failed (HTTP $($Response.StatusCode))$details"
    }
}

try {
    $resolvedReplay = (Resolve-Path -LiteralPath $ReplayPath).Path
    $file = Get-Item -LiteralPath $resolvedReplay
    if ($file.PSIsContainer -or $file.Extension -ine '.rofl') {
        throw 'Select a .rofl replay file.'
    }

    $gameIdMatch = [regex]::Match($file.BaseName, '(?:^|[-_])(\d{8,})$')
    if (-not $gameIdMatch.Success) {
        $gameIdMatch = [regex]::Match($file.BaseName, '(\d{8,})')
    }
    if (-not $gameIdMatch.Success) {
        throw 'Could not identify a game ID in the filename. Keep a numeric name such as 11191200253.rofl.'
    }
    $gameId = $gameIdMatch.Groups[1].Value
    $replayVersion = Read-RoflVersion -Path $resolvedReplay

    $connection = Get-LcuConnection
    $configurationResponse = Invoke-Lcu -Connection $connection -Method GET -Path '/lol-replays/v1/configuration'
    Assert-LcuSuccess -Response $configurationResponse -Operation 'Read replay configuration' -AllowedStatus @(200)
    $configuration = $configurationResponse.Body | ConvertFrom-Json

    if (-not $configuration.isReplaysEnabled) {
        throw 'Replays are not enabled in the current client.'
    }
    if ($configuration.isPatching) {
        throw 'League Client is patching. Wait for it to finish before playing a replay.'
    }
    if ($configuration.gameVersion -ne $replayVersion) {
        throw "Version mismatch: replay is $replayVersion, current client is $($configuration.gameVersion)."
    }

    $pathResponse = Invoke-Lcu -Connection $connection -Method GET -Path '/lol-replays/v1/rofls/path'
    Assert-LcuSuccess -Response $pathResponse -Operation 'Read replay directory' -AllowedStatus @(200)
    $replayDirectory = $pathResponse.Body | ConvertFrom-Json
    if (-not $replayDirectory) {
        throw 'League Client returned an empty replay directory.'
    }
    [System.IO.Directory]::CreateDirectory($replayDirectory) | Out-Null

    $clientReplay = Join-Path $replayDirectory "$PlatformId-$gameId.rofl"
    $sourceFullPath = [System.IO.Path]::GetFullPath($resolvedReplay)
    $destinationFullPath = [System.IO.Path]::GetFullPath($clientReplay)
    if ($sourceFullPath -ine $destinationFullPath) {
        if (Test-Path -LiteralPath $clientReplay) {
            $sourceHash = (Get-FileHash -LiteralPath $resolvedReplay -Algorithm SHA256).Hash
            $destinationHash = (Get-FileHash -LiteralPath $clientReplay -Algorithm SHA256).Hash
            if ($sourceHash -ne $destinationHash) {
                if (-not $Replace) {
                    throw "A different replay with the same game ID already exists: $clientReplay. Add -Replace to back it up and replace it."
                }
                $backup = "$clientReplay.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                Move-Item -LiteralPath $clientReplay -Destination $backup
                Write-Host "Backed up the old replay: $backup" -ForegroundColor Yellow
                Copy-Item -LiteralPath $resolvedReplay -Destination $clientReplay
            }
        }
        else {
            Copy-Item -LiteralPath $resolvedReplay -Destination $clientReplay
        }
    }

    $existingGame = Get-CimInstance Win32_Process -Filter "Name='League of Legends.exe'" |
        Select-Object -First 1
    if ($existingGame) {
        if ($existingGame.CommandLine -like "*$([System.IO.Path]::GetFileName($clientReplay))*") {
            Write-Host "Replay is already running: $clientReplay" -ForegroundColor Green
            exit 0
        }
        throw 'A game or another replay is already running. Close it and try again.'
    }

    $scanResponse = Invoke-Lcu -Connection $connection -Method POST -Path '/lol-replays/v1/rofls/scan'
    Assert-LcuSuccess -Response $scanResponse -Operation 'Scan local replays'

    $contextJson = '{"componentType":"replay-button_match-history"}'
    $watchResponse = Invoke-Lcu `
        -Connection $connection `
        -Method POST `
        -Path "/lol-replays/v1/rofls/$gameId/watch" `
        -Body $contextJson
    Assert-LcuSuccess -Response $watchResponse -Operation 'Start replay'

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $startedGame = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $startedGame = Get-CimInstance Win32_Process -Filter "Name='League of Legends.exe'" |
            Where-Object { $_.CommandLine -like "*$([System.IO.Path]::GetFileName($clientReplay))*" } |
            Select-Object -First 1
        if ($startedGame) {
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $startedGame) {
        throw "League Client accepted the request, but no replay process appeared within $TimeoutSeconds seconds."
    }

    try {
        $shell = New-Object -ComObject WScript.Shell
        $null = $shell.AppActivate([int]$startedGame.ProcessId)
    }
    catch {
        # The replay is running; foreground activation failure is non-fatal.
    }

    Write-Host 'Replay started successfully.' -ForegroundColor Green
    Write-Host "Game ID: $gameId"
    Write-Host "Version: $replayVersion"
    Write-Host "Client replay: $clientReplay"
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
