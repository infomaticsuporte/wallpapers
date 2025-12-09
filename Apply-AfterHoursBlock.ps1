# Apply-AfterHoursBlock.ps1 (v6.5)
# Duas fases: CLEAN (remove denies legados) + APPLY (Allow só Administrators + Deny AzureAD)
# Coleta SIDs AzureAD de forma mais robusta: grupos locais (PrincipalSource), Win32_UserProfile e ProfileList (registro)
# Logoff apenas de sessões não-admin. Compatível com Windows PowerShell 5.1.

param(
    [switch]$BlockRdp,
    [bool]$BlockAzureAdmins = $true   # TRUE: bloqueia AzureAD mesmo se estiverem em Administrators
)
$ErrorActionPreference = 'Stop'

function Write-Log($msg) {
    $logDir = "C:\\Logs\\AfterHours"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path (Join-Path $logDir 'AfterHours.log') -Value "[$stamp] $msg"
}

# Verifica privilégios
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log 'ERROR: Run as Admin/SYSTEM'; throw 'Elevated required'
}

# Utilitários para grupos BUILTIN por SID (independe de idioma)
function Get-BuiltinGroupLocalName([string]$sid) {
    try {
        $name = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value
        if ($name -like 'BUILTIN\\*') { return $name.Split('\\')[1] } else { return $name }
    } catch { Write-Log ("Warn: translate SID '{0}': {1}" -f $sid, $_.Exception.Message); return $null }
}
function Get-LocalGroupMemberSIDsByBuiltinSid([string]$groupSid) {
    $sids = @()
    $groupName = Get-BuiltinGroupLocalName $groupSid
    if (-not $groupName) { return @() }
    try {
        $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
        foreach ($m in $members) {
            try {
                # Preferimos PrincipalSource AzureAD quando disponível
                if ($m.PrincipalSource -and $m.PrincipalSource.ToString() -eq 'AzureAD') {
                    if ($m.SID -and $m.SID.Value) { $sids += $m.SID.Value; continue }
                }
                # Fallback para qualquer membro: traduz por nome
                $sid = $null
                if ($m.SID -and $m.SID.Value) { $sid = $m.SID.Value }
                else { $sid = (New-Object System.Security.Principal.NTAccount($m.Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
                if ($sid) { $sids += $sid }
            } catch { }
        }
    } catch { Write-Log ("Warn: enumerate group '{0}': {1}" -f $groupName, $_.Exception.Message) }
    return ($sids | Sort-Object -Unique)
}

# SIDs AzureAD (S-1-12-1-*) via grupos BUILTIN, Win32_UserProfile e ProfileList
function Get-AzureAdUserSIDs([bool]$includeAdmins) {
    $azureSIDs = @()

    # 1) Grupos BUILTIN
    $candidateGroupSids = @(
        'S-1-5-32-545', # Users
        'S-1-5-32-555', # Remote Desktop Users
        'S-1-5-32-547', # Power Users
        'S-1-5-32-546', # Guests
        'S-1-5-32-551'  # Backup Operators
    )
    foreach ($gsid in $candidateGroupSids) {
        $azureSIDs += (Get-LocalGroupMemberSIDsByBuiltinSid $gsid | Where-Object { $_ -like 'S-1-12-1-*' })
    }
    if ($includeAdmins) {
        $azureSIDs += (Get-LocalGroupMemberSIDsByBuiltinSid 'S-1-5-32-544' | Where-Object { $_ -like 'S-1-12-1-*' })
    }

    # 2) Perfis existentes (Win32_UserProfile)
    try {
        $profileSIDs = (Get-CimInstance Win32_UserProfile -ErrorAction Stop |
            Where-Object { $_.SID -like 'S-1-12-1-*' -and $_.LocalPath -like 'C:\\Users\\*' } |
            Select-Object -ExpandProperty SID)
        if ($profileSIDs) { $azureSIDs += $profileSIDs }
    } catch { Write-Log ("Warn: Win32_UserProfile AzureAD: {0}" -f $_.Exception.Message) }

    # 3) Registro (ProfileList)
    try {
        $keys = Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList' -ErrorAction Stop
        foreach ($k in $keys) {
            $name = $k.PSChildName
            if ($name -like 'S-1-12-1-*') { $azureSIDs += $name }
        }
    } catch { Write-Log ("Warn: Registry ProfileList: {0}" -f $_.Exception.Message) }

    return (($azureSIDs | Sort-Object -Unique))
}

# Caminhos
$work    = Join-Path $env:TEMP 'SecPol-AfterHours'
$infClean= Join-Path $work 'afterhours_clean.inf'
$infPolicy=Join-Path $work 'afterhours_policy.inf'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# ===================== FASE 1: CLEAN =====================
$linesClean=@()
$linesClean+='[Version]'
$linesClean+='signature="$CHICAGO$"'
$linesClean+='Revision=1'
$linesClean+='' 
$linesClean+='[Privilege Rights]'
$linesClean+='SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545'
if ($BlockRdp) { $linesClean+='SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555' }
$linesClean+='SeDenyInteractiveLogonRight ='
$linesClean+='SeDenyRemoteInteractiveLogonRight ='
Remove-Item -Path $infClean -ErrorAction SilentlyContinue
$linesClean | Out-File -FilePath $infClean -Encoding ASCII
Write-Log 'Phase 1: Cleaning denies and restoring default allow rights'
secedit /configure /db "$work\\secpol_clean.sdb" /cfg "$infClean" /areas USER_RIGHTS | Out-Null
try { gpupdate /force | Out-Null } catch { Write-Log ("Warning gpupdate (clean phase): {0}" -f $_.Exception.Message) }

# ===================== FASE 2: APPLY =====================
$adminMemberSIDs = Get-LocalGroupMemberSIDsByBuiltinSid 'S-1-5-32-544'
$azureInAdmins = $adminMemberSIDs | Where-Object { $_ -like 'S-1-12-1-*' }
if ($BlockAzureAdmins -and $azureInAdmins.Count -gt 0) {
    $adminMemberSIDs = $adminMemberSIDs | Where-Object { $_ -notlike 'S-1-12-1-*' }
}

$azureSIDs = Get-AzureAdUserSIDs -includeAdmins:$BlockAzureAdmins
$denySIDs  = $azureSIDs | Sort-Object -Unique

$lines=@()
$lines+='[Version]'
$lines+='signature="$CHICAGO$"'
$lines+='Revision=1'
$lines+='' 
$lines+='[Privilege Rights]'

$allowInteractive = @('*S-1-5-32-544')
foreach ($sid in $adminMemberSIDs) { $allowInteractive += ('*' + $sid) }
$lines += ('SeInteractiveLogonRight = ' + ($allowInteractive -join ','))

if ($BlockRdp) {
    $allowRemote = @('*S-1-5-32-544')
    foreach ($sid in $adminMemberSIDs) { $allowRemote += ('*' + $sid) }
    $lines += ('SeRemoteInteractiveLogonRight = ' + ($allowRemote -join ','))
}

if ($denySIDs.Count -gt 0) {
    $lines += 'SeDenyInteractiveLogonRight = ' + ( ($denySIDs | ForEach-Object { "*$_" }) -join ',' )
    if ($BlockRdp) { $lines += 'SeDenyRemoteInteractiveLogonRight = ' + ( ($denySIDs | ForEach-Object { "*$_" }) -join ',' ) }
}

Remove-Item -Path $infPolicy -ErrorAction SilentlyContinue
$lines | Out-File -FilePath $infPolicy -Encoding ASCII

$msg = ("Phase 2: Apply policy (Allow Admins group + {0} members; Deny AzureAD count={1})" -f $adminMemberSIDs.Count, $denySIDs.Count)
if ($BlockRdp) { $msg += ' + RDP restricted to Administrators' }
Write-Log $msg

secedit /configure /db "$work\\secpol_policy.sdb" /cfg "$infPolicy" /areas USER_RIGHTS | Out-Null
try { gpupdate /force | Out-Null } catch { Write-Log ("Warning gpupdate (apply phase): {0}" -f $_.Exception.Message) }

# ---------- LOGOFF de sessões não-admin ----------
Write-Log 'Evaluating interactive sessions to log off non-admins...'
$adminsName = Get-BuiltinGroupLocalName 'S-1-5-32-544'
$adminMembersNames = @()
try { $adminMembersNames = Get-LocalGroupMember -Group $adminsName -ErrorAction Stop | Select-Object -ExpandProperty Name } catch { }
$quser = & quser 2>$null
if ($quser) {
    foreach ($line in $quser) {
        if ($line -match '^\s*>?\s*(\S+)\s+(\S+)\s+(\d+)\s') {
            $user = $Matches[1]; $session = [int]$Matches[3]
            if ($adminMembersNames -contains $user) {
                Write-Log ("Skipping admin session {0} ('{1}')" -f $session, $user)
            } else {
                Write-Log ("Logging off session {0} (user '{1}')" -f $session, $user)
                & logoff $session /V 2>$null
            }
        }
    }
} else {
    Write-Log 'No interactive sessions found or quser not available.'
}

Write-Log 'AfterHours policy applied successfully.'
