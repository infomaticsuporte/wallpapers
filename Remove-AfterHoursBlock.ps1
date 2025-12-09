# Remove-AfterHoursBlock.ps1 (v6.5)
# Limpa quaisquer denies e restaura allow padrão
param([switch]$UnblockRdp)
$ErrorActionPreference='Stop'
function Write-Log($msg){
    $logDir="C:\\Logs\\AfterHours"
    if(-not(Test-Path $logDir)){New-Item -ItemType Directory -Force -Path $logDir|Out-Null}
    $stamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path (Join-Path $logDir 'AfterHours.log') -Value "[$stamp] $msg"
}
$work   = Join-Path $env:TEMP 'SecPol-AfterHours'
$infPath= Join-Path $work 'afterhours_restore.inf'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$lines=@()
$lines+='[Version]'
$lines+='signature="$CHICAGO$"'
$lines+='Revision=1'
$lines+='' 
$lines+='[Privilege Rights]'
$lines+='SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545'
if($UnblockRdp){$lines+='SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555'}
$lines+='SeDenyInteractiveLogonRight ='
$lines+='SeDenyRemoteInteractiveLogonRight ='
Remove-Item -Path $infPath -ErrorAction SilentlyContinue
$lines | Out-File -FilePath $infPath -Encoding ASCII
Write-Log 'Restoring default allow rights and clearing denies'
secedit /configure /db "$work\\secpol_restore.sdb" /cfg "$infPath" /areas USER_RIGHTS | Out-Null
try { gpupdate /force | Out-Null } catch { Write-Log ("Warning gpupdate: {0}" -f $_.Exception.Message) }
Write-Log 'Policy restored.'
