# Create-Tasks.ps1 (v3.5)
param(
    [string]$BasePath='C:\\Scripts\\AfterHours',
    [string]$BlockTime='19:00',
    [string]$UnblockTime='07:00',
    [switch]$IncludeRdp
)
$ErrorActionPreference='Stop'
if(-not(Test-Path $BasePath)){New-Item -ItemType Directory -Force -Path $BasePath|Out-Null}
$applyPath = Join-Path $BasePath 'Apply-AfterHoursBlock.ps1'
$removePath= Join-Path $BasePath 'Remove-AfterHoursBlock.ps1'
if(-not(Test-Path $applyPath)){throw "File not found: $applyPath"}
if(-not(Test-Path $removePath)){throw "File not found: $removePath"}
$blockAt   = [DateTime]::ParseExact($BlockTime,'HH:mm',$null)
$unblockAt = [DateTime]::ParseExact($UnblockTime,'HH:mm',$null)
$triggerBlock   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday,Tuesday,Wednesday,Thursday,Friday -At $blockAt
$triggerUnblock = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday,Tuesday,Wednesday,Thursday,Friday -At $unblockAt
$applyArgs  = "-NoProfile -ExecutionPolicy Bypass -File `"$applyPath`""
if($IncludeRdp){ $applyArgs += " -BlockRdp" }
$removeArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$removePath`""
if($IncludeRdp){ $removeArgs += " -UnblockRdp" }
$actionBlock   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $applyArgs
$actionUnblock = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $removeArgs
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'AfterHours_BlockLocalLogon' -Trigger $triggerBlock -Action $actionBlock -Principal $principal -Description 'Block local logon (and RDP if enabled) at 19:00 (Mon-Fri) and force logoff' -Force
Register-ScheduledTask -TaskName 'AfterHours_AllowLocalLogon' -Trigger $triggerUnblock -Action $actionUnblock -Principal $principal -Description 'Allow local logon (and RDP if enabled) at 07:00 (Mon-Fri)' -Force
Write-Host "Tasks created successfully:"; Write-Host " - AfterHours_BlockLocalLogon (Mon-Fri at $BlockTime)"; Write-Host " - AfterHours_AllowLocalLogon (Mon-Fri at $UnblockTime)"; if($IncludeRdp){Write-Host 'RDP will also be denied during block hours.'}else{Write-Host 'Console logon only is controlled.'}; Write-Host 'Weekend remains fully blocked.'
