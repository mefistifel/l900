param([switch]$Elevated)
$ErrorActionPreference='Stop'
$project='D:\Server\anti-spam-bot'
$agent=Join-Path $project 'remote-updater'
$task='KITAI-AntiSpam-Update'
$mutex=$null;$locked=$false;$backup=$null;$taskChanged=$false
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=New-Object Security.Principal.WindowsPrincipal($identity)
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  if($Elevated){throw 'Administrator rights are required for Task Scheduler.'}
  Write-Host 'Requesting Windows administrator rights to install the scheduled task...'
  $argsText='-NoProfile -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Elevated'
  $child=Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argsText -Wait -PassThru
  exit $child.ExitCode
 }
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 if(-not(Test-Path -LiteralPath (Join-Path $project 'bot.py'))){throw 'Existing AntiSpam project not found.'}
 Get-Command docker.exe -ErrorAction Stop | Out-Null
 & docker.exe info --format '{{.ServerVersion}}'
 if($LASTEXITCODE -ne 0){throw 'Docker is unavailable for this Windows account.'}
 Write-Host 'Checking the published update channel...'
 $meta=Invoke-RestMethod -Uri ('https://raw.githubusercontent.com/mefistifel/l900/main/release.json?t='+[DateTime]::UtcNow.Ticks) -TimeoutSec 25
 if($meta.version -notmatch '^\d+\.\d+(?:\.\d+)?$' -or $meta.file -cne 'bot.py' -or $meta.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $meta.source_commit -notmatch '^[a-f0-9]{40}$'){throw 'Invalid published release manifest.'}
 $mutex=New-Object System.Threading.Mutex($false,'Global\KitaiAntiSpamUpdater')
 try {$locked=$mutex.WaitOne(0)} catch [System.Threading.AbandonedMutexException] {$locked=$true}
 if(-not $locked){throw 'A bot update or VPN check is running. Run this file again after it finishes.'}
 New-Item -ItemType Directory -Path $agent -Force | Out-Null
 $backup=Join-Path $agent ('setup-backups\'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
 New-Item -ItemType Directory -Path $backup -Force | Out-Null
 foreach($name in @('Update.ps1','config.json','CHECK-NOW.cmd','DISABLE.cmd','ENABLE.cmd','STATUS.cmd')){
  $old=Join-Path $agent $name
  if(Test-Path -LiteralPath $old){Copy-Item -LiteralPath $old -Destination (Join-Path $backup $name)}
 }
 $existing=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
 if($existing){Export-ScheduledTask -TaskName $task | Set-Content -LiteralPath (Join-Path $backup 'task.xml') -Encoding Unicode}
 try {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Update.ps1') -Destination (Join-Path $agent 'Update.ps1') -Force
  @{owner='mefistifel';repo='l900';branch='main';enabled=$true;project=$project} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $agent 'config.json') -Encoding UTF8
  foreach($name in @('CHECK-NOW.cmd','DISABLE.cmd','ENABLE.cmd','STATUS.cmd')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $agent $name) -Force}
  Write-Host 'Registering automatic checks every 10 minutes...'
  $account=[Security.Principal.WindowsIdentity]::GetCurrent().Name
  $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $agent 'Update.ps1')+'" -CheckOnce')
  $period=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 10)
  $logon=New-ScheduledTaskTrigger -AtLogOn -User $account
  $userPrincipal=New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
  $null=Register-ScheduledTask -TaskName $task -Action $action -Trigger @($period,$logon) -Principal $userPrincipal -Settings $settings -Force
  $taskChanged=$true
 } catch {
  foreach($name in @('Update.ps1','config.json','CHECK-NOW.cmd','DISABLE.cmd','ENABLE.cmd','STATUS.cmd')){
   $saved=Join-Path $backup $name;$dest=Join-Path $agent $name
   if(Test-Path -LiteralPath $saved){Copy-Item -LiteralPath $saved -Destination $dest -Force}else{Remove-Item -LiteralPath $dest -ErrorAction SilentlyContinue}
  }
  throw
 }
 Write-Host 'AUTO UPDATE ENABLED: mefistifel/l900; every 10 minutes while this Windows user is logged on.' -ForegroundColor Green
 Write-Host ('Published version: '+$meta.version+'. Bot code and VPN are not restarted by this setup.')
} catch {Write-Host ('ERROR: '+$_.Exception.Message) -ForegroundColor Red;$rc=1}
finally {if($locked){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}}
if($taskChanged){
 & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $agent 'Update.ps1') -CheckOnce
 if($LASTEXITCODE -ne 0){Write-Host 'Auto-update is enabled, but the initial check failed. It will retry on schedule.';$rc=1}else{$rc=0}
}
if($Elevated){Read-Host 'Press Enter to close this window' | Out-Null}
if($rc){exit $rc}
exit 0
