param([switch]$CheckOnce)
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$project='D:\Server\anti-spam-bot'
$agent=Join-Path $project 'remote-updater'
$configPath=Join-Path $agent 'config.json'
$logPath=Join-Path $agent 'updater.log'
$mutex=$null;$locked=$false;$tempDir=$null
function Log([string]$Message){
 $line='[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message
 Write-Host $line
 if(Test-Path -LiteralPath $agent){
  if((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 1048576){Move-Item -LiteralPath $logPath -Destination ($logPath+'.old') -Force}
  Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
 }
}
function Invoke-NativeDocker([string[]]$DockerArgs){
 $stdout=[IO.Path]::GetTempFileName();$stderr=[IO.Path]::GetTempFileName()
 try {
  $previous=$ErrorActionPreference
  try {$ErrorActionPreference='Continue'; & docker.exe @DockerArgs 1> $stdout 2> $stderr;$code=$LASTEXITCODE} finally {$ErrorActionPreference=$previous}
  $out=[IO.File]::ReadAllText($stdout);$err=[IO.File]::ReadAllText($stderr)
  return [pscustomobject]@{Code=$code;Stdout=$out;Stderr=$err}
 } finally {Remove-Item -LiteralPath $stdout,$stderr -ErrorAction SilentlyContinue}
}
function Invoke-DockerChecked([string[]]$DockerArgs){
 $result=Invoke-NativeDocker -DockerArgs $DockerArgs
 if($result.Code -ne 0){throw ('docker.exe '+$DockerArgs[0]+' failed; exit '+$result.Code)}
 return $result.Stdout.Trim()
}
function Inspect-Bot {
 $raw=Invoke-DockerChecked -DockerArgs @('inspect','kitaichip-antispam')
 return @($raw | ConvertFrom-Json)[0]
}
function Ready([string]$Hash,[string]$Version){
 $info=Inspect-Bot
 if(-not $info.State.Running){return $false}
 $hashCode="import hashlib; print(hashlib.sha256(open('/app/bot.py','rb').read()).hexdigest())"
 $installed=Invoke-DockerChecked -DockerArgs @('exec','kitaichip-antispam','python','-c',$hashCode)
 if($installed -ine $Hash){return $false}
 $r=Invoke-NativeDocker -DockerArgs @('logs','--tail','200','kitaichip-antispam')
 if($r.Code -ne 0){return $false}
 $lines=$r.Stdout+"`n"+$r.Stderr
 return ($lines -match ('AntiSpam v'+[regex]::Escape($Version)+' ready; active group IDs=\[[^\]\s]+') -and $lines -match 'Application started')
}
try {
 if(-not(Test-Path -LiteralPath $configPath)){throw 'Updater configuration not found. Run ENABLE-AUTOUPDATE.cmd.'}
 $cfg=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
 if(-not $cfg.enabled){Log 'Updates disabled.';exit 0}
 if($cfg.owner -cne 'mefistifel' -or $cfg.repo -cne 'l900'){throw 'Unexpected update channel. No changes made.'}
 $mutex=New-Object System.Threading.Mutex($false,'Global\KitaiAntiSpamUpdater')
 try {$locked=$mutex.WaitOne(0)} catch [System.Threading.AbandonedMutexException] {$locked=$true}
 if(-not $locked){Log 'Bot update or VPN operation already running; retry on next check.';exit 0}
 Get-Command docker.exe -ErrorAction Stop | Out-Null
 $rootUrl='https://raw.githubusercontent.com/mefistifel/l900'
 $meta=Invoke-RestMethod -Uri ($rootUrl+'/main/release.json?t='+[DateTime]::UtcNow.Ticks) -TimeoutSec 25
 if($meta.file -cne 'bot.py' -or $meta.version -notmatch '^\d+\.\d+(?:\.\d+)?$' -or $meta.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $meta.source_commit -notmatch '^[a-f0-9]{40}$'){throw 'Invalid release manifest.'}
 $target=Join-Path $project 'bot.py'
 $sourceText=Get-Content -LiteralPath $target -Raw -Encoding UTF8
 $versionMatch=[regex]::Match($sourceText,'(?m)^VERSION\s*=\s*["''](\d+\.\d+(?:\.\d+)?)["'']')
 if(-not $versionMatch.Success){throw 'Installed source version is unknown.'}
 $oldVersion=[version]$versionMatch.Groups[1].Value;$newVersion=[version]$meta.version
 if($newVersion -le $oldVersion){Log ('CHECK OK: installed '+$oldVersion+'; published '+$newVersion+'. No newer release.');exit 0}
 $vpn=@((Invoke-DockerChecked -DockerArgs @('inspect','bot-vpn')) | ConvertFrom-Json)[0]
 $bot=Inspect-Bot
 if(-not $vpn.State.Running -or -not $bot.State.Running){throw 'VPN or bot is stopped; update postponed.'}
 if($bot.HostConfig.NetworkMode -notin @("container:$($vpn.Id)",'container:bot-vpn')){throw 'VPN network mismatch; update postponed.'}
 # Check actual Telegram HTTPS reachability before making any bot changes.
 $networkCode="import ssl,urllib.request,urllib.error; o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context())); o.open('https://api.telegram.org/',timeout=10).close(); print('HTTPS_OK')"
 $null=Invoke-DockerChecked -DockerArgs @('exec','kitaichip-antispam','python','-c',$networkCode)
 $compose=$null
 foreach($name in @('compose.yaml','compose.yml','docker-compose.yml','docker-compose.yaml')){
  $candidate=Join-Path $project $name
  if(Test-Path -LiteralPath $candidate){$compose=$candidate;break}
 }
 if(-not $compose){throw 'Compose file not found.'}
 $composeArgs=@('compose','-f',$compose,'--project-directory',$project)
 $services=(Invoke-DockerChecked -DockerArgs ($composeArgs+@('config','--services'))) -split '\r?\n'
 if('antispam' -notin $services){throw 'Compose service antispam not found.'}
 $tempDir=Join-Path $agent ('download-'+[guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Path $tempDir | Out-Null
 $download=Join-Path $tempDir 'bot.py'
 # A pinned commit prevents source/manifest races during publication.
 Invoke-WebRequest -Uri ($rootUrl+'/'+$meta.source_commit+'/bot.py') -OutFile $download -TimeoutSec 30 -UseBasicParsing
 if((Get-Item -LiteralPath $download).Length -gt 262144){throw 'Release exceeds size limit.'}
 if((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash -ine $meta.sha256){throw 'Downloaded release SHA256 mismatch.'}
 $newSource=Get-Content -LiteralPath $download -Raw -Encoding UTF8
 if($newSource -notmatch ('(?m)^VERSION\s*=\s*["'']'+[regex]::Escape($meta.version)+'["'']')){throw 'Downloaded source version mismatch.'}
 $null=Invoke-DockerChecked -DockerArgs @('cp',$download,'kitaichip-antispam:/tmp/kitai-release-check.py')
 try {
  $syntax="import ast; ast.parse(open('/tmp/kitai-release-check.py',encoding='utf-8').read()); print('SYNTAX_OK')"
  $null=Invoke-DockerChecked -DockerArgs @('exec','kitaichip-antispam','python','-c',$syntax)
 } finally {$null=Invoke-NativeDocker -DockerArgs @('exec','kitaichip-antispam','rm','-f','/tmp/kitai-release-check.py')}
 $stamp=(Get-Date -Format 'yyyyMMdd-HHmmss-fff')
 $backup=Join-Path $project ('backups\auto-'+$stamp)
 New-Item -ItemType Directory -Path $backup -Force | Out-Null
 Copy-Item -LiteralPath $target -Destination (Join-Path $backup 'bot.py')
 $oldImage=$bot.Image;$imageName=$bot.Config.Image
 if(-not $oldImage -or -not $imageName){throw 'Existing Docker image identity unavailable.'}
 $null=Invoke-DockerChecked -DockerArgs @('image','tag',$oldImage,('antispam-rollback:auto-'+$stamp))
 $changed=$false
 try {
  Copy-Item -LiteralPath $download -Destination $target -Force;$changed=$true
  Log ('Installing '+$meta.version)
  $null=Invoke-DockerChecked -DockerArgs ($composeArgs+@('up','-d','--no-deps','--build','--force-recreate','antispam'))
  $ok=$false
  for($i=0;$i -lt 18;$i++){Start-Sleep -Seconds 5;try {if(Ready $meta.sha256 $meta.version){$ok=$true;break}} catch {}}
  if(-not $ok){throw 'Telegram startup was not confirmed within 90 seconds.'}
  Log ('UPDATE SUCCESS: '+$meta.version+'; Telegram ready; backup '+$backup)
 } catch {
  $reason=$_.Exception.Message
  $logs=Invoke-NativeDocker -DockerArgs @('logs','--tail','180','kitaichip-antispam')
  $safeLogs=[regex]::Replace(($logs.Stdout+"`n"+$logs.Stderr),'\d{6,}:[A-Za-z0-9_-]{20,}','[TOKEN]')
  $safeLogs | Set-Content -LiteralPath (Join-Path $backup 'failed-startup.txt') -Encoding UTF8
  if($changed){
   Copy-Item -LiteralPath (Join-Path $backup 'bot.py') -Destination $target -Force
   try {
    $null=Invoke-DockerChecked -DockerArgs @('image','tag',$oldImage,$imageName)
    $null=Invoke-DockerChecked -DockerArgs ($composeArgs+@('up','-d','--no-deps','--no-build','--force-recreate','antispam'))
    Log 'Previous source and image restored; Telegram recovery still needs checking.'
   } catch {throw ('UPDATE FAILED: '+$reason+'. ROLLBACK FAILED. Backup: '+$backup)}
  }
  throw ('UPDATE FAILED: '+$reason+'. Backup: '+$backup)
 }
} catch {Log ('ERROR: '+$_.Exception.Message);exit 1}
finally {
 if($tempDir){Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue}
 if($locked){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}
}
