#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MsiPath,[Parameter(Mandatory)][string]$ExpectedSHA256,[Parameter(Mandatory)][string]$ResultDirectory)
$ErrorActionPreference='Stop'
if((Get-FileHash $MsiPath -Algorithm SHA256).Hash -ne $ExpectedSHA256){throw 'Checksum mismatch.'}
if(Get-Service Fail2Ban4Win -ErrorAction SilentlyContinue){throw 'Refusing to replace an existing service.'}
$config=Join-Path $env:ProgramData 'Fail2Ban4Win\configuration.ini'
if(Test-Path $config){throw 'Refusing to replace existing configuration.'}
if(Test-Path $ResultDirectory){throw 'Use a fresh test directory.'}
New-Item -ItemType Directory -Path $ResultDirectory | Out-Null
function Msi([string]$Operation,[string]$Log){
 $logPath=Join-Path $ResultDirectory $Log
 $p=Start-Process msiexec.exe -ArgumentList "$Operation `"$MsiPath`" /qn /norestart /L*v `"$logPath`"" -Wait -PassThru
 if($p.ExitCode -ne 0){throw "MSI exit $($p.ExitCode); see $logPath"}
}
$installed=$false
$before=@(Get-NetFirewallRule | Where-Object DisplayGroup -eq 'Fail2Ban4Win' | Select-Object -ExpandProperty Name) -join "`n"
try {
 Msi '/i' 'install.log';$installed=$true
 $service=Get-CimInstance Win32_Service -Filter "Name='Fail2Ban4Win'"
 if($service.StartMode -ne 'Disabled' -or $service.State -ne 'Stopped'){throw 'Service must initially be disabled and stopped.'}
 if($service.PathName -notmatch '^"[^\"]+Fail2Ban4Win.exe"'){throw 'Unquoted service executable path.'}
 if((Get-Content $config -Raw) -notmatch '(?m)^isDryRun=true\r?$'){throw 'Expected dry-run config.'}
 foreach($rule in (Get-Acl $config).Access){
  $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
  if($rule.AccessControlType -eq 'Allow' -and $sid -in 'S-1-1-0','S-1-5-11','S-1-5-32-545' -and
     ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData)){throw 'Unprivileged users can modify service configuration.'}
 }
 Set-Service Fail2Ban4Win -StartupType Manual
 Start-Service Fail2Ban4Win
 (Get-Service Fail2Ban4Win).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
 Start-Sleep -Seconds 3
 if((Get-Service Fail2Ban4Win).Status -ne 'Running'){throw 'Diagnostic service exited.'}
 Stop-Service Fail2Ban4Win
 (Get-Service Fail2Ban4Win).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
 Set-Service Fail2Ban4Win -StartupType Disabled
 Add-Content $config '; MSI lifecycle test marker'
 Msi '/fa' 'repair.log'
 if((Get-Content $config -Raw) -notmatch 'MSI lifecycle test marker'){throw 'Repair overwrote local configuration.'}
 $after=@(Get-NetFirewallRule | Where-Object DisplayGroup -eq 'Fail2Ban4Win' | Select-Object -ExpandProperty Name) -join "`n"
 if($before -ne $after){throw 'Diagnostic test altered owned firewall rules.'}
 'PASS install, disabled service, quoted path, config ACL, diagnostic start/stop and config-preserving repair'
} finally {if($installed){Msi '/x' 'uninstall.log'}}
if(Get-Service Fail2Ban4Win -ErrorAction SilentlyContinue){throw 'Uninstall left service behind.'}
if((Get-Content $config -Raw) -notmatch 'MSI lifecycle test marker'){throw 'Uninstall removed local configuration.'}
Copy-Item $config (Join-Path $ResultDirectory 'configuration.after-uninstall.ini')
@('[Result]','Status=Passed','Install=Passed','DiagnosticService=Passed','Repair=Passed','Uninstall=Passed','ConfigPreserved=true','FirewallUnchanged=true') | Set-Content (Join-Path $ResultDirectory 'result.ini')
'PASS MSI uninstall and local configuration preservation'
