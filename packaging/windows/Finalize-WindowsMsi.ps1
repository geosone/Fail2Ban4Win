#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MsiPath)
$ErrorActionPreference='Stop'
$installer=New-Object -ComObject WindowsInstaller.Installer
$database=$installer.OpenDatabase((Resolve-Path $MsiPath).Path,1)
$view=$database.OpenView('SELECT `FileName`, `Component_` FROM `File`');$view.Execute()
$component=$null
while($record=$view.Fetch()){
 if(($record.StringData(1) -split '\|')[-1] -eq 'configuration.ini'){$component=$record.StringData(2)}
}
$view.Close()
if(!$component -or $component -notmatch '^C[0-9]+$'){throw 'Cannot identify configuration component.'}
$view=$database.OpenView("SELECT ``Attributes`` FROM ``Component`` WHERE ``Component``='$component'");$view.Execute();$record=$view.Fetch()
$attributes=$record.IntegerData(1) -bor 128 # msidbComponentAttributesNeverOverwrite
$view.Close()
$view=$database.OpenView("UPDATE ``Component`` SET ``Attributes``=$attributes WHERE ``Component``='$component'");$view.Execute();$view.Close()
$database.Commit()
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
(Get-FileHash $MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
