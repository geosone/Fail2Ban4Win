#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Release','Debug')][string]$Configuration='Release')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$msbuild=& $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if(!$msbuild){throw 'MSBuild with .NET Framework 4.7.2 targeting pack required.'}
Push-Location $root
try {
    & $msbuild Fail2Ban4Win/Fail2Ban4Win.csproj /t:Restore /p:RestoreLockedMode=false /verbosity:minimal
    if($LASTEXITCODE -ne 0){throw 'Restore failed.'}
    & $msbuild Fail2Ban4Win/Fail2Ban4Win.csproj /t:Build "/p:Configuration=$Configuration" /verbosity:minimal
    if($LASTEXITCODE -ne 0){throw 'Build failed.'}
} finally {Pop-Location}
