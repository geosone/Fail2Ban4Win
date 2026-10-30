#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$lock=Get-Content (Join-Path $root 'Fail2Ban4Win/packages.lock.json') -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$index=@('Dependency notices for the fork build. Upstream License.txt remains applicable.','')
foreach($framework in $lock.dependencies.PSObject.Properties){
 foreach($dependency in $framework.Value.PSObject.Properties){
  $id=$dependency.Name;$version=$dependency.Value.resolved
  if(!$version){continue}
  $package=Join-Path (Join-Path (Join-Path $env:USERPROFILE '.nuget\packages') $id.ToLowerInvariant()) $version.ToLowerInvariant()
  $nuspec=Get-ChildItem $package -Filter '*.nuspec' | Select-Object -First 1
  if(!$nuspec){throw "Missing restored metadata: $id $version"}
  [xml]$metadata=Get-Content $nuspec.FullName -Raw
  $entry=Join-Path $OutputDirectory ($id+'-'+$version)
  New-Item -ItemType Directory -Force -Path $entry | Out-Null
  Copy-Item $nuspec.FullName $entry
  $notices=@(Get-ChildItem $package -File -Recurse | Where-Object {$_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)([._-].*)?$'})
  $n=0;foreach($notice in $notices){$n++;Copy-Item $notice.FullName (Join-Path $entry ("$n-"+$notice.Name))}
  $license=$metadata.SelectSingleNode('//*[local-name()="metadata"]/*[local-name()="license"]')
  if(!$notices -and $license -and $license.type -eq 'expression'){
   Invoke-WebRequest -UseBasicParsing -Uri ('https://licenses.nuget.org/'+[uri]::EscapeDataString($license.InnerText)) -OutFile (Join-Path $entry 'LICENSE.txt')
  } elseif(!$notices -and $id -eq 'WindowsFirewallHelper' -and $version -eq '2.2.0.86'){
   Copy-Item (Join-Path $PSScriptRoot '../third-party/WindowsFirewallHelper-2.2.0.86-LICENSE.txt') (Join-Path $entry 'LICENSE.txt')
  } elseif(!$notices -and (!$license -or $license.type -ne 'file')){throw "License text needs manual review: $id $version"}
  if($license -and $license.type -eq 'file'){
   $licensePath=Join-Path $package $license.InnerText
   if(!(Test-Path $licensePath)){throw "Missing package license: $id"}
   Copy-Item $licensePath (Join-Path $entry 'PACKAGE-LICENSE.txt')
  }
  $index+="$id $version | SHA512 contentHash=$($dependency.Value.contentHash)"
 }
}
$index | Set-Content (Join-Path $OutputDirectory 'DEPENDENCIES.txt')
