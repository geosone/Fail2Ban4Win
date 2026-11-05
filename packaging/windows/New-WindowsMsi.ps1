#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$BuildDirectory,[Parameter(Mandatory)][string]$OutputDirectory,[ValidateSet('x86','x64')][string]$Architecture='x64')
$ErrorActionPreference='Stop'
# Read the file version from a PE version resource. VS_FIXEDFILEINFO
# (Microsoft winver.h) starts with the signature 0xFEEF04BD; zero-based offset 8
# holds dwFileVersionMS (major << 16 | minor) and offset 12 dwFileVersionLS
# (build << 16 | revision), both little-endian UInt32. wixl leaves File.Version
# empty, and Windows Installer costing (before the old product is removed)
# would then keep an installed versioned file instead of the new one.
function PeVersion([string]$Path){
 $bytes=[IO.File]::ReadAllBytes($Path)
 for($i=0;$i -le $bytes.Length-16;$i++){
  if($bytes[$i] -eq 0xBD -and $bytes[$i+1] -eq 0x04 -and $bytes[$i+2] -eq 0xEF -and $bytes[$i+3] -eq 0xFE){
   $ms=[BitConverter]::ToUInt32($bytes,$i+8)
   $ls=[BitConverter]::ToUInt32($bytes,$i+12)
   return '{0}.{1}.{2}.{3}' -f ($ms -shr 16),($ms -band 0xffff),($ls -shr 16),($ls -band 0xffff)
  }
 }
 return $null
}
# The fork version comes from the built executable, so program, MSI and file
# name always agree. Test MSIs 1.5.1/1.5.2 were fork test builds of 1.5.0.
$programVersion=PeVersion (Join-Path $BuildDirectory 'Fail2Ban4Win.exe')
if($programVersion -notmatch '^(\d+\.\d+\.\d+)\.0$'){throw "Unexpected program file version: $programVersion"}
$version=$Matches[1]
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if(Test-Path $OutputDirectory){throw 'Use a fresh output directory.'}
$output=[IO.Path]::GetFullPath($OutputDirectory);$payload=Join-Path $output 'payload'
New-Item -ItemType Directory -Path $payload | Out-Null
foreach($file in Get-ChildItem $BuildDirectory -File | Where-Object {$_.Extension -in '.exe','.dll','.config' -and $_.Name -ne 'NLog.config'}){Copy-Item $file.FullName $payload}
if(!(Test-Path (Join-Path $payload 'Fail2Ban4Win.exe'))){throw 'Missing built executable.'}
if(!(Test-Path (Join-Path $BuildDirectory 'third-party-notices/DEPENDENCIES.txt'))){throw 'Dependency license collection is required.'}
Copy-Item (Join-Path $BuildDirectory 'third-party-notices') $payload -Recurse
Copy-Item (Join-Path $root 'License.txt') $payload
Copy-Item (Join-Path $root 'Readme.md') $payload
Copy-Item (Join-Path $PSScriptRoot 'FORK-NOTICE.txt') $payload
Copy-Item (Join-Path $PSScriptRoot 'configuration.ini') $payload
# Keep logging outside Program Files. NLog expands the specialfolder renderer.
$nlog=[IO.File]::ReadAllText((Join-Path $root 'Fail2Ban4Win/Logging/NLog.config')).Replace('value="logs"','value="${specialfolder:folder=CommonApplicationData}/Fail2Ban4Win/logs"')
[IO.File]::WriteAllText((Join-Path $payload 'NLog.config'),$nlog)
$xml=[xml]'<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi" />';$ns=$xml.DocumentElement.NamespaceURI
function E($Parent,$Name,$Attributes){$n=$xml.CreateElement($Name,$ns);foreach($k in $Attributes.Keys){$n.SetAttribute($k,[string]$Attributes[$k])};$null=$Parent.AppendChild($n);return ,$n}
function G([string]$s){$hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($s)));return ([guid]($hash.Substring(0,8)+'-'+$hash.Substring(8,4)+'-5'+$hash.Substring(13,3)+'-8'+$hash.Substring(17,3)+'-'+$hash.Substring(20,12))).ToString()}
$product=E $xml.DocumentElement Product @{Id=(G "product/$version/$Architecture");Name="Fail2Ban4Win $version ($Architecture)";Language='1033';Version=$version;Manufacturer='Fail2Ban4Win contributors';UpgradeCode=(G "upgrade/$Architecture")}
$null=E $product Package @{InstallerVersion='500';Compressed='yes';InstallScope='perMachine'}
# The shared upgrade code lets a release replace the earlier test MSIs.
$null=E $product MajorUpgrade @{DowngradeErrorMessage='A newer Fail2Ban4Win MSI is already installed.'}
$null=E $product Media @{Id='1';Cabinet='payload.cab';EmbedCab='yes'}
$property=E $product Property @{Id='NETFRAMEWORK45'}
$null=E $property RegistrySearch @{Id='NetFrameworkRelease';Root='HKLM';Key='SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full';Name='Release';Type='raw'}
$condition=E $product Condition @{Message='.NET Framework 4.7.2 or newer is required.'};$condition.InnerText='Installed OR NETFRAMEWORK45 >= "#461808"'
$target=E $product Directory @{Id='TARGETDIR';Name='SourceDir'}
$program=E $target Directory @{Id=$(if($Architecture -eq 'x64'){'ProgramFiles64Folder'}else{'ProgramFilesFolder'})}
$install=E $program Directory @{Id='INSTALLFOLDER';Name='Fail2Ban4Win'}
$dataRoot=E $target Directory @{Id='CommonAppDataFolder'}
$data=E $dataRoot Directory @{Id='CONFIGFOLDER';Name='Fail2Ban4Win'}
$feature=E $product Feature @{Id='Main';Title='Fail2Ban4Win disabled service';Level='1'}
$index=0;$directories=@{''=$install}
foreach($file in Get-ChildItem $payload -File -Recurse | Sort-Object FullName){
 $relative=[IO.Path]::GetRelativePath($payload,$file.FullName).Replace([char]92,[char]47)
 $parts=$relative.Split('/');$key=''
 for($i=0;$i -lt $parts.Length-1;$i++){
  $parentKey=$key;$key=($key+'/'+$parts[$i]).TrimStart('/')
  if(!$directories.ContainsKey($key)){$directories[$key]=E $directories[$parentKey] Directory @{Id=('D'+(G $key).Replace('-',''));Name=$parts[$i]}}
 }
 $index++;$id="C$index";$attrs=@{Id=$id;Guid=(G "$Architecture/$relative")}
 if($Architecture -eq 'x64'){$attrs.Win64='yes'}
 $parent=$directories[$key]
 if($file.Name -eq 'configuration.ini'){$parent=$data;$attrs.Permanent='yes'}
 $component=E $parent Component $attrs
 $fileAttributes=@{Id="F$index";Source=$file.FullName;KeyPath='yes'}
 if($file.Extension -in '.exe','.dll'){
  $fileVersion=PeVersion $file.FullName
  if($fileVersion){$fileAttributes.DefaultVersion=$fileVersion}
 }
 $null=E $component File $fileAttributes
 if($file.Name -eq 'Fail2Ban4Win.exe'){
  $service=E $component ServiceInstall @{Id='Service';Name='Fail2Ban4Win';DisplayName='Fail2Ban4Win';Description='Authentication failure monitor; configure before activation.';Type='ownProcess';Start='disabled';Account='LocalSystem';ErrorControl='normal'}
  $null=E $service ServiceDependency @{Id='mpssvc'}
  $null=E $component ServiceControl @{Id='ServiceControl';Name='Fail2Ban4Win';Stop='both';Remove='uninstall';Wait='yes'}
 }
 $null=E $feature ComponentRef @{Id=$id}
}
$wxs=Join-Path $output 'Fail2Ban4Win.wxs';$xml.Save($wxs)
$msi=Join-Path $output "Fail2Ban4Win-$version-windows-$Architecture.msi"
& wixl -a $Architecture -o $msi $wxs
if($LASTEXITCODE -ne 0){throw 'MSI build failed.'}
[IO.File]::WriteAllText("$msi.sha256",(Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant()+"  $([IO.Path]::GetFileName($msi))`n")
Write-Warning 'Finalize with Finalize-WindowsMsi.ps1 on Windows before distribution.'
$msi
