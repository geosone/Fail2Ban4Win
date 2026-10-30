# Windows INI / MSI test build

This fork is based on Aldaviva/Fail2Ban4Win development commit
`aea9e9132ddafdfce843029cbefbf2fb3bf7b7fb`. Apache-2.0 applies; see License.txt.
The upstream assembly is developing 1.5.0. These packages are fork test builds,
not an official upstream 1.5.0 release. Runtime remains .NET Framework 4.7.2+.
.NET 10 is not required by this program.

## Settings and behavior

MSI binaries install under Program Files/Fail2Ban4Win, with a quoted service
path and the Windows Firewall service dependency. The service starts disabled.
Settings use `%ProgramData%\Fail2Ban4Win\configuration.ini`; the original
JSON loader remains a fallback for existing installations without that INI.
Configuration remains on repair and uninstall. Logs go to ProgramData too.
User-created config, logs and plugin files are not deleted blindly.

The shipped configuration is `isDryRun=true`, no event selectors, individual
IP addresses (banSubnetBits=0), reserved-subnet whitelist and no startup
unban-all. Do not enable bans before configuring and testing selectors for
trusted authentication events. Upstream handles Windows Event Log. Mystic
text-log ingestion is still a separate adapter task; installing this package
alone does not protect Mystic's Telnet/SSH logins.

The service currently uses LocalSystem, as the upstream program does.
Unprivileged users must not be able to modify configuration, plugins or
binaries. The MSI test validates the installed INI ACL. Runtime plugin loading
requires protected plugin directories. Actual ban/unban, IPv6 behavior and
upgrade migration need separate qualification. Uninstall does not currently
perform a dedicated cleanup of bans created during an earlier active setup;
remove owned rules deliberately before uninstalling an actively banning setup.

## Build

Run `Build-Windows.ps1` with VS2022 MSBuild and net472 reference assemblies.
The fork fixes current dependency API incompatibilities: protected plugin
constructor, long-delay call and string checks compatible with the runner's
compiler. The workflow builds Debug for unit tests, then a Release payload,
and collects dependency notices from matching restored NuGet packages.
The WindowsFirewallHelper package omitted its MIT license text; we include
it from the exact 2.2.0.86 source tag. Provenance is in packaging/third-party.

On Linux, with PowerShell 7 and wixl:

```powershell
./New-WindowsMsi.ps1 -BuildDirectory <Release-output> -OutputDirectory <new-directory> -Architecture x64
```

Repeat for x86. The program is managed AnyCPU; the MSI profile selects its
Program Files location and Windows Installer component architecture.
Finalize each candidate with the Windows Installer API on Windows:

```powershell
./Finalize-WindowsMsi.ps1 -MsiPath <candidate.msi>
# After that PowerShell process exits:
Get-FileHash <candidate.msi> -Algorithm SHA256
```

The native finalizer sets NeverOverwrite for the configuration component
because wixl 0.106 ignores that WiX attribute. Hash after process exit so COM
record/view lifetimes cannot keep the MSI locked while reading its checksum.
MSI version 1.5.1 means the fork's 1.5.0 test build 1, not an upstream version.
Uninstall older test packages before replacing them; automatic upgrade is
not qualified. x86 and x64 packages share the same service name and must not
be installed side by side.

## Validation

GitHub run 41050728831 built the final program payload and passed 50 tests.
The earlier payload and final MSI candidates undergo Windows 10 Pro 22H2
x86/x64 install/start/stop/repair/uninstall tests via Test-WindowsMsi.ps1.
The test refuses existing service/configuration, verifies disabled startup,
quoted executable path, INI permissions, configuration preservation and no
change to owned firewall rules. Test activation remains dry-run only.

Release binaries, licenses, matching source and SHA256 are provided as test
packages at https://bbs.disconnected-by-peer.at/windows/.
