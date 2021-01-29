Start-Transcript -Path "$env:UserProfile\Desktop\PS-Initial-Script.log" -Append -IncludeInvocationHeader -NoClobber
Write-Host 'Preparing things...'
Set-StrictMode -Version 'Latest'
Get-History -Count '1000' | Out-File -FilePath "$env:UserProfile\Desktop\Prior-PS-History.log"
Set-ExecutionPolicy -ExecutionPolicy 'Restricted' -Scope 'LocalMachine' -Force
Invoke-WebRequest -Uri 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' -OutFile "$env:UserProfile\Desktop\FirefoxInstaller.exe" # Downloads Mozilla Firefox
Import-Module -Name '.\Win10_Functions' -Force
Write-Host 'Done.'

Write-Host 'Installing firewall...'
	# Profile settings
		(New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults() # Resets Windows Firewall
		Set-Variable -Name 'NetworkName' -Value (Get-NetConnectionProfile | Select-Object -ExpandProperty 'Name')
		Set-NetConnectionProfile -Name $NetworkName -NetworkCategory 'Public' # Sets network connection to the Public profile
		Remove-NetFirewallRule -Name '*' # Removes default rules
		Set-NetFirewallProfile -All -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Block' -AllowUnicastResponseToMulticast 'False' -NotifyOnListen 'True' -LogMaxSizeKilobytes '32767' -LogAllowed 'True' -LogBlocked 'True' -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
	# Enabled rules
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'ICMP - Echo Reply' -Protocol 'ICMPv4' -ICMPType '8' -RemoteAddress '172.25.37.0/24' -Program 'System'
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Mozilla Firefox - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Mozilla Firefox - DNS' -Protocol 'UDP' -LocalPort '53' -Program "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Svchost' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:SystemRoot\System32\svchost.exe"
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Windows Defender' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:ProgramFiles\Windows Defender\MSASCui.exe"
		New-NetFirewallRule -Direction 'Inbound' -DisplayName 'Windows Update' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:SystemRoot\System32\wuauclt.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x64) - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "$env:ProgramFiles\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x64) - DNS' -Protocol 'UDP' -LocalPort '53' -Program "$env:ProgramFiles\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x86) - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Internet Explorer (x86) - DNS' -Protocol 'UDP' -LocalPort '53' -Program "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Microsoft Edge - HTTP/HTTPS' -Protocol 'TCP' -LocalPort '80','443' -Program "$EdgeDir\MicrosoftEdge.exe"
		New-NetFirewallRule -Direction 'Inbound' -Enabled 'False' -DisplayName 'Microsoft Edge - DNS' -Protocol 'UDP' -LocalPort '53' -Program "$EdgeDir\MicrosoftEdge.exe"

		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'ICMP - Echo Request' -Protocol 'ICMPv4' -ICMPType '8' -Program 'System'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Palo Alto Management' -Protocol 'TCP' -RemoteAddress '172.31.37.2' -RemotePort '443'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test HTTP Service' -Protocol 'TCP' -RemoteAddress '172.25.37.11' -RemotePort '80'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test HTTPS Service' -Protocol 'TCP' -RemoteAddress '172.25.37.97' -RemotePort '443'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test DNS Service' -Protocol 'UDP' -RemoteAddress '172.25.37.23' -RemotePort '53'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test AD/DNS & NTP Services' -Protocol 'UDP' -RemoteAddress '172.25.37.27' -RemotePort '53','123','389'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test AD/DNS Service' -Protocol 'TCP' -RemoteAddress '172.25.37.27' -RemotePort '389','445'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Test POP3 & SMTP' -Protocol 'TCP' -RemoteAddress '172.25.37.39' -RemotePort '25','110'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Drop All Other PA Inside Addresses' -RemoteAddress '172.25.37.0/24' -Action 'Block'
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'DNS' -Protocol 'UDP' -RemotePort '53' -Program "$env:SystemRoot\System32\svchost.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Mozilla Firefox - HTTP/HTTPS' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Malwarebytes - Service' -Protocol 'TCP' -RemotePort '80','443' -Program "\Malwarebytes\Anti-Malware\MBAMService.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Malwarebytes - Tray' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Malwarebytes\Anti-Malware\mbamtray.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Nslookup' -Protocol 'UDP' -RemotePort '53' -Program "$env:SystemRoot\System32\nslookup.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Svchost' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:SystemRoot\System32\svchost.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Windows Defender' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Windows Defender\MSASCui.exe"
		New-NetFirewallRule -Direction 'Outbound' -DisplayName 'Windows Update' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:SystemRoot\System32\wuauclt.exe"
	# Disabled rules
		Set-Variable -Name 'EdgeDir' -Value (Resolve-Path -Path "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_*" | Select-Object -ExpandProperty 'Path')
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Internet Explorer (x64)' -Protocol 'TCP' -RemotePort '80','443' -Program "$env:ProgramFiles\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Internet Explorer (x86)' -Protocol 'TCP' -RemotePort '80','443' -Program "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Microsoft Edge' -Protocol 'TCP' -RemotePort '80','443' -Program "$EdgeDir\MicrosoftEdge.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Nmap' -RemoteAddress '172.25.37.0/24' -Program "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'PowerShell' -Protocol 'TCP' -RemotePort '443' -Program "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
		New-NetFirewallRule -Direction 'Outbound' -Enabled 'False' -DisplayName 'Zenmap' -RemoteAddress '172.25.37.0/24' -Program "${env:ProgramFiles(x86)}\Nmap\zenmap.exe"
		Write-Host 'Done.'

Clear-Caches

Write-Host 'Downloading various programs...'
	Enable-NetFirewallRule -Name 'PowerShell'
	Start-Job -Name 'Malwarebytes' -ScriptBlock {Invoke-WebRequest -Uri 'https://downloads.malwarebytes.com/file/mb3win_43841' -OutFile "$env:UserProfile\Desktop\MalwareBytesInstaller.exe"}
	Start-Job -Name 'CCleaner' -ScriptBlock {Invoke-WebRequest -Uri 'https://download.ccleaner.com/ccsetup558.exe' -OutFile "$env:UserProfile\Desktop\CCleanerInstaller.exe"}
	Start-Job -Name 'Sysinternals' -ScriptBlock {Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SysinternalsSuite.zip' -OutFile "$env:UserProfile\Desktop\Sysinternals.zip"}
	Write-Host 'Done.'

Write-Warning 'Creating a new non-priviledged user...'
	Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds' -Name 'ConsolePrompting' -Value $TRUE
	Set-Variable -Name 'NewUser' -Value (Get-Credential -Message 'Please enter the new non-priviledged user information below.')
	New-LocalUser $NewUser.Username -Password $NewUser.Password
	Add-LocalGroupMember -Group 'Users' -Member $NewUser.Username
	Remove-Variable -Name $NewUser
	Write-Host 'Done.'

Enable-ManualServices

Enable-AutomaticServices

Get-WindowsUpdateLog

Disable-Services

Disable-NetworkConnections

Write-Host 'Correcting registry keys...'
	New-item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Value '1' # Displays hidden files
	New-item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value '0' # Displays file extensions
	New-item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SharingWizardOn' -Value '0' # Disables Sharing Wizard
	net accounts /maxpwage:30 /minpwage:0 /minplen:10 /lockoutthreshold:5 /uniquepw:2 # Sets user password restrictions
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -Value 'UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED.' # Sets login screen MOTD
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -Value 'You must have explicit authorized permission to access or configure this device. Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties. All activities on this device are logged and monitored.' # Sets login screen MOTD
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Value '1' # Disables password display button
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name 'DisablePasswordReveal' -Value '1' # Disables password display button
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Value '1' # Disables password display button
	New-Item -Path 'Registry::HKCU\Software\Policies\Microsoft\Windows\WCN\UI' -Name 'DisableWcnUi' -Value '1' # Disables Windows Connect Now wizard
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP' -Name 'CEIPEnable' -Value '0' # Disables CEIP for apps and generally
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value '0' # Disables CEIP for apps and generally
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\PushToInstall' -Name 'DisablePushToInstall' -Value '1' # Disables pushing of apps for installation from the Windows store
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name 'DisableContentFileUpdates' -Value '1' # Disables pushing of apps for installation from the Windows store
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'AllowProjectionToPC' -Value '0' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'RequirePinForPairing' -Value '1' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\WirelessDisplay' -Name 'EnforcePinBasedPairing' -Value '1' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\PresentationSettings' -Name 'NoPresentationSettings' -Value '1' # Disables projecting (Connect) to the device and requires a pin for pairing
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value '1' # Disables Autorun
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value '255' # Disables Autorun
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCloudSearch' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortanaAboveLock' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Value '0' # Disables Cortana
	New-Item -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Value '1' # Disables Cortana
	New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay' -Value '1' # Disables Autoplay
	New-Item -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Value '506' # Disables Sticky keys
	Write-Host 'Done.'

Write-Host 'Configuring Internet options...'
	# Misc. tabs
		Set-Variable -Name 'Path' -Value 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Scope 'Script'
		Set-Variable -Name 'Path1' -Value 'Registry::HKCU\Software\Microsoft\Internet Explorer' -Scope 'Script'
		New-Item -Path "$Path1\Main" -Name 'Start Page' -Value 'https://google.com' # Home page
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'WarnOnClose' -Value '0' # Warn me when closing multiple tabs: No
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'NetTabPageShow' -Value '1' # When a new tab is opened, open: A blank page
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'PopupsUseNewWindow' -Value '0' # When a pop-up is encountered: Let IE decide
		New-Item -Path "$Path1\TabbedBrowsing" -Name 'ShortcutBehavior' -Value '1' # Open links from other programs in: A new tab
		New-Item -Path $Path1 -Name 'Privacy' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Privacy" -Name 'ClearBrowsingHistoryOnExit' -Value '1' # Delete browsing history on exit: Yes
		New-Item -Path $Path1 -Name 'ContinuousBrowsing' -Value '0' # Delete browsing history on exit: Yes
		New-Item -Path $Path -Name 'SyncMode5' -Value '0' # Check for newer versions of stored pages: Never
		New-Item -Path "$Path\5.0\Cache\Content" -Name "CacheLimit" -Value '8192' # Disk space to use (Website caches): Minimum of 8 mB
		New-Item -Path $Path -Name 'Url History' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Url History" -Name 'DaysToKeep' -Value '0' # Days to keep pages in history: 0
		New-Item -Path $Path1 -Name 'BrowserStorage' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\BrowserStorage" -Name 'IndexedDB' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\BrowserStorage\IndexedDB" -Name 'AllowWebsiteDatabases' -Value '0' # Allow website caches and databases
		New-Item -Path "$Path1\BrowserStorage" -Name 'AppCache' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\BrowserStorage\AppCache" -Name 'AllowWebsiteCaches' -Value '0' # Allow website caches and databases
	# Privacy Tab
		New-Item -Path $Path1 -Name 'Geolocation' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Geolocation" -Name 'BlockAllWebsites' -Value '1' # Never allow websites to request your physical location
		New-Item -Path "$Path1\New Windows" -Name 'PopupMgr' -Value '1' # Turn on Pop-up Blocker
		New-Item -Path "$Path1\New Windows" -Name 'BlockUserInit' -Value '1' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'UseTimerMethod' -Value '0' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'UseHooks' -Value '0' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'AllowHTTPS' -Value '0' # Blocking level: High: Block all pop-ups
		New-Item -Path "$Path1\New Windows" -Name 'BlockControls' -Value '1' # Blocking level: High: Block all pop-ups
		New-Item -Path $Path1 -Name 'Safety' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Safety" -Name 'PrivacIE' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Safety\PrivacIE" -Name 'DisableToolbars' -Value '1' # Disable toolbars and extensions when InPrivate Browsing starts
	# Programs Tab
		New-Item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\{2933BF90-7B36-11D2-B20E-00C04F983E60}\iexplore' -Name 'Flags' -Value '4' #Disable XML DOM Document extension
		New-Item -Path $Path -Name 'Activities' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities" -Name 'Email' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Email" -Name 'live.com' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Email\live.com" -Name 'Enabled' -Value '0' # Disable E-mail with Windows Live accelerator
		New-Item -Path "$Path\Activities" -Name 'Map' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Map" -Name 'bing.com' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Map\bing.com" -Name 'Enabled' -Value '0' # Disable Map with Bing accelerator
		New-Item -Path "$Path\Activities" -Name 'Translate' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Translate" -Name 'microsofttranslator.com' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path\Activities\Translate\microsofttranslator.com" -Name 'Enabled' -Value '0' # Disable Translate with Bing accelerator
	# Advanced tab
		New-Item -Path "$Path1\Main" -Name 'DisableScriptDebuggerIE' -Value 'yes' # Disable script debugging (Internet Explorer): Yes
		New-Item -Path "$Path1\Main" -Name 'Disables Script Debugger' -Value 'yes' # Disable script debugging (Other): Yes
		New-Item -Path "$Path1\Recovery" -Name 'AutoRecover' -Value '2' # Enable automatic crash recovery: No
		New-Item -Path 'Registry::HKCU\Software\Microsoft\FTP' -Name 'Use Web Based FTP' -Value 'yes' # Enable FTP folder view: No
		New-Item -Path "$Path1\Main" -Name 'Enable Browser Extensions' -Value '0' # Enable third-party browser extensions: No
		New-Item -Path 'Registry::HKCU\Software\Microsoft\FTP' -Name 'Use PASV' -Value 'no' # Use Passive FTP: No
		New-Item -Path $Path -Name 'EnableHttp1_1' -Value '0' # Use HTTP 1.1: No
		New-Item -Path $Path -Name 'ProxyHttp1.1' -Value '0' # Use HTTP 1.1 through proxy connections: No
		New-Item -Path $Path -Name 'EnableHTTP2' -Value '1' # Use HTTP2
		New-Item -Path "$Path1\Main" -Name 'FeatureControl' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Main\FeatureControl" -Name 'FEATURE_LOCALMACHINE_LOCKDOWN' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Name 'Settings' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" -Name 'LOCALMACHINE_CD_UNLOCK' -Value '0' # Allow content from CDs...: No
		New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Name 'iexplore.exe' -Value '1' # Allow content from my files...: No
		New-Item -Path $Path1 -Name 'Download' -Type 'Directory' -ErrorAction 'SilentlyContinue'
		New-Item -Path "$Path1\Download" -Name 'RunInvalidSignatures' -Value '0' # Allow software to run if invalid: No
		New-Item -Path "$Path1\Main" -Name 'MixedContentBlockImages' -Value '1' # Block unsecure images with other content: Yes
		New-Item -Path $Path -Name 'CertificateRevocation' -Value '1' # Check for publisher/server's certificate revocation: Yes
		New-Item -Path "$Path1\Download" -Name 'CheckExe' -Value 'yes' # Check for signatures on downloaded programs: Yes
		New-Item -Path "$Path1\Main" -Name 'XMLHTTP' -Value '0' # Enable XMLHTTP support: No
		New-Item -Path "$Path1\PhishingFilter" -Name 'Enabledv9' -Value '1' # Enable Widows Defender SmartScreen: Yes
		New-Item -Path "$Path1\Main" -Name 'DoNotTrack' -Value '1' # Enable Do Not Track requests: Yes
		New-Item -Path $Path -Name 'WarnonBadCertRecving' -Value '1' # Warn about certificate address mismatch: Yes
		New-Item -Path $Path -Name 'WarnonZoneCrossing' -Value '1' # Warn if changing between secure/not secure modes: Yes
		New-Item -Path $Path -Name 'WarnOnPostRedirect' -Value '1' # Warn if POST submittal is redirected...: Yes

Disable-Protocols

Write-Host 'Enabling TLSv1.2...'
	Set-Variable -Name 'Path' -Value 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
	Set-Variable -Name 'Protocol' -Value 'TLS 1.2'
	New-Item -Path $Path -Name $Protocol -Type 'Directory' -ErrorAction 'SilentlyContinue'
	New-Item -Path $Path -Name 'Client' -Type 'Directory' -ErrorAction 'SilentlyContinue'
	New-Item -Path $Path -Name 'Server' -Type 'Directory' -ErrorAction 'SilentlyContinue'
	New-item -Path "$Path\Client" -Name 'DisabledByDefault' -Value '0'
	New-item -Path "$Path\Client" -Name 'Enabled' -Value '1'
	New-item -Path "$Path\Server" -Name 'DisabledByDefault' -Value '0'
	New-item -Path "$Path\Server" -Name 'Enabled' -Value '1'
	New-item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols' -Value '0x800'
	New-item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DefaultSecureProtocols' -Value '0x800'
	New-item -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'SecureProtocols' -Value '0x800'
	New-item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'chUseStrongCrypto' -Value '1'
	New-item -Path 'Registry::HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'chUseStrongCrypto' -Value '1'
	Write-Host 'Done.'

Write-Warning 'Setting UAC level to High...'
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value '2'
	New-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value '1'
	Write-Host 'Done.'

Write-Host 'Removing pre-installed bloatware...'
	[Array]$Apps =
		'Microsoft.3DBuilder',
		'Microsoft.Appconnector',
		'Microsoft.BingFinance',
		'Microsoft.BingNews',
		'Microsoft.BingSports',
		'Microsoft.BingTranslator',
		'Microsoft.BingWeather',
		'Microsoft.FreshPaint',
		'Microsoft.Microsoft3DViewer',
		'Microsoft.MicrosoftOfficeHub',
		'Microsoft.MicrosoftSolitaireCollection',
		'Microsoft.MicrosoftPowerBIForWindows',
		'Microsoft.MinecraftUWP',
		'Microsoft.MicrosoftStickyNotes',
		'Microsoft.NetworkSpeedTest',
		'Microsoft.Office.OneNote',
		'Microsoft.OneConnect',
		'Microsoft.People',
		'Microsoft.Print3D',
		'Microsoft.SkypeApp',
		'Microsoft.Wallet',
		'Microsoft.WindowsAlarms',
		'Microsoft.WindowsCamera',
		'Microsoft.windowscommunicationsapps',
		'Microsoft.WindowsMaps',
		'Microsoft.WindowsPhone',
		'Microsoft.WindowsSoundRecorder',
		'Microsoft.XboxApp',
		'Microsoft.XboxGameOverlay',
		'Microsoft.XboxIdentityProvider',
		'Microsoft.XboxSpeechToTextOverlay',
		'Microsoft.ZuneMusic',
		'Microsoft.ZuneVideo',
		'Microsoft.CommsPhone',
		'Microsoft.ConnectivityStore',
		'Microsoft.GetHelp',
		'Microsoft.Getstarted',
		'Microsoft.Messaging',
		'Microsoft.Office.Sway',
		'Microsoft.OneConnect',
		'Microsoft.WindowsFeedbackHub',
		'Microsoft.Microsoft3DViewer',
		'Microsoft.BingFoodAndDrink',
		'Microsoft.BingTravel',
		'Microsoft.BingHealthAndFitness',
		'Microsoft.WindowsReadingList',
		'9E2F88E3.Twitter',
		'PandoraMediaInc.29680B314EFC2',
		'Flipboard.Flipboard',
		'ShazamEntertainmentLtd.Shazam',
		'king.com.CandyCrushSaga',
		'king.com.CandyCrushSodaSaga',
		'king.com.*',
		'ClearChannelRadioDigital.iHeartRadio',
		'4DF9E0F8.Netflix',
		'6Wunderkinder.Wunderlist',
		'Drawboard.DrawboardPDF',
		'2FE3CB00.PicsArt-PhotoStudio',
		'D52A8D61.FarmVille2CountryEscape',
		'TuneIn.TuneInRadio',
		'GAMELOFTSA.Asphalt8Airborne',
		'TheNewYorkTimes.NYTCrossword',
		'DB6EA5DB.CyberLinkMediaSuiteEssentials',
		'Facebook.Facebook',
		'flaregamesGmbH.RoyalRevolt2',
		'Playtika.CaesarsSlotsFreeCasino',
		'A278AB0D.MarchofEmpires',
		'KeeperSecurityInc.Keeper',
		'ThumbmunkeysLtd.PhototasticCollage',
		'XINGAG.XING',
		'89006A2E.AutodeskSketchBook',
		'D5EA27B7.Duolingo-LearnLanguagesforFree',
		'46928bounde.EclipseManager',
		'ActiproSoftwareLLC.562882FEEB491',
		'DolbyLaboratories.DolbyAccess',
		'SpotifyAB.SpotifyMusic',
		'A278AB0D.DisneyMagicKingdoms',
		'WinZipComputing.WinZipUniversal',
		'Microsoft.ScreenSketch',
		'Microsoft.XboxGamingOverlay',
		'Microsoft.YourPhone'
	Foreach ($App in $Apps) {
		Get-AppxPackage -Name $App | Remove-AppxPackage -AllUsers -ErrorAction 'SilentlyContinue'
	}
	Get-Process | Where {$_.Name -Like '*onedrive*'} | Set-Variable -Name 'OneDrive' -Value "$_"
	Stop-Process $OneDrive
	$env:SystemRoot\SysWOW64\OneDriveSetup.exe /uninstall
	Write-Host 'Done.'

Write-Host 'Removing Microsoft telemetry...'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\AppID' -TaskName 'SmartScreenSpecific'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Application Experience' -TaskName 'Microsoft Compatibility Appraiser'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Application Experience' -TaskName 'ProgramDataUpdater'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Autochk' -TaskName 'Proxy'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program' -TaskName 'Consolidator'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program' -TaskName 'KernelCeipTask'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program' -TaskName 'UsbCeip'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\DiskDiagnostic' -TaskName 'Microsoft-Windows-DiskDiagnosticDataCollector'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\NetTrace' -TaskName 'GatherNetworkInfo'
	Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Error Reporting' -TaskName 'QueueReporting'
	Write-Host 'Done.'

Write-Warning 'Disabling Optional Features; this may take a while...'
	[Array]$Features =
		'LegacyComponents',
		'DirectPlay',
		'SimpleTCP',
		'SNMP',
		'WMISnmpProvider',
		'MicrosoftWindowsPowerShellV2Root',
		'MicrosoftWindowsPowerShellV2',
		'Windows-Identity-Foundation',
		'Microsoft-Windows-Subsystem-Linux',
		'WorkFolders-Client',
		'MediaPlayback',
		'WindowsMediaPlayer',
		'IIS-WebServerRole',
		'IIS-WebServer',
		'IIS-CommonHttpFeatures',
		'IIS-HttpErrors',
		'IIS-HttpRedirect',
		'IIS-ApplicationDevelopment',
		'IIS-NetFxExtensibility',
		'IIS-NetFxExtensibility45',
		'IIS-HealthAndDiagnostics',
		'IIS-HttpLogging',
		'IIS-LoggingLibraries',
		'IIS-RequestMonitor',
		'IIS-HttpTracing',
		'IIS-Security',
		'IIS-URLAuthorization',
		'IIS-RequestFiltering',
		'IIS-IPSecurity',
		'IIS-Performance',
		'IIS-HttpCompressionDynamic',
		'IIS-WebServerManagementTools',
		'IIS-ManagementScriptingTools',
		'IIS-IIS6ManagementCompatibility',
		'IIS-Metabase',
		'WAS-WindowsActivationService',
		'WAS-ProcessModel',
		'WAS-NetFxEnvironment',
		'WAS-ConfigurationAPI',
		'IIS-HostableWebCore',
		'WCF-HTTP-Activation',
		'WCF-NonHTTP-Activation',
		'WCF-Services45',
		'WCF-TCP-Activation45',
		'WCF-Pipe-Activation45',
		'WCF-MSMQ-Activation45',
		'WCF-TCP-PortSharing45',
		'IIS-StaticContent',
		'IIS-DefaultDocument',
		'IIS-DirectoryBrowsing',
		'IIS-WebDAV',
		'IIS-WebSockets',
		'IIS-ApplicationInit',
		'IIS-ASPNET',
		'IIS-ASPNET45',
		'IIS-ASP',
		'IIS-CGI',
		'IIS-ISAPIExtensions',
		'IIS-ISAPIFilter',
		'IIS-ServerSideIncludes',
		'IIS-CustomLogging',
		'IIS-BasicAuthentication',
		'IIS-HttpCompressionStatic',
		'IIS-ManagementConsole',
		'IIS-ManagementService',
		'IIS-WMICompatibility',
		'IIS-LegacyScripts',
		'IIS-LegacySnapIn',
		'IIS-FTPServer',
		'IIS-FTPSvc',
		'IIS-FTPExtensibility',
		'MSMQ-Container',
		'MSMQ-Server',
		'MSMQ-Triggers',
		'MSMQ-HTTP',
		'MSMQ-Multicast',
		'MSMQ-DCOMProxy',
		'NetFx4-AdvSrvs',
		'NetFx4Extended-ASPNET45',
		'Printing-PrintToPDFServices-Features',
		'Printing-XPSServices-Features',
		'RasRip',
		'MSRDC-Infrastructure',
		'SMB1Protocol',
		'SMB1Protocol-Client',
		'SMB1Protocol-Server',
		'TelnetClient',
		'TFTP',
		'Windows-Defender-Default-Definitions',
		'Printing-Foundation-Features',
		'FaxServicesClientPackage',
		'Printing-Foundation-InternetPrinting-Client',
		'Printing-Foundation-LPRPortMonitor',
		'TIFFIFilter',
		'Internet-Explorer-Optional-amd64'
	Foreach ($Feature in $Features) {
		Disable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -ErrorAction 'SilentlyContinue'
	}

Wait-Job -Name 'CCleaner', 'Malwarebytes', 'Sysinternals'
Disable-NetFirewallRule -Name 'PowerShell'
Start-CleanUp
