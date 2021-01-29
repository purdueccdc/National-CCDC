# Created by Zamanry, 01/09/2019
# Functioning as of 02/01/2019
# These assumptions are made:
# 	Script is ran from priviledged user's Desktop
# 		Ex: C:\Users\Administrator\Desktop\Win8.1_Domain.ps1
# 	Ethernet connection
# 	Static IP addressing
# 	Domain connection
# 	No printing
# 	No wireless connections
# 	No Windows Store
# 	No scored services
# 	Only needs an internet connection
# Issues:
# 	Create custom MSI package installations (feature request)

# Downloads Mozilla Firefox
	#$Job = Start-Job { Invoke-WebRequest -Uri 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US' -OutFile "./FirefoxInstaller.exe" }

$Inside = '172.20.240.0/22'
$Phantom = '172.20.240.10'
$BIND = '172.20.242.10'
$AD = '172.20.242.200'
$Splunk = '172.20.241.20'

# Builds firewall
	Write-Host 'Installing firewall...'
		# Resetting, etc.
			$NetworkName = Get-NetConnectionProfile | Select-Object -ExpandProperty 'Name'
			Set-NetConnectionProfile -Name "$NetworkName" -NetworkCategory 'Public' # Sets network connection to the Public profile
			netsh advfirewall reset
			netsh advfirewall firewall delete rule name="all"
		# Logging, profiles, etc.
			netsh advfirewall set allprofiles logging maxfilesize "32767"
			netsh advfirewall set allprofiles logging allowedconnections enable
			netsh advfirewall set allprofiles logging droppedconnections enable
			netsh advfirewall set allprofiles firewallpolicy 'blockinbound,blockoutbound'
			netsh advfirewall set allprofiles settings inboundusernotification enable
			netsh advfirewall set allprofiles settings unicastresponsetomulticast disable
			netsh advfirewall set allprofiles logging filename "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
			netsh advfirewall set allprofiles state on
		# Inbound rules
			netsh advfirewall firewall add rule name="ICMP-Echo-Reply" dir="in" action="allow" program="System" protocol="ICMPv4:8,any" remoteip=$Inside
			netsh advfirewall firewall add rule name="Internet-Explorer-(x64)-HTTP/S" dir="in" action="allow" program="%ProgramFiles%\Internet Explorer\iexplore.exe" protocol="TCP" localport="80,443"
			netsh advfirewall firewall add rule name="Internet-Explorer-(x64)-DNS" dir="in" action="allow" program="%ProgramFiles%\Internet Explorer\iexplore.exe" protocol="UDP" localport="53"
			netsh advfirewall firewall add rule name="Internet-Explorer-(x86)-HTTP/S" dir="in" action="allow" program="%ProgramFiles% (x86)\Internet Explorer\iexplore.exe" protocol="TCP" localport="80,443"
			netsh advfirewall firewall add rule name="Internet-Explorer-(x86)-DNS" dir="in" action="allow" program="%ProgramFiles% (x86)\Internet Explorer\iexplore.exe" protocol="UDP" localport="53"
			netsh advfirewall firewall add rule name="Mozilla-Firefox-(x64)-DNS" dir="in" action="allow" program="%ProgramFiles%\Mozilla Firefox\firefox.exe" protocol="UDP" localport="53"
			netsh advfirewall firewall add rule name="Mozilla-Firefox-(x86)-DNS" dir="in" action="allow" program="%ProgramFiles% (x86)\Mozilla Firefox\firefox.exe" protocol="UDP" localport="53"
			netsh advfirewall firewall add rule name="Mozilla-Firefox-(x64)-HTTP/S" dir="in" action="allow" program="%ProgramFiles%\Mozilla Firefox\firefox.exe" protocol="TCP" localport="80,443"
			netsh advfirewall firewall add rule name="Mozilla-Firefox-(x86)-HTTP/S" dir="in" action="allow" program="%ProgramFiles% (x86)\Mozilla Firefox\firefox.exe" protocol="TCP" localport="80,443"
			netsh advfirewall firewall add rule name="Splunk-Forwarder" dir="in" action="allow" protocol="TCP" localport="8089" remoteip=$Splunk
			netsh advfirewall firewall add rule name="Svchost" dir="in" action="allow" program="%SystemRoot%\System32\svchost.exe" protocol="TCP" localport="80,443"
			netsh advfirewall firewall add rule name="Windows-Defender" dir="in" action="allow" program="%ProgramFiles%\Windows Defender\MSASCui.exe" protocol="TCP" localport="80,443"
			netsh advfirewall firewall add rule name="Windows-Update" dir="in" action="allow" program="%SystemRoot%\System32\wuauclt.exe" protocol="TCP" localport="80,443" service="wuauserv"
		# Outbound rules
			netsh advfirewall firewall add rule name="DNS" dir="out" action="allow" program="%SystemRoot%\System32\svchost.exe" protocol="UDP" remoteport="53" remoteip=$AD
			netsh advfirewall firewall add rule name="ICMP-Echo-Request" dir="out" action="allow" program="System" protocol="ICMPv4:8,any"
			netsh advfirewall firewall add rule name="Internet-Explorer-(x64)-HTTP/S" dir="out" action="allow" program="%ProgramFiles%\Internet Explorer\iexplore.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Internet-Explorer-(x86)-HTTP/S" dir="out" action="allow" program="%ProgramFiles% (x86)\Internet Explorer\iexplore.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Malwarebytes-Service" dir="out" action="allow" program="%ProgramFiles%\Malwarebytes\Anti-Malware\MBAMService.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Malwarebytes-Tray" dir="out" action="allow" program="%ProgramFiles%\Malwarebytes\Anti-Malware\mbamtray.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Mozilla-Firefox-(x64)-HTTP/S" dir="out" action="allow" program="%ProgramFiles%\Mozilla Firefox\firefox.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Mozilla-Firefox-(x86)-HTTP/S" dir="out" action="allow" program="%ProgramFiles% (x86)\Mozilla Firefox\firefox.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Nslookup" dir="out" action="allow" program="%SystemRoot%\System32\nslookup.exe" protocol="UDP" remoteport="53"
			netsh advfirewall firewall add rule name="NTP" dir="out" action="allow" program="%SystemRoot%\System32\svchost.exe" protocol="UDP" remoteport="123" service="W32Time" remoteip=$AD
			netsh advfirewall firewall add rule name="Splunk-Forwarder" dir="out" action="allow" protocol="TCP" remoteport="8000,8089,9997" remoteip=$Splunk
			netsh advfirewall firewall add rule name="Splunk-Phantom" dir="out" action="allow" protocol="TCP" remoteport="443" remoteip=$Phantom
			netsh advfirewall firewall add rule name="Svchost" dir="out" action="allow" program="%SystemRoot%\System32\svchost.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Windows-Defender" dir="out" action="allow" program="%ProgramFiles%\Windows Defender\MSASCui.exe" protocol="TCP" remoteport="80,443"
			netsh advfirewall firewall add rule name="Windows-Update" dir="out" action="allow" program="%SystemRoot%\System32\wuauclt.exe" protocol="TCP" remoteport="80,443" service="wuauserv"
			# Domain connection
				netsh advfirewall firewall add rule name="Global-Catalog" dir="out" action="allow" program="%SystemRoot%\System32\lsass.exe" protocol="TCP" remoteport="3268" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="Kerberos" dir="out" action="allow" program="%SystemRoot%\System32\lsass.exe" protocol="TCP" remoteport="88" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="Kerberos-Password-Change" dir="out" action="allow" program="%SystemRoot%\System32\lsass.exe" protocol="TCP" remoteport="464" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="LDAP-TCP-LSASS" dir="out" action="allow" program="%SystemRoot%\System32\lsass.exe" protocol="TCP" remoteport="389" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="LDAP-UDP-LSASS" dir="out" action="allow" program="%SystemRoot%\System32\lsass.exe" protocol="UDP" remoteport="389" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="LDAP-TCP-Svchost" dir="out" action="allow" program="%SystemRoot%\System32\svchost.exe" protocol="TCP" remoteport="389" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="LDAP-UDP-Svchost" dir="out" action="allow" program="%SystemRoot%\System32\svchost.exe" protocol="UDP" remoteport="389" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="RPC-Endpoint-Mapper" dir="out" action="allow" program="any" protocol="TCP" remoteport="135,1024-5000" remoteip=$AD profile="domain"
				netsh advfirewall firewall add rule name="SMB" dir="out" action="allow" program="System" protocol="TCP" remoteport="445" remoteip=$AD profile="domain"
			# Miscellaneous rules disabled by default
				# Inbound rules
					# N/A
				# Outbound rules
					netsh advfirewall firewall add rule name="Nmap" dir="out" action="allow" program="%ProgramFiles% (x86)\Nmap\nmap.exe" protocol="any" enable="no"
					netsh advfirewall firewall add rule name="PowerShell" dir="out" action="allow" program="%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" protocol="TCP" remoteport="443" profile="any" enable="no"
					netsh advfirewall firewall add rule name="Zenmap" dir="out" action="allow" program="%ProgramFiles% (x86)\Nmap\zenmap.exe" protocol="any" profile="any" enable="no"
			Write-Host 'Done.'

# Flushes caches (DNS, ARP, NetBIOS, routes, hosts)
	Write-Host 'Flushing caches...'
		Ipconfig /flushdns
		netsh interface ipv4 delete arpcache
		netsh interface ipv4 delete destinationcache
		netsh interface ipv4 delete neighbors
		$Adapter = Get-NetAdapter -Name 'Ethernet*' -Physical | Select-Object -ExpandProperty 'Name'
		netsh interface ipv4 delete winsservers "$Adapter" all
		$Drive = (Get-Location).Drive.Name
		$Drive = "${Drive}:"
		Remove-Item -Path "$Drive\Windows\System32\drivers\etc\hosts" -Force
		New-Item -Path "$Drive\Windows\System32\drivers\etc" -Name 'hosts' -ItemType 'file' -Value '# This file has been flushed by Zamanry.' -Force
		$Drive = "$NULL"
		Write-Host 'Done.'

# Enables services
	Write-Host 'Enabling critical services...'
		$Services = 'W32Time', 'wuauserv'
		$Index = 0
		$CrntService = $Services[$Index]
		Do {
			Set-Service -Name "$CrntService" -StartupType 'Manual'
			$Index++
			$CrntService = $Services[$Index]
		} Until ($CrntService -eq $NULL)
		$Services = 'BITS', 'TrustedInstaller', 'EventLog', 'wscsvc'
		$Index = 0
		$CrntService = $Services[$Index]
		Do {
			Set-Service -Name "$CrntService" -StartupType 'Automatic' -Status 'Running'
			$Index++
			$CrntService = $Services[$Index]
		} Until ($CrntService -eq $NULL)
		Write-Host 'Done.'

# Disables services
	Write-Host 'Disabling unnecessary services...'
		$Services =
			'ALG',
			'AppXSvc',
			'BDESVC',
			'bthserv',
			'PeerDistSvc',
			'CertPropSvc',
			'Browser',
			'DeviceAssociationService',
			#'DeviceInstall',
			#'DsmSvc',
			#'DPS',
			'WdiServiceHost',
			'WdiSystemHost',
			'TrkWks',
			'Eaphost',
			'WPCSvc',
			'Fax',
			'fdPHost',
			'FDResPub',
			'HomeGroupListener',
			'HomeGroupProvider',
			'hidserv',
			'vmickvpexchange',
			'vmicguestinterface',
			'vmicshutdown',
			'vmicheartbeat',
			'vmicrdv',
			'vmictimesync',
			'vmicvss',
			'IKEEXT',
			'SharedAccess',
			'IEEtwCollectorService',
			'iphlpsvc',
			'PolicyAgent',
			#'lltdsvc',
			'wlidsvc',
			'MSiSCSI',
			'MsKeyboardFilter',
			'NetTcpPortSharing',
			'napagent',
			#'NcdAutoSetup',
			'NcbService',
			'PNRPsvc',
			'p2psvc',
			'p2pimsvc',
			#'PerfHost',
			#'pla',
			'PNRPAutoReg',
			'WPDBusEnum',
			'Spooler',
			'PrintNotify',
			'wercplsupport',
			'QWAVE',
			'RasAuto',
			'RasMan',
			'SessionEnv',
			'TermService',
			'UmRdpService',
			'RpcLocator',
			'RemoteRegistry',
			'RemoteAccess',
			'SstpSvc',
			'SensrSvc',
			'ShellHWDetection',
			'SCardSvr',
			'ScDeviceEnum',
			'SCPolicySvc',
			'SNMPTRAP',
			'SSDPSRV',
			'WiaRpc',
			'lmhosts',
			'TapiSrv',
			'Themes',
			#'upnphost',
			'WebClient',
			'Audiosrv',
			'AudioEndpointBuilder',
			'WbioSrvc',
			'wcncsvc',
			'WerSvc',
			'stisvc',
			'lfsvc',
			'WMPNetworkSvc',
			'WinRM',
			'WinHttpAutoProxySvc',
			'WlanSvc',
			'wmiApSrv',
			'workfolderssvc',
			'WwanSvc'
		$Index = 0
		$CrntService = $Services[$Index]
		Do {
			Set-Service -Name "$CrntService" -StartupType 'Disabled'
			Stop-Service -Name "$CrntService" -Force
			$Index++
			$CrntService = $Services[$Index]
		} Until ($CrntService -eq $NULL)
		Write-Host 'Done.'

# Disables network connections
	Write-Host 'Disabling unnecessary network connections...'
		New-Item -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name 'DisabledComponents' -Value '0xFF' # Disables IPv6 completely
		Get-NetAdapter -Name "*" | Set-DNSClient -RegisterThisConnectionsAddress $FALSE # Disables 'Register this connection's addresses in DNS'
		# Unchecks items on Ethernet adapter
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp" # Microsoft LLDP Protocol Driver
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_implat" # Microsoft Network Adapter Multiplexor Protocol
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio" # Link-Layer Topology Discovery Mapper I/O Driver
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6" # Internet Protocol Version 6 (TCP/IPv6)
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server" # File and Printer Sharing for Micorsoft Networks
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr" # Link-Layer Topology Discovery Responder
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient" # Client for Microsoft Networks
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer" # QoS a Scheduler
			$Adapter = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "ipenabled = 'true'"
			$Adapter.SetTCPIPNetBIOS(2) # Disables NetBIOS over TCP/IP
			$AdapterClass = Get-WmiObject -List Win32_NetworkAdapterConfiguration
			$AdapterClass.EnableWINS($FALSE,$FALSE) # Disables WINS
			$Adapter, $AdapterClass = "$NULL"
			netsh Interface IPv4 Set Global mldlevel=none # Disables IGMPLevel
			New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\DirectplayNATHelp\DPNHUPnP" -Name 'UPnPMode' –Value '2' # Disables UPnP
			New-Item -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name 'fAllowToGetHelp' –Value '0' # Disables Remote Assistance
			New-Item -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name 'fDenyTSConnections' –Value '1' # Disables Remote Desktop
			Write-Host 'Done.'

# Configures random options
	Write-Host 'Correcting registry keys...'
		New-item -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name 'Hidden' -Value '1' # Displays hidden files
		New-item -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name 'HideFileExt' -Value '0' # Displays file extensions
		New-item -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name 'SharingWizardOn' -Value '0' # Disables Sharing Wizard
		New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers" -Name '1' -Value '45.33.48.4' # Configures an NTP address
		New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers" -Name '(Default)' -Value '1' # Enables an NTP address
		w32tm /resync /force # Restarts Windows Time
		Write-Host 'Done.'

# Configures Internet options
	Write-Host 'Configuring Internet options...'
		# Misc. tabs
			$Path = 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
			$Path1 = 'Registry::HKCU\Software\Microsoft\Internet Explorer'
			New-Item -Path "$Path1\Main" -Name 'Start Page' -Value 'https://google.com' # Home page
			New-Item -Path "$Path1\TabbedBrowsing" -Name 'WarnOnClose' -Value '0' # Warn me when closing multiple tabs: No
			New-Item -Path "$Path1\TabbedBrowsing" -Name 'NetTabPageShow' -Value '1' # When a new ta is opened, open: A blank page
			New-Item -Path "$Path1\TabbedBrowsing" -Name 'PopupsUseNewWindow' -Value '0' # When a pop-up is encountered: Let IE decide
			New-Item -Path "$Path1\TabbedBrowsing" -Name 'ShortcutBehavior' -Value '1' # Open links from other programs in: A new tab
			New-Item -Path "$Path1" -Name 'Privacy' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Privacy" -Name 'ClearBrowsingHistoryOnExit' -Value '1' # Delete browsing history on exit: Yes
			New-Item -Path "$Path1" -Name 'ContinuousBrowsing' -Value '0' # Delete browsing history on exit: Yes
			New-Item -Path "$Path" -Name 'SyncMode5' -Value '0' # Check for newer versions of stored pages: Never
			New-Item -Path "$Path\5.0\Cache\Content" -Name "CacheLimit" -Value '8192' # Disk space to use (Website caches): Minimum of 8 mB
			New-Item -Path "$Path" -Name 'Url History' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path\Url History" -Name 'DaysToKeep' -Value '0' # Days to keep pages in history: 0
			New-Item -Path "$Path1" -Name 'BrowserStorage' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\BrowserStorage" -Name 'IndexedDB' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\BrowserStorage\IndexedDB" -Name 'AllowWebsiteDatabases' -Value '0' # Allow website caches and databases
			New-Item -Path "$Path1\BrowserStorage" -Name 'AppCache' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\BrowserStorage\AppCache" -Name 'AllowWebsiteCaches' -Value '0' # Allow website caches and databases
		# Privacy Tab
			New-Item -Path "$Path1" -Name 'Geolocation' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Geolocation" -Name 'BlockAllWebsites' -Value '1' # Never allow websites to request your physical location
			New-Item -Path "$Path1\New Windows" -Name 'PopupMgr' -Value '1' # Turn on Pop-up Blocker
			New-Item -Path "$Path1\New Windows" -Name 'BlockUserInit' -Value '1' # Blocking level: High: Block all pop-ups
			New-Item -Path "$Path1\New Windows" -Name 'UseTimerMethod' -Value '0' # Blocking level: High: Block all pop-ups
			New-Item -Path "$Path1\New Windows" -Name 'UseHooks' -Value '0' # Blocking level: High: Block all pop-ups
			New-Item -Path "$Path1\New Windows" -Name 'AllowHTTPS' -Value '0' # Blocking level: High: Block all pop-ups
			New-Item -Path "$Path1\New Windows" -Name 'BlockControls' -Value '1' # Blocking level: High: Block all pop-ups
			New-Item -Path "$Path1" -Name 'Safety' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Safety" -Name 'PrivacIE' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Safety\PrivacIE" -Name 'DisableToolbars' -Value '1' # Disable toolbars and extensions when InPrivate Browsing starts
		# Programs Tab
			New-Item -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\{2933BF90-7B36-11D2-B20E-00C04F983E60}\iexplore" -Name 'Flags' -Value '4' #Disable XML DOM Document extension
			New-Item -Path "$Path" -Name 'Activities' -Type 'Directory' -ErrorAction 'SilentlyContinue'
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
			New-Item -Path "Registry::HKCU\Software\Microsoft\FTP" -Name 'Use Web Based FTP' -Value 'yes' # Enable FTP folder view: No
			New-Item -Path "$Path1\Main" -Name 'Enable Browser Extensions' -Value '0' # Enable third-party browser extensions: No
			New-Item -Path "Registry::HKCU\Software\Microsoft\FTP" -Name 'Use PASV' -Value 'no' # Use Passive FTP: No
			New-Item -Path "$Path" -Name 'EnableHttp1_1' -Value '0' # Use HTTP 1.1: No
			New-Item -Path "$Path" -Name 'ProxyHttp1.1' -Value '0' # Use HTTP 1.1 through proxy connections: No
			New-Item -Path "$Path" -Name 'EnableHTTP2' -Value '1' # Use HTTP2
			New-Item -Path "$Path1\Main" -Name 'FeatureControl' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Main\FeatureControl" -Name 'FEATURE_LOCALMACHINE_LOCKDOWN' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Name 'Settings' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" -Name 'LOCALMACHINE_CD_UNLOCK' -Value '0' # Allow content from CDs...: No
			New-Item -Path "$Path1\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN" -Name 'iexplore.exe' -Value 1 # Allow content from my files...: No
			New-Item -Path "$Path1" -Name 'Download' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path1\Download" -Name 'RunInvalidSignatures' -Value '0' # Allow software to run if invalid: No
			New-Item -Path "$Path1\Main" -Name 'MixedContentBlockImages' -Value '1' # Block unsecure images with other content: Yes
			New-Item -Path "$Path" -Name 'CertificateRevocation' -Value '1' # Check for publisher/server's certificate revocation: Yes
			New-Item -Path "$Path1\Download" -Name 'CheckExe' -Value 'yes' # Check for signatures on downloaded programs: Yes
			New-Item -Path "$Path1\Main" -Name 'XMLHTTP' -Value '0' # Enable XMLHTTP support: No
			New-Item -Path "$Path1\PhishingFilter" -Name 'Enabledv9' -Value '1' # Enable Widows Defender SmartScreen: Yes
			New-Item -Path "$Path1\Main" -Name 'DoNotTrack' -Value '1' # Enable Do Not Track requests: Yes
			New-Item -Path "$Path" -Name 'WarnonBadCertRecving' -Value '1' # Warn about certificate address mismatch: Yes
			New-Item -Path "$Path" -Name 'WarnonZoneCrossing' -Value '1' # Warn if changing between secure/not secure modes: Yes
			New-Item -Path "$Path" -Name 'WarnOnPostRedirect' -Value '1' # Warn if POST submittal is redirected...: Yes
			$Path1 = "$NULL"

# Disables outdated protocols:
	Write-Host 'Disabling outdated protocols...'
		$Path = 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
		Function DisableProtocol {
			New-Item -Path "$Path" -Name "$Protocol" -Type 'Directory' -ErrorAction 'SilentlyContinue'
			$Path = "$Path\$Protocol"
			New-Item -Path "$Path" -Name 'Client' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path" -Name 'Server' -Type 'Directory' -ErrorAction 'SilentlyContinue'
			New-Item -Path "$Path\Client" -Name 'DisabledByDefault' -Value '1'
			New-Item -Path "$Path\Client" -Name 'Enabled' -Value '0'
			New-Item -Path "$Path\Server" -Name 'DisabledByDefault' -Value '1'
			New-Item -Path "$Path\Server" -Name 'Enabled' -Value '0'
		}
		$Protocols = 'DTLS 1.0', 'PCT 1.0', 'SSL 2.0', 'SSL 3.0', 'TLS 1.0'
		$Index = 0
		$Protocol = $Protocols[$Index]
		Do {
			DisableProtocol
			$Index++
			$Protocol = $Protocols[$Index]
		} Until ($Protocol -eq $NULL)
		Write-Host 'Done.'

# Enables TLS 1.2
	# Write-Host 'Enabling TLS 1.2...'
	# 	$Protocol = 'TLS 1.2'
	# 	New-Item -Path "$Path" -Name "$Protocol" -Type 'Directory' -ErrorAction 'SilentlyContinue'
	# 	New-Item -Path "$Path" -Name 'Client' -Type 'Directory' -ErrorAction 'SilentlyContinue'
	# 	New-Item -Path "$Path" -Name 'Server' -Type 'Directory' -ErrorAction 'SilentlyContinue'
	# 	New-item -Path "$Path\Client" -Name 'DisabledByDefault' -Value '0'
	# 	New-item -Path "$Path\Client" -Name 'Enabled' -Value '1'
	# 	New-item -Path "$Path\Server" -Name 'DisabledByDefault' -Value '0'
	# 	New-item -Path "$Path\Server" -Name 'Enabled' -Value '1'
	# 	New-item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name 'DefaultSecureProtocols' -Value '0x800'
	# 	New-item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name 'DefaultSecureProtocols' -Value '0x800'
	# 	New-item -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name 'SecureProtocols' -Value '0x800'
	# 	New-item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name 'chUseStrongCrypto' -Value '1'
	# 	New-item -Path "Registry::HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name 'chUseStrongCrypto' -Value '1'
	# 	$Path = "$NULL"

# Enables a High UAC level
	Write-Warning 'Setting UAC level to High...'
		New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'ConsentPromptBehaviorAdmin' -Value '2'
		New-Item -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'PromptOnSecureDesktop' -Value '1'
		Write-Host 'Done.'

# Installs programs for manual installation
	#Write-Host 'Retrieving program installers...'
	#	Invoke-WebRequest -Uri 'https://downloads.malwarebytes.com/file/mb3' -OutFile "./MalwareBytesInstaller.exe"
	#	Invoke-WebRequest -Uri 'https://download.ccleaner.com/ccsetup552.exe' -OutFile "./CCleanerInstaller.exe"
	#	Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/SysinternalsSuite.zip' -OutFile "./Sysinternals.zip"
	#	Write-Host 'Done.'

# Disables Optional Features
	Write-Warning 'Disabling Optional Features... This may take a while...'
		$Features =
			'Microsoft-Hyper-V-All',
			'Microsoft-Hyper-V-Tools-All',
			'Microsoft-Hyper-V',
			'Microsoft-Hyper-V',
			'Microsoft-Hyper-V-Management-Clients',
			'Microsoft-Hyper-V-Management-PowerShell',
			'Printing-Foundation-Features',
			'Printing-Foundation-LPRPortMonitor',
			'Printing-Foundation-LPDPrintService',
			'Printing-Foundation-InternetPrinting-Client',
			'FaxServicesClientPackage',
			'ScanManagementConsole',
			'LegacyComponents',
			'DirectPlay',
			'SimpleTCP',
			'SNMP',
			'WMISnmpProvider',
			'Windows-Defender-Default-Definitions',
			'Windows-Identity-Foundation',
			'MicrosoftWindowsPowerShellV2',
			'DirectoryServices-ADAM-Client',
			'Internet-Explorer-Optional-amd64',
			'NetFx3',
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
			'IIS-CertProvider',
			'IIS-WindowsAuthentication'
			'IIS-DigestAuthentication',
			'IIS-ClientCertificateMappingAuthentication',
			'IIS-IISCertificateMappingAuthentication',
			'IIS-ODCLogging',
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
			'MSMQ-ADIntegration',
			'MSMQ-HTTP',
			'MSMQ-Multicast',
			'MSMQ-DCOMProxy',
			'WCF-Services45',
			'WCF-HTTP-Activation45',
			'WCF-TCP-Activation45',
			'WCF-Pipe-Activation45',
			'WCF-MSMQ-Activation45',
			'WCF-TCP-PortSharing45',
			'WCF-HTTP-Activation',
			'WCF-NonHTTP-Activation',
			'NetFx4-AdvSrvs',
			'NetFx4Extended-ASPNET45',
			'MediaPlayback',
			'Microsoft-Windows-MobilePC-Client-Premium-Package-net',
			'Microsoft-Windows-MobilePC-LocationProvider-INF',
			'Printing-XPSServices-Features',
			'RasCMAK',
			'RasRip',
			'MSRDC-Infrastructure',
			'SearchEngine-Client-Package'
			'TelnetClient',
			'TFTP',
			'TIFFIFilter',
			'Xps-Foundation-Xps-Viewer',
			'WorkFolders-Client',
			'SMB1Protocol',
			'SevicesForNFS-ClientOnly',
			'ClientForNFS-Infrastructure',
			'NFS-Administration'
	  	$Index = 0
		$CrntFeature = $Features[$Index]
	  	Do {
			Disable-WindowsOptionalFeature -Online -FeatureName "$CrntFeature" -NoRestart -ErrorAction 'SilentlyContinue'
			$Index++
			$CrntFeature = $Features[$Index]
	  	} Until ($CrntFeature -eq $NULL)

# Cleans up
	Write-Warning 'Please restart PC now.'
		Clear-History
		Set-ExecutionPolicy restricted
