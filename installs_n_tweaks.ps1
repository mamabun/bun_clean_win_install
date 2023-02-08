# TODO: More apps?
#	Fix Nvidia telemetry removal

echo "This script installs Mamabun's default apps and tweaks"
read-host  "Hit ctrl-c to exit or enter to continue"

# Check if winget is installed, if not install it
if ((Get-Command "winget" -ErrorAction SilentlyContinue) -eq $null) 
{ 
	echo "Installing winget"
	Install-Module -Name WingetTools
	Install-WinGet
}

echo "Installing VCRedists, .Net, and the DX9 runtimes"

echo "VCRedist 2013 x64"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2013.x64 -e 

echo "VCRedist 2013 x86"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2013.x86 -e

echo "VCRedist 2012 x64"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2012.x64 -e

echo "VCRedist 2012 x86"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2010.x86 -e

echo "VCRedist 2012-2015 x64"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2015+.x64 -e

echo "VCRedist 2012-2015 x86"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2015+.x86 -e

echo "VCRedist 2005 x86"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2005.x86 -e

echo "VCRedist 2005 x64"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2005.x64 -e

echo "VCRedist 2008 x64"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2008.x64 -e

echo "VCRedist 2008 x86"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.VCRedist.2008.x86 -e

echo "DirectX 9 Runtime"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.DirectX -e

echo ".Net5 Runtime"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.DotNet.Runtime.5 -e

echo ".Net6 Runtime"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.DotNet.Runtime.6 -e

echo ".Net7 Runtime"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.DotNet.Runtime.7 -e

echo ".Net 3.1 Runtime"
winget install --accept-package-agreements --accept-source-agreements --id=Microsoft.DotNet.Runtime.3_1 -e


echo " "
echo "Installing Notepad++"
winget install --accept-package-agreements --accept-source-agreements --id=Notepad++.Notepad++ -e

echo " "
echo "Installing Hexchat"
winget install --accept-package-agreements --accept-source-agreements --id=HexChat.HexChat -e

echo " "
echo "Installing 7zip"
winget install --accept-package-agreements --accept-source-agreements --id=7zip.7zip -e

echo " "
echo "Installing Telegram"
winget install --accept-package-agreements --accept-source-agreements --id=Telegram.TelegramDesktop -e

echo " "
echo "Installing Discord"
winget install --accept-package-agreements --accept-source-agreements --id=Discord.Discord -e

echo " "
echo "Installing Vivaldi"
winget install --accept-package-agreements --accept-source-agreements --id=VivaldiTechnologies.Vivaldi -e

echo " "
echo "Installing qBittorrent"
winget install --accept-package-agreements --accept-source-agreements --id=qBittorrent.qBittorrent -e

echo " "
echo "Installing Digikam"
winget install --accept-package-agreements --accept-source-agreements --id=KDE.digikam -e

echo " "
echo "Installing Wise Disk Cleaner and Registry Cleaner"
winget install --accept-package-agreements --accept-source-agreements --id=WiseCleaner.WiseDiskCleaner -e
winget install --accept-package-agreements --accept-source-agreements --id=WiseCleaner.WiseRegistryCleaner -e

echo " "
echo "Installing Picard music tagger"
winget install --accept-package-agreements --accept-source-agreements --id=MusicBrainz.Picard -e

echo " "
echo "Installing Soulseek music client"
winget install --accept-package-agreements --accept-source-agreements --id=Soulseek.SoulseekQt -e

echo " "
echo "Installing iTunes and iCloud"
winget install --accept-package-agreements --accept-source-agreements --id=9PB2MZ1ZMB1S -e
winget install --accept-package-agreements --accept-source-agreements --id=9PKTQ5699M62 -e

echo " "
echo "Apps are now installed"

echo " "
echo " "

# Various system tweaks 

echo "Applying tweaks"
read-host  "Hit ctrl-c to exit or enter to continue"

echo " "
echo "Disabling the insecure SMBv1 protocol"
dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Client" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Server" /NoRestart

echo " "
echo "Disable Powershell 2.0 against downgrade attacks"
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /NoRestart
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2" /NoRestart

echo " "
echo "Disable camera on lockscreen"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f

echo " "
echo "Disable autoplay and autorun"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f

echo " "
echo "Disable remote Assistance"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f

echo " "
echo "Disable Microsoft Office logging and telemetry"
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE

echo " "
echo "Disable sending Media player tracking, metadata retrieval, and auto licence download"
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "GroupPrivacyAcceptance" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AcceptedEULA" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "FirstTime" /t REG_DWORD /d 1 /f
Set-Service -Name WMPNetworkSvc -startupType disabled

echo " "
echo "Disable caching thumbnails on networked drives"
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V "DisableThumbsDBOnNetworkFolders" /t REG_DWORD /d 1 /f

echo " "
echo "Allow Windows Updates for other products (e.g. Microsoft Office)"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /V "RegisteredWithAU" /t REG_DWORD /d 1 /f

echo " "
echo "Disable Windows Feedback"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /V "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /V "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

echo " "
echo "Disable narrator"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Narrator\NoRoam" /V "WinEnterLaunchEnabled" /t REG_DWORD /d 0 /f

echo " "
echo "Disable accessibility options"
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /V "Flags" /t REG_SZ /d "58" /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /V "Flags" /t REG_SZ /d "506" /f

echo " "
echo "Disable NTFS last access timestamp"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /V "NtfsDisableLastAccessUpdate" /t REG_DWORD 80000001 /f

echo " "
echo "Enable Windows Explorer StatusBar"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\Main" /V "Show_StatusBar" /t REG_SZ /d "yes" /f 
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\Main" /V "StatusBarOther" /t REG_DWORD /d 1 /f

echo " "
echo "Realtek high-pitch sound crackling fix"
reg add "HKEY_CURRENT_USER\Software\Realtek\Audio\RtkNGUI64\PowerMgnt" /V "Enabled" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Realtek\Audio\RtkNGUI64\PowerMgnt" /V "DelayTime" /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\Software\Realtek\Audio\RtkNGUI64\PowerMgnt" /V "OnlyBattery" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\Software\Realtek\Audio\RtkNGUI64\PowerMgnt" /V "PowerState" /t REG_DWORD /d 0 /f

echo " "
echo "Speed up the Shell and the Desktop by increasing (lowering) some timeouts"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Start_ShowRun" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "NoResolveSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "NoResolveTrack" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "NoInternetOpenWith" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "AutoEndTasks"/t REG_SZ /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "HungAppTimeout"/t REG_SZ /d "2000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "MenuShowDelay"/t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "WaitToKillAppTimeout"/t REG_SZ /d "3000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /V "LowLevelHooksTimeout"/t REG_SZ /d "2000" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control" /V"WaitToKillServiceTimeout"/t REG_SZ /d "2000" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /V "WaitToKillServiceTimeout"/t REG_SZ /d "2000" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /V "WaitToKillServiceTimeout"/t REG_SZ /d "2000" /f

echo " "
echo "Disable Dump File creation on BSOD"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /V "AutoReboot" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /V "CrashDumpEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /V "Overwrite" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /V "LogEvent" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /V "DumpFile" /t REG_EXPAND_SZ /d 25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,00,5c,00,4d,00,45,00,4d,00,4f,00,52,00,59,00,2e,00,44,00,4d,00,50,00,00,00 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /V "MinidumpDir" /t REG_EXPAND_SZ /d 25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,00,5c,00,4d,00,69,00,6e,00,69,00,64,00,75,00,6d,00,70,00,00,00 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /V "DumpFilters" /t REG_MULTI_SZ /d 64,00,75,00,6d,00,70,00,66,00,76,00,65,00,2e,00,73,00,79,00,73,00,00,00,00,00 /f

echo " "
echo "Enable confirmation of file deletion"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "ConfirmFileDelete" /t REG_DWORD /d 1 /f

echo " "
echo "Disable online tips and help for Settings app"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "AllowOnlineTips" /t REG_DWORD /d 0 /f

echo " "
echo "Hide Microsoft Edge button in IE"
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /V "HideNewEdgeButton" /t REG_DWORD /d 1 /f

echo "Remove Look for an app in the Store message"
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /V "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f

echo " "
echo "Enable status bar (bottom) in Explorer"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ShowStatusBar" /t REG_DWORD /d 1 /f

echo " "
echo "Show all icons in the Control Panel"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /V "AllItemsIconView"/t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /V "StartupPage" /t REG_DWORD /d 1 /f

echo " "
echo "Fix Slow-Loading Windows Icons by Increasing the Icon Cache"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /V "Max Cached Icons" /t REG_SZ /d "4096" /f

echo " "
echo "Disable installing MRT from installing"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT" /V "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT" /V "DontReportInfectionInformation" /t REG_DWORD /d 1 /f

echo " "
echo "Disable sending error reports in IE"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main" /V "IEWatsonDisabled" /t REG_DWORD /d 1 /f 

echo " "
echo "Enable case sensitivity in explorer"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DontPrettyPath" /t REG_DWORD /d 1 /f

echo " "
echo "Open NFO files with Notepad++"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo" /V "Application" /t REG_SZ /d "C:\Program Files (x86)\Notepad++\NOTEPAD++.EXE" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\OpenWithList" /V "a" /t REG_SZ /d "Explorer.exe" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\OpenWithList" /V "MRUList" /t REG_SZ /d "ba" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\OpenWithList" /V "b" /t REG_SZ /d "C:\Program Files (x86)\Notepad++\NOTEPAD++.EXE" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\OpenWithProgids" /V "MSInfo.Document"/t REG_NONE /d ([char] 0) /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\UserChoice" /V "ProgId" /t REG_SZ /d "Applications\\notepad++.exe" /f
reg add "HKEY_HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\UserChoice" /V "Hash" /t REG_SZ /d "+81k+7QMMkA=" /f

echo " "
echo "Reduce IE cache to 10MB"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Content" /V "CacheLimit" /t REG_DWORD /d 00002800 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Content" /V "CacheLimit" /t REG_DWORD /d 00002800 /f

echo " "
echo "Disable the warning: Information transmitted over the Internet may become available to other users"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1601" /t REG_DWORD /d 0 /f

echo " "
echo "Restart explorer automatically"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /V "AutoRestartShell" /t REG_DWORD /d 1 /f

echo " "
echo "Disable sending feedback in IE"
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Restrictions" /V "NoHelpItemSendFeedback" /t REG_DWORD /d 1 /f

echo " "
echo "Disable IE hints"
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\Restrictions" /V "NoHelpItemTipOfTheDay" /t REG_DWORD /d 1 /f

echo " "
echo "Enable icon drop shadows"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewShadow" /t REG_DWORD /d 1 /f

echo " "
echo "Disable low disk space check"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V "NoLowDiskSpaceChecks" /t REG_DWORD /d 1 /f

echo " "
echo "Change the default IE homepage to Google(User)"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main" /V "Start Page" /t REG_SZ /d "http://google.com" /f

echo " "
echo "Changes default homepage for IE to Google(local machine)"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main" /V "Default_Page_URL" /t REG_SZ /d "http://google.com/" /f

echo " "
echo "Speed up browsing computers on the local network(may not be present)"
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RemoteComputer\NameSpace\{D6277990-4C6A-11CF-8D87-00AA0060F5BF}" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RemoteComputer\NameSpace\{2227A280-3AEA-1069-A2DE-08002B30309D}" /f

echo " "
echo "Display detailed information in Device Manager"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /V "DEVMGR_SHOW_DETAILS" /t REG_DWORD /d 1 /f

echo " "
echo "Disable aeroshake"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DisallowShaking" /t REG_DWORD /d 1 /f

echo " "
echo "Show hidden files and directories and show file extensions"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /t REG_DWORD /d 0 /f

echo " "
echo "Explorer as seperate processes"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "SeparateProcess" /t REG_DWORD /d 1 /f

echo " "
echo "Show cortana as a button, saving space"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ShowCortanaButton" /t REG_DWORD /d 1 /f

echo " "
echo "Don't use sharing wizzard"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "SharingWizardOn" /t REG_DWORD /d 0 /f

echo " "
echo "Use powershell on win-x instead of cmd"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DontUsePowerShellOnWinX" /t REG_DWORD /d 0 /f

echo " "
echo "Disable ads and sponsered apps"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f

echo " "
echo "Disable first signon animation"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /V "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f

echo " "
echo "Show verbose login messages"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "VerboseStatus" /t REG_DWORD /d 1 /f

#Test-Path doesn't like system variables. Hardcoded it for now"
#echo " "
#echo "Removing NVidia telemetry"
#if (Test-Path -LiteralPath "C:\Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" -PathType Leaf)
#{ rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
#    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
#	del /s "%SystemRoot%\System32\DriverStore\FileRepository\NvTelemetry*.dll"
#	rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2>nul
#	rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2>nul
#	reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f 
#	reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f 
#	reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f 
#	reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f 
#	reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
#}	
#else {
#	echo "Not found, skipping"
#}


echo " "
$msg = 'A reboot is strongly recommended. Do you wish to reboot? [Y/N]'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
        shutdown -t 00 -r
		exit
    }
} until ($response -eq 'n')
