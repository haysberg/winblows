if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Write-Output("Installation de Chocolatey...")
# Run your code that needs to be elevated here...
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco feature enable -n=allowGlobalConfirmation

Write-Output("Telechargement de LoL...")
Invoke-WebRequest -Uri "https://lol.secure.dyn.riotcdn.net/channels/public/x/installer/current/live.euw.exe" -OutFile "$HOME\Downloads\lol_install_euw.exe"

Write-Output("Installation de LoL...")
Start-Process -Filepath "$HOME\Downloads\lol_install_euw.exe"

Write-Output("Installation des drivers NVIDIA")
choco install nvidia-display-driver --params "'/DCH'"

Write-Output("Installation du reste avec Chocolatey...")
choco install thunderbird discord spotify brave steam bitwarden termius 7zip.install vlc vscode gimp dropbox eartrumpet icue mattermost-desktop gitkraken microsoft-windows-terminal greenshot telegram.install signal amd-ryzen-chipset

Write-Output("Coup de karscher sur le PC...")
& ([scriptblock]::Create((iwr https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10SysPrepDebloater.ps1 -UseBasicParsing))) -Debloat -SysPrep -Privacy

Write-Output("Dark Mode...")
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0

Write-Output("Tweaks Taskbar")
#Cacher le volume
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name HideSCAVolume -Value 1
kill -n explorer

Set-Itemproperty -path 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds' -Name 'ShellFeedsTaskbarViewMode' -value '0'

Set-Itemproperty -path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds' -Name 'ShellFeedsTaskbarViewMode' -value 2

Write-Output("Activation de Windows...")
iwr -Uri "https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/master/MAS/Separate-Files-Version/Activators/HWID-KMS38_Activation/HWID_Activation.cmd" -OutFile "$HOME\Downloads\activation.cmd"
& "$HOME\Downloads\activation.cmd" /a