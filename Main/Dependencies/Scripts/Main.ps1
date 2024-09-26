#DesksideSupportPS
#10/12/22
#[COMPANY] Deskside Support

#Global Variables
#Identifies if the device is 64-bit or 32-bit
$Architecture = Get-WmiObject -Class Win32_OperatingSystem | Select-Object OSArchitecture

#Current script directory
$currentDirectory = $PSScriptRoot

#Dependency directories
$ExecutablesDir = Join-Path $currentDirectory "Dependencies\Executables"
$HashesTokensDir = Join-Path $currentDirectory "Dependencies\Hashes"
$ConfigurationsDir = Join-Path $currentDirectory "Dependencies\Configurations"
$ScriptsDir = Join-Path $currentDirectory "Dependencies\Scripts"

#Global Functions
#Accepts file input
function AcceptFile($type, $where) {
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        InitialDirectory = [Environment]::GetFolderPath($where)
        Filter           = $type
    }
    $null = $FileBrowser.ShowDialog()
    return $FileBrowser.FileName
}

#Hashing function for token input
function Get-TokenHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $HashAlgorithm = New-Object System.Security.Cryptography.SHA256Managed
    $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($Token)
    $HashedBytes = $HashAlgorithm.ComputeHash($ByteArray)
    $HashedToken = [System.BitConverter]::ToString($HashedBytes).Replace("-", "").ToLower()

    return $HashedToken
}

#Component Functions
#Installs Google Chrome
function Install-GoogleChrome {
    $FolderName = "C:\Program Files\Google\Chrome\Application\"
    if (Test-Path $FolderName) {
        Write-Host "Chrome is already installed."
    }
    else {
        Write-Host "Installing Chrome..."
        $LocalTempDir = $env:TEMP
        $ChromeInstaller = "ChromeInstaller.exe"
        $ChromeInstallerPath = Join-Path $LocalTempDir $ChromeInstaller
        (New-Object System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', $ChromeInstallerPath)
        Start-Process -FilePath $ChromeInstallerPath -ArgumentList "/silent", "/install" -Wait
        Remove-Item $ChromeInstallerPath -Force -ErrorAction SilentlyContinue
        Write-Host "Chrome installation finished."
    }
}

#Installs / Initiates Dell Command Update
function Invoke-DellCommandUpdate {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prepare", "Start")]
        [string]$SubFunction,
        [switch]$Bypass
    )

    $DcuExecutable = Join-Path $ExecutablesDir "DCU.exe"

    if ($SubFunction -eq "Prepare") {
        #Downloads and Installs Dell Command Update
        Write-Host "Installing Dell Command Update..."
        $DcuArguments = "/s"
        $DcuProcess = Start-Process -FilePath $DcuExecutable -ArgumentList $DcuArguments -Wait -PassThru
        if ($DcuProcess.ExitCode -eq 0) {
            Write-Host "Dell Command Update installation finished."
        }
        else {
            Write-Error "Failed to install Dell Command Update. Exit code: $($DcuProcess.ExitCode)"
        }
    }
    elseif ($SubFunction -eq "Start") {
        #Locates and initiates Dell Command Update
        Write-Host "Initiating Dell Command Update..."
        $DcuExePath = if ($Architecture.OSArchitecture -eq "32-bit" -or $Bypass) {
            Get-ChildItem -Path $env:ProgramFiles -Filter "dcu-cli.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        }
        else {
            Get-ChildItem -Path ${env:ProgramFiles(x86)} -Filter "dcu-cli.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        }

        if ($DcuExePath) {
            $DcuArguments = "/configure", "silent", "-autoSuspendBitLocker=enable", "-userConsent=disable"
            Start-Process -FilePath $DcuExePath -ArgumentList $DcuArguments -Wait
            Start-Process -FilePath $DcuExePath -ArgumentList "/scan", "-outputLog=`"C:\dell\logs\scan.log`"" -Wait
            Start-Process -FilePath $DcuExePath -ArgumentList "/applyUpdates", "-outputLog=`"C:\dell\logs\applyUpdates.log`"" -Wait
            Write-Host "Dell Command Update finished."
        }
        else {
            Write-Warning "Dell Command Update executable not found."
        }
    }
}

#Initiates Bitlocker Drive Encryption
function Enable-BitlockerEncryption {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prepare", "Start")]
        [string]$SubFunction
    )

    if ($SubFunction -eq "Prepare") {
        #Removes an old bitlocker file to allow the main function to work
        $ReAgent = "C:\Windows\System32\Recovery\ReAgent.xml"
        if (Test-Path $ReAgent) {
            Remove-Item $ReAgent -Force -Confirm:$false
            Write-Host "$ReAgent has been deleted."
        }
        else {
            Write-Host "$ReAgent doesn't exist, skipping deletion."
        }
    }
    elseif ($SubFunction -eq "Start") {
        #Initiates the Bitlocker Encryption of the Device
        Write-Host "Initiating Bitlocker encryption. You will be prompted for a PIN (1234)."
        $Pin = ConvertTo-SecureString "4357" -AsPlainText -Force
        Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -SkipHardwareTest -Pin $Pin -AdAccountOrGroupProtector
        Get-BitLockerVolume -MountPoint "C:"
        Write-Host "Bitlocker encryption finished."
    }
}

#Installs WindowsUpdate Module and Initiates Windows Update
function Update-Windows {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Prepare", "Start")]
        [string]$SubFunction
    )

    if ($SubFunction -eq "Prepare") {
        #Windows Update Module Install
        Write-Host "Installing PSWindowsUpdate module..."
        Install-PackageProvider -Name NuGet -Force
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        Install-Module -Name PSWindowsUpdate -Force
        Write-Host "PSWindowsUpdate module installed."
    }
    elseif ($SubFunction -eq "Start") {
        #Begins the Actual Install of the Updates
        Write-Host "Initiating Windows Update..."
        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
        Install-WindowsUpdate -MicrosoftUpdate -Confirm:$false -ForceInstall -AcceptAll -IgnoreReboot
        Write-Host "Windows Update finished."
    }
}

#Initiates Device Rename and Domain Addition
function Add-DeviceToDomain {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Host "Adding device to domain..."
    $SerialName = (Get-WmiObject -Class Win32_BIOS).SerialNumber
    if ($env:COMPUTERNAME -ne $SerialName) {
        Write-Host "Renaming device from $env:COMPUTERNAME to $SerialName..."
        Rename-Computer -NewName $SerialName
    }
    else {
        Write-Host "Device name is already set to $SerialName."
    }

    Add-Computer -DomainName "[DOMAIN]" -Credential $Credential -Force -Options JoinWithNewName, AccountCreate
    Write-Host "Device added to domain."
}

#Installs the Automate Agent
function Install-AutomateAgent {
    Write-Host "Installing Automate Agent..."
    $AutomateInstallerPath = Join-Path $ExecutablesDir "Agent.msi"
    Start-Process -FilePath $AutomateInstallerPath -Wait
    Write-Host "Automate Agent installation finished."
}

#Installs the SentinelOne Agent
function Install-SentinelOneAgent {
    Write-Host "Installing SentinelOne Agent..."
    $S1TokenFile = Join-Path $HashesTokensDir "s1token.txt"
    $S1Executable = Join-Path $ExecutablesDir "S1.exe"

    if (Test-Path $S1TokenFile) {
        $S1HashedToken = Get-Content $S1TokenFile
        $S1Arguments = "/SITE_TOKEN=`"$S1HashedToken`"", "/SILENT"
        $S1Process = Start-Process -FilePath $S1Executable -ArgumentList $S1Arguments -Wait -PassThru

        if ($S1Process.ExitCode -eq 0) {
            Write-Host "SentinelOne Agent installed successfully."
        }
        else {
            Write-Error "Failed to install SentinelOne Agent. Exit code: $($S1Process.ExitCode)"
        }
    }
    else {
        Write-Warning "SentinelOne token file not found. Skipping SentinelOne Agent installation."
    }
}

#Installs Adobe Acrobat Pro
function Install-AdobeAcrobatPro {
    Write-Host "Installing Adobe Acrobat Pro..."
    $AcrobatSetup = Join-Path $ExecutablesDir "Setup.exe"
    $SerialNumberFile = Join-Path $HashesTokensDir "acrobat_serial.txt"

    if (Test-Path $SerialNumberFile) {
        $HashedSerialNumber = Get-Content $SerialNumberFile
        $AcrobatArguments = "ISX_SERIALNUMBER=`"$HashedSerialNumber`"", "/sAll"
        $AcrobatProcess = Start-Process -FilePath $AcrobatSetup -ArgumentList $AcrobatArguments -Wait -PassThru

        if ($AcrobatProcess.ExitCode -eq 0) {
            Write-Host "Adobe Acrobat Pro installed successfully."
        }
        else {
            Write-Error "Failed to install Adobe Acrobat Pro. Exit code: $($AcrobatProcess.ExitCode)"
        }
    }
    else {
        Write-Warning "Adobe Acrobat Pro serial number file not found. Skipping installation."
    }
}

#Allows for the addition of AD users from an Excel input with a column named Username
function Add-ADUsersToGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Group,
        [Parameter(Mandatory = $true)]
        [string]$Sheet,
        [Parameter(Mandatory = $true)]
        [string]$Row
    )

    $ExcelFile = AcceptFile -Type 'Excel Files|*.xls;*.xlsx;*.xlsm' -Where 'Desktop'
    $UsernameRow = Import-Excel -Path $ExcelFile -WorksheetName $Sheet -ImportColumns @($Row) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $GroupSearcher = [ADSISearcher] "(&(objectCategory=group)(SAMAccountName=$Group))"
    $GroupPath = $GroupSearcher.FindOne().Properties['distinguishedName'][0]
    $GroupObject = [ADSI]"LDAP://$GroupPath"

    foreach ($UserEntry in $UsernameRow) {
        $Username = ($UserEntry -replace '[[\]{}@ ''"]').Split("=")[1]
        if (-not [string]::IsNullOrWhiteSpace($Username)) {
            $UserSearcher = [ADSISearcher] "(&(objectCategory=person)(objectClass=user)(SAMAccountName=$Username))"
            $UserPath = $UserSearcher.FindOne().Properties['distinguishedName'][0]
            $UserObject = [ADSI]"LDAP://$UserPath"

            if ($UserSearcher.FindOne().Properties.memberof -match "CN=$Group,") {
                Write-Host "$Username is already a member of $Group."
            }
            else {
                Write-Host "Adding $Username to $Group..."
                $GroupObject.Add($UserObject.Path)
            }
        }
    }
}

#Core Functions
#Sweeps through all Windows Users and Clears Non-Essential Ones
function Clear-NonEssentialUsers {
    $path = 'C:\Users'
    $excluded = '[ADMIN_USER]', 'Public', '[OTHER_USER]', 'Administrator'

    Write-Host "Clearing non-essential user profiles..."
    Get-ChildItem -Path $path -Exclude $excluded -Include *.* -Recurse -Force | Remove-Item -Force
    Get-ChildItem -Path $path -Exclude $excluded -Force | Remove-Item -Force
    Write-Host "Non-essential user profiles cleared."
}

#Sets things up post re-imaging
function Setup-PostImage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("1", "2")]
        [string]$SubFunction
    )

    if ($SubFunction -eq "1") {
        #Pre-Restart
        Install-GoogleChrome
        Install-SentinelOneAgent
        Invoke-DellCommandUpdate -SubFunction "Start" -Bypass
        Enable-BitlockerEncryption -SubFunction "Prepare"
        Update-Windows -SubFunction "Prepare"
        Update-Windows -SubFunction "Start"
        Add-DeviceToDomain -Credential $Credential
        Write-Host "Restarting..."
        Start-Sleep -Seconds 2
        Write-Host "Please restart the device to complete the setup."
        #Restart-Computer
    }
    elseif ($SubFunction -eq "2") {
        #Post-Restart
        Add-DeviceToDomain -Credential $Credential
        Enable-BitlockerEncryption -SubFunction "Start"
        Install-AutomateAgent
        Write-Host "Please enable Bitlocker after restart."
        Write-Host "Restarting..."
        Start-Sleep -Seconds 2
        Write-Host "Please restart the device to complete the setup."
        #Restart-Computer
    }
}

#Assigns a csv list of service tags to a specified OU
function Move-DevicesToOU {
    $Where = Read-Host "Please enter the OU path: ([OU1], [OU2], [OU3], [OU4], [OU5])"
    $What = Read-Host "Please enter the device list type: (Laptops, Desktops)"
    $How = Read-Host "Excel (E) or Plaintext (T)"
    $filety = 'Comma Separated Values (*.csv)|*.csv'
    $location = 'Desktop'

    if ($How -eq "E") {
        $File = AcceptFile -Type $filety -Where $location
        $Devices = Get-Content -Path $File
    }
    elseif ($How -eq "T") {
        $Devices = Read-Host "Input device service tags (comma-separated)"
        $Devices = $Devices -split ","
    }
    else {
        Write-Warning "Invalid input. Exiting..."
        return
    }

    foreach ($Device in $Devices) {
        Get-ADComputer -Identity $Device | Move-ADObject -TargetPath "OU=$What,OU=$Where,OU=[COMPANY],OU=[DEPARTMENT],DC=[DOMAIN_PART1],DC=[DOMAIN_PART2],DC=[DOMAIN_PART3]" -Verbose
    }
}

#Sets up new devices out of the box
function Setup-NewDevice {
    $SubFunction = Read-Host "Prepare [Pre-Restart] (1) or Start [Post-Restart] (2)"
    if ($SubFunction -eq "1") {
        #Pre-Restart
        Invoke-DellCommandUpdate -SubFunction "Prepare"
        Update-Windows -SubFunction "Prepare"
        Install-SentinelOneAgent
        Write-Host "Please restart the device to complete the setup."
    }
    elseif ($SubFunction -eq "2") {
        #Post-Restart
        Update-Windows -SubFunction "Start"
        Invoke-DellCommandUpdate -SubFunction "Start"
        Install-SentinelOneAgent
        Write-Host "Setup checklist:"
        Get-SetupChecklist
        Write-Host "Please restart the device to complete the setup."
    }
}

function Find-InstalledApplications {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Main", "Sub", "SubTwo")]
        [string]$SubFunction,
        [Parameter(Mandatory = $true)]
        [string[]]$Applications
    )

    if ($SubFunction -eq "Main") {
        foreach ($Application in $Applications) {
            $Installed = $null -ne (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -match $Application })
            Write-Host "'$Application' is$(if (-not $Installed) { " not" }) installed."
        }
    }
    elseif ($SubFunction -eq "Sub") {
        foreach ($Path in $Applications) {
            Write-Host "'$Path' is$(if (-not (Test-Path -Path $Path)) { " not" }) installed."
        }
    }
    elseif ($SubFunction -eq "SubTwo") {
        $Architecture = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture
        $DcuExePath = if ($Architecture -eq "32-bit" -or $Applications[0]) {
            Get-ChildItem -Path $env:ProgramFiles -Filter "dcu-cli.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        }
        else {
            Get-ChildItem -Path ${env:ProgramFiles(x86)} -Filter "dcu-cli.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        }
        Write-Host "$DcuExePath is installed."
    }
}

function Get-SetupChecklist {
    Find-InstalledApplications -SubFunction "Main" -Applications "Office", "Sentinel Agent", "[VOIP_SOFTWARE]", "[REMOTE_ACCESS_SOFTWARE]", "[VPN_SOFTWARE]", "DisplayLink", "Chrome"
    Find-InstalledApplications -SubFunction "Sub" -Applications "$env:WINDIR\LTSvc\", "$env:APPDATA\Microsoft\Teams\", "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
    Find-InstalledApplications -SubFunction "SubTwo" -Applications $true
}

function Invoke-MondayPreface {
    Add-ADUsersToGroup -Group "VPN Client Access" -Sheet "Sheet1" -Row "3"
}

#Main Menu Loop
function Show-Menu {
    Write-Host "
    Deskside Support Options:

    1:
        Cluttered Devices
            (Clears Non-Admin Users, Disk Cleanup, Defrag)

    2:
        Post-Imaged Devices
            (Bitlocker and Agent Install, After Reboot
            Automate > Scripts > AntiVirus
            S1 Deploy New)

    3:
        Mover of Devices
            (Move AD Users en masse)

    4:
        New Devices
            (Out of Box Configuration,
            Automate > Scripts > AntiVirus
            S1 Deploy New)

    5:
        Checklist
            (Run after a user has logged in and finished setting things up)

    6:
        Monday Preface
            (Add Monday's users to VPN in AD, and Assign a license in O365)

    7:
        Adobe Pro Installer
            (Installs Adobe Acrobat 2017)

    E:
        Exit Script.
    "
}

do {
    Show-Menu
    $UserInput = Read-Host "Please enter your selection"
    switch ($UserInput) {
        '1' {
            Clear-NonEssentialUsers
        }
        '2' {
            Setup-PostImage -SubFunction (Read-Host "Enter 1 for Pre-Restart or 2 for Post-Restart")
        }
        '3' {
            Move-DevicesToOU
        }
        '4' {
            Setup-NewDevice
        }
        '5' {
            Get-SetupChecklist
        }
        '6' {
            Invoke-MondayPreface
        }
        '7' {
            Install-AdobeAcrobatPro
        }
        'e' {
            Write-Host "Exiting..."
            return
        }
        default {
            Write-Warning "Invalid selection. Please try again."
        }
    }
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
} while ($true)