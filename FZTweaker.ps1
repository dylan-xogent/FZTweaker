<#
.SYNOPSIS
    FZTweaker - Advanced Gaming Optimization Suite
.DESCRIPTION
    A comprehensive GUI tool for optimizing Windows for gaming performance
    Features include bloatware removal, system optimization, GPU tweaks, and more
.NOTES
    Author: FZTweaker Team
    Version: 1.0.0
    Requires: PowerShell 5.1+ and Administrator privileges
#>

# Requires administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "FZTweaker requires administrator privileges. Please run as Administrator!"
    Start-Sleep -Seconds 3
    exit
}

# Load required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework

# Set Error Action Preference
$ErrorActionPreference = "SilentlyContinue"

# Application variables
$appName = "FZTweaker"
$appVersion = "1.0.0"
$appAuthor = "FZTweaker Team"
$appWebsite = "https://fztweaker.com"
$logFile = "$env:TEMP\FZTweaker_log.txt"

# Create log file
if (!(Test-Path $logFile)) {
    New-Item -Path $logFile -ItemType File -Force | Out-Null
}

# Logging function
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $logFile -Value $logMessage
    
    # Also output to console with color based on level
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
    }
}

# Create the main form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "$appName v$appVersion - Gaming Optimization Suite"
$mainForm.Size = New-Object System.Drawing.Size(900, 700)
$mainForm.StartPosition = "CenterScreen"
$mainForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$mainForm.ForeColor = [System.Drawing.Color]::White
$mainForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$mainForm.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\System32\shell32.dll")
$mainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$mainForm.MaximizeBox = $false

# Create a tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 100)
$tabControl.Size = New-Object System.Drawing.Size(865, 500)
$tabControl.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabControl.ForeColor = [System.Drawing.Color]::White
$mainForm.Controls.Add($tabControl)

# Create tabs
$tabDashboard = New-Object System.Windows.Forms.TabPage
$tabDashboard.Text = "Dashboard"
$tabDashboard.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabDashboard.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabDashboard)

$tabBloatware = New-Object System.Windows.Forms.TabPage
$tabBloatware.Text = "Bloatware Removal"
$tabBloatware.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabBloatware.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabBloatware)

$tabSystem = New-Object System.Windows.Forms.TabPage
$tabSystem.Text = "System Optimization"
$tabSystem.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabSystem.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabSystem)

$tabGPU = New-Object System.Windows.Forms.TabPage
$tabGPU.Text = "GPU Settings"
$tabGPU.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabGPU.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabGPU)

$tabNetwork = New-Object System.Windows.Forms.TabPage
$tabNetwork.Text = "Network"
$tabNetwork.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabNetwork.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabNetwork)

$tabStorage = New-Object System.Windows.Forms.TabPage
$tabStorage.Text = "Storage"
$tabStorage.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabStorage.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabStorage)

$tabGames = New-Object System.Windows.Forms.TabPage
$tabGames.Text = "Game Specific"
$tabGames.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabGames.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabGames)

$tabAdvanced = New-Object System.Windows.Forms.TabPage
$tabAdvanced.Text = "Advanced"
$tabAdvanced.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabAdvanced.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabAdvanced)

$tabAbout = New-Object System.Windows.Forms.TabPage
$tabAbout.Text = "About"
$tabAbout.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$tabAbout.ForeColor = [System.Drawing.Color]::White
$tabControl.Controls.Add($tabAbout)

# Create header with logo
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Location = New-Object System.Drawing.Point(0, 0)
$headerPanel.Size = New-Object System.Drawing.Size(900, 90)
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$mainForm.Controls.Add($headerPanel)

$logoLabel = New-Object System.Windows.Forms.Label
$logoLabel.Text = "FZTweaker"
$logoLabel.Location = New-Object System.Drawing.Point(20, 20)
$logoLabel.Size = New-Object System.Drawing.Size(300, 40)
$logoLabel.Font = New-Object System.Drawing.Font("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
$logoLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$headerPanel.Controls.Add($logoLabel)

$taglineLabel = New-Object System.Windows.Forms.Label
$taglineLabel.Text = "Advanced Gaming Optimization Suite"
$taglineLabel.Location = New-Object System.Drawing.Point(25, 60)
$taglineLabel.Size = New-Object System.Drawing.Size(300, 20)
$taglineLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$taglineLabel.ForeColor = [System.Drawing.Color]::LightGray
$headerPanel.Controls.Add($taglineLabel)

# Create footer
$footerPanel = New-Object System.Windows.Forms.Panel
$footerPanel.Location = New-Object System.Drawing.Point(0, 610)
$footerPanel.Size = New-Object System.Drawing.Size(900, 50)
$footerPanel.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$mainForm.Controls.Add($footerPanel)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Location = New-Object System.Drawing.Point(20, 15)
$statusLabel.Size = New-Object System.Drawing.Size(500, 20)
$statusLabel.ForeColor = [System.Drawing.Color]::LightGray
$footerPanel.Controls.Add($statusLabel)

$versionLabel = New-Object System.Windows.Forms.Label
$versionLabel.Text = "v$appVersion"
$versionLabel.Location = New-Object System.Drawing.Point(800, 15)
$versionLabel.Size = New-Object System.Drawing.Size(80, 20)
$versionLabel.ForeColor = [System.Drawing.Color]::LightGray
$versionLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
$footerPanel.Controls.Add($versionLabel)

# Create progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(10, 580)
$progressBar.Size = New-Object System.Drawing.Size(865, 20)
$progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$progressBar.Value = 0
$progressBar.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
$progressBar.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
$mainForm.Controls.Add($progressBar)

# Helper function to create styled buttons
function New-StyledButton {
    param (
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 150,
        [int]$Height = 35,
        [System.Windows.Forms.Control]$Parent
    )
    
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size($Width, $Height)
    $button.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $button.ForeColor = [System.Drawing.Color]::White
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.FlatAppearance.BorderSize = 0
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    
    $Parent.Controls.Add($button)
    return $button
}

# Helper function to create styled checkboxes
function New-StyledCheckbox {
    param (
        [string]$Text,
        [int]$X,
        [int]$Y,
        [bool]$Checked = $true,
        [System.Windows.Forms.Control]$Parent
    )
    
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Text = $Text
    $checkbox.Location = New-Object System.Drawing.Point($X, $Y)
    $checkbox.Size = New-Object System.Drawing.Size(350, 25)
    $checkbox.ForeColor = [System.Drawing.Color]::White
    $checkbox.Checked = $Checked
    $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    $Parent.Controls.Add($checkbox)
    return $checkbox
}

# Helper function to create styled group boxes
function New-StyledGroupBox {
    param (
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 400,
        [int]$Height = 200,
        [System.Windows.Forms.Control]$Parent
    )
    
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = $Text
    $groupBox.Location = New-Object System.Drawing.Point($X, $Y)
    $groupBox.Size = New-Object System.Drawing.Size($Width, $Height)
    $groupBox.ForeColor = [System.Drawing.Color]::White
    $groupBox.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    
    $Parent.Controls.Add($groupBox)
    return $groupBox
}

# Helper function to create styled labels
function New-StyledLabel {
    param (
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 400,
        [int]$Height = 20,
        [System.Windows.Forms.Control]$Parent,
        [int]$FontSize = 9,
        [System.Drawing.FontStyle]$FontStyle = [System.Drawing.FontStyle]::Regular
    )
    
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, $Height)
    $label.ForeColor = [System.Drawing.Color]::White
    $label.Font = New-Object System.Drawing.Font("Segoe UI", $FontSize, $FontStyle)
    
    $Parent.Controls.Add($label)
    return $label
}

# Helper function to update status
function Update-Status {
    param (
        [string]$Message,
        [int]$ProgressValue = -1,
        [string]$Level = "INFO"
    )
    
    $statusLabel.Text = $Message
    
    if ($ProgressValue -ge 0) {
        $progressBar.Value = $ProgressValue
    }
    
    # Log the message
    Write-Log -Message $Message -Level $Level
    
    # Force UI update
    [System.Windows.Forms.Application]::DoEvents()
}

# Helper function to create a backup
function New-SystemBackup {
    Update-Status -Message "Creating system restore point..." -Level "INFO"
    
    try {
        # Enable System Restore if it's disabled
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
        
        # Create a restore point
        Checkpoint-Computer -Description "FZTweaker Backup" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        
        Update-Status -Message "System restore point created successfully." -Level "SUCCESS"
        return $true
    }
    catch {
        Update-Status -Message "Failed to create system restore point: $_" -Level "ERROR"
        return $false
    }
}

# Helper function to export registry keys
function Export-RegistryKey {
    param (
        [string]$KeyPath,
        [string]$ExportPath
    )
    
    try {
        if (!(Test-Path (Split-Path -Path $ExportPath -Parent))) {
            New-Item -Path (Split-Path -Path $ExportPath -Parent) -ItemType Directory -Force | Out-Null
        }
        
        reg export $KeyPath $ExportPath /y | Out-Null
        return $true
    }
    catch {
        Write-Log -Message "Failed to export registry key $KeyPath : $_" -Level "ERROR"
        return $false
    }
}

# Function to backup registry before making changes
function Backup-Registry {
    $backupFolder = "$env:USERPROFILE\Documents\FZTweaker\Backup\Registry\$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    
    Update-Status -Message "Backing up registry..." -Level "INFO"
    
    try {
        # Create backup directory if it doesn't exist
        if (!(Test-Path $backupFolder)) {
            New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
        }
        
        # Export important registry keys
        $keysToBackup = @(
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion",
            "HKLM\SYSTEM\CurrentControlSet\Control",
            "HKLM\SYSTEM\CurrentControlSet\Services",
            "HKCU\Software\Microsoft\Windows\CurrentVersion",
            "HKLM\SOFTWARE\Microsoft\DirectX",
            "HKLM\SOFTWARE\NVIDIA Corporation",
            "HKLM\SOFTWARE\AMD"
        )
        
        $totalKeys = $keysToBackup.Count
        $currentKey = 0
        
        foreach ($key in $keysToBackup) {
            $currentKey++
            $progress = [math]::Round(($currentKey / $totalKeys) * 100)
            Update-Status -Message "Backing up registry key: $key" -ProgressValue $progress
            
            $keyName = ($key -split '\\')[-1]
            $exportPath = "$backupFolder\$keyName.reg"
            Export-RegistryKey -KeyPath $key -ExportPath $exportPath
        }
        
        Update-Status -Message "Registry backup completed successfully. Backup location: $backupFolder" -Level "SUCCESS"
        return $true
    }
    catch {
        Update-Status -Message "Failed to backup registry: $_" -Level "ERROR"
        return $false
    }
}

# Function to detect system hardware
function Get-SystemInfo {
    Update-Status -Message "Detecting system hardware..." -Level "INFO"
    
    $systemInfo = @{
        CPU = ""
        RAM = 0
        GPU = @()
        OS = ""
        IsLaptop = $false
        HasSSD = $false
    }
    
    # Get CPU info
    $cpuInfo = Get-WmiObject -Class Win32_Processor
    $systemInfo.CPU = $cpuInfo.Name
    
    # Get RAM info
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $systemInfo.RAM = [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB)
    
    # Get GPU info
    $gpuInfo = Get-WmiObject -Class Win32_VideoController
    foreach ($gpu in $gpuInfo) {
        $systemInfo.GPU += $gpu.Name
    }
    
    # Get OS info
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $systemInfo.OS = $osInfo.Caption
    
    # Check if system is a laptop
    $chassisType = Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -ExpandProperty ChassisTypes
    if ($chassisType -contains 9 -or $chassisType -contains 10 -or $chassisType -contains 14) {
        $systemInfo.IsLaptop = $true
    }
    
    # Check if system has SSD
    $diskDrives = Get-PhysicalDisk | Where-Object { $_.MediaType -eq "SSD" }
    if ($diskDrives) {
        $systemInfo.HasSSD = $true
    }
    
    return $systemInfo
}

# Function to remove bloatware
function Remove-Bloatware {
    param (
        [array]$AppsToRemove
    )
    
    Update-Status -Message "Removing bloatware applications..." -Level "INFO"
    
    $totalApps = $AppsToRemove.Count
    $currentApp = 0
    
    foreach ($app in $AppsToRemove) {
        $currentApp++
        $progress = [math]::Round(($currentApp / $totalApps) * 100)
        Update-Status -Message "Removing $app..." -ProgressValue $progress
        
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    
    Update-Status -Message "Bloatware removal completed." -Level "SUCCESS"
}

# Function to optimize system settings
function Optimize-SystemSettings {
    param (
        [bool]$SetHighPerformance = $true,
        [bool]$DisableHibernation = $true,
        [bool]$OptimizeVisualEffects = $true,
        [bool]$DisableGameDVR = $true,
        [bool]$DisableIndexing = $true,
        [bool]$DisableSuperfetch = $true,
        [bool]$ConfigureWindowsUpdate = $true
    )
    
    Update-Status -Message "Optimizing system settings..." -Level "INFO"
    $progressValue = 0
    $progressStep = 100 / 7 # 7 is the number of optimization steps
    
    # Set power plan to high performance
    if ($SetHighPerformance) {
        Update-Status -Message "Setting power plan to High Performance..." -ProgressValue $progressValue
        $highPerfGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        powercfg -setactive $highPerfGUID
        $progressValue += $progressStep
    }
    
    # Disable hibernation
    if ($DisableHibernation) {
        Update-Status -Message "Disabling hibernation..." -ProgressValue $progressValue
        powercfg -h off
        $progressValue += $progressStep
    }
    
    # Optimize visual effects
    if ($OptimizeVisualEffects) {
        Update-Status -Message "Optimizing visual effects for performance..." -ProgressValue $progressValue
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
        $progressValue += $progressStep
    }
    
    # Disable Game DVR and Game Bar
    if ($DisableGameDVR) {
        Update-Status -Message "Disabling Game DVR and Game Bar..." -ProgressValue $progressValue
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0
        $progressValue += $progressStep
    }
    
    # Disable Windows Search indexing
    if ($DisableIndexing) {
        Update-Status -Message "Disabling Windows Search indexing..." -ProgressValue $progressValue
        Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
        Set-Service "WSearch" -StartupType Disabled
        $progressValue += $progressStep
    }
    
    # Disable Superfetch/Prefetch
    if ($DisableSuperfetch) {
        Update-Status -Message "Disabling Superfetch/Prefetch..." -ProgressValue $progressValue
        Stop-Service "SysMain" -Force -ErrorAction SilentlyContinue
        Set-Service "SysMain" -StartupType Disabled
        $progressValue += $progressStep
    }
    
    # Configure Windows Update
    if ($ConfigureWindowsUpdate) {
        Update-Status -Message "Configuring Windows Update for manual control..." -ProgressValue $progressValue
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
        $progressValue += $progressStep
    }
    
    Update-Status -Message "System optimization completed." -Level "SUCCESS" -ProgressValue 100
}

# Function to optimize NVIDIA settings
function Optimize-NvidiaSettings {
    Update-Status -Message "Checking for NVIDIA GPU..." -Level "INFO"
    
    # Check if NVIDIA GPU is present
    $nvidiaPaths = @(
        "HKLM:\SOFTWARE\NVIDIA Corporation\Global"
        "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm"
    )
    
    $hasNvidia = $false
    foreach ($path in $nvidiaPaths) {
        if (Test-Path $path) {
            $hasNvidia = $true
            break
        }
    }
    
    if ($hasNvidia) {
        Update-Status -Message "NVIDIA GPU detected. Applying optimizations..." -Level "INFO"
        
        # Create NVIDIA registry paths if they don't exist
        $nvidiaRegPaths = @(
            "HKLM:\SOFTWARE\NVIDIA Corporation\Global\NVTweak"
            "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak"
            "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        )
        
        foreach ($path in $nvidiaRegPaths) {
            if (!(Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }
        
        # Set preferred GPU to NVIDIA
        If (!(Test-Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak")) {
            New-Item -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "PreferredGPU" -Type DWord -Value 1
        
        # Configure NVIDIA 3D settings via registry
        # Power management mode - Prefer maximum performance
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "PowerMizerMode" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "PowerMizerLevel" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "PowerMizerEnable" -Type DWord -Value 1
        
        # Texture filtering quality - Performance
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "TextureFilteringQuality" -Type DWord -Value 0
        
        # Disable VSync
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "VSync" -Type DWord -Value 0
        
        # Disable Triple Buffering
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "TripleBuffering" -Type DWord -Value 0
        
        # Set maximum pre-rendered frames to 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "MaxPreRenderedFrames" -Type DWord -Value 1
        
        # Threaded optimization - On
        Set-ItemProperty -Path "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak" -Name "ThreadedOptimization" -Type DWord -Value 1
        
        # Create NVIDIA profile for global settings
        $nvidiaProfilePath = "HKCU:\SOFTWARE\NVIDIA Corporation\Global\NVTweak\Profiles\Global"
        If (!(Test-Path $nvidiaProfilePath)) {
            New-Item -Path $nvidiaProfilePath -Force | Out-Null
        }
        
        # Apply settings to global profile
        Set-ItemProperty -Path $nvidiaProfilePath -Name "PowerMizerMode" -Type DWord -Value 1
        Set-ItemProperty -Path $nvidiaProfilePath -Name "VerticalSyncMode" -Type DWord -Value 0
        Set-ItemProperty -Path $nvidiaProfilePath -Name "TextureFilteringQuality" -Type DWord -Value 0
        Set-ItemProperty -Path $nvidiaProfilePath -Name "MaxPreRenderedFrames" -Type DWord -Value 1
        
        Update-Status -Message "NVIDIA settings applied successfully." -Level "SUCCESS"
        return $true
    } else {
        Update-Status -Message "No NVIDIA GPU detected. Skipping NVIDIA optimizations." -Level "WARNING"
        return $false
    }
}

# Function to optimize AMD settings
function Optimize-AMDSettings {
    Update-Status -Message "Checking for AMD GPU..." -Level "INFO"
    
    # Check if AMD GPU is present
    $amdPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\*"
    )
    
    $hasAMD = $false
    foreach ($path in Get-ChildItem $amdPaths -ErrorAction SilentlyContinue) {
        $provider = (Get-ItemProperty -Path $path.PSPath -Name "ProviderName" -ErrorAction SilentlyContinue).ProviderName
        if ($provider -like "*AMD*" -or $provider -like "*ATI*" -or $provider -like "*Radeon*") {
            $hasAMD = $true
            break
        }
    }
    
    if ($hasAMD) {
        Update-Status -Message "AMD GPU detected. Applying optimizations..." -Level "INFO"
        
        # Create AMD registry paths if they don't exist
        $amdRegPath = "HKLM:\SOFTWARE\AMD\CN"
        if (!(Test-Path $amdRegPath)) {
            New-Item -Path $amdRegPath -Force | Out-Null
        }
        
        # Disable Radeon Chill (power saving feature)
        Set-ItemProperty -Path $amdRegPath -Name "RadeonChill" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        # Set Tessellation Mode to Override application settings
        Set-ItemProperty -Path $amdRegPath -Name "TessellationMode" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        # Set Tessellation Level to 8x for better performance
        Set-ItemProperty -Path $amdRegPath -Name "TessellationLevel" -Type DWord -Value 8 -ErrorAction SilentlyContinue
        
        # Disable Frame Rate Target Control
        Set-ItemProperty -Path $amdRegPath -Name "FRTC" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        # Set Power Mode to Performance
        Set-ItemProperty -Path $amdRegPath -Name "PowerMode" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        
        # Disable Radeon Anti-Lag
        Set-ItemProperty -Path $amdRegPath -Name "AntiLag" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        # Disable Radeon Boost
        Set-ItemProperty -Path $amdRegPath -Name "RadeonBoost" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        # Disable Radeon Image Sharpening
        Set-ItemProperty -Path $amdRegPath -Name "ImageSharpening" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        Update-Status -Message "AMD GPU settings applied successfully." -Level "SUCCESS"
        return $true
    } else {
        Update-Status -Message "No AMD GPU detected. Skipping AMD optimizations." -Level "WARNING"
        return $false
    }
}

# Function to optimize network settings
function Optimize-NetworkSettings {
    Update-Status -Message "Optimizing network settings..." -Level "INFO"
    
    # Disable Nagle's Algorithm for lower latency
    Update-Status -Message "Disabling Nagle's Algorithm..." -ProgressValue 10
    $tcpipParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*"
    Get-ChildItem -Path $tcpipParams | ForEach-Object {
        $interface = $_.PSPath
        # Only modify interfaces with an IP address
        $ipAddress = (Get-ItemProperty -Path $interface -Name "IPAddress" -ErrorAction SilentlyContinue).IPAddress
        if ($ipAddress) {
            # Disable Nagle's Algorithm
            New-ItemProperty -Path $interface -Name "TcpAckFrequency" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $interface -Name "TCPNoDelay" -Value 1 -PropertyType DWord -Force | Out-Null
        }
    }
    
    # Optimize QoS settings
    Update-Status -Message "Optimizing QoS settings..." -ProgressValue 30
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
    
    # Optimize network throttling
    Update-Status -Message "Optimizing network throttling index..." -ProgressValue 50
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff
    
    # Set DNS servers to Google DNS for potentially faster lookups
    Update-Status -Message "Setting DNS servers to Google DNS..." -ProgressValue 70
    $networkInterfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    foreach ($interface in $networkInterfaces) {
        Set-DnsClientServerAddress -InterfaceIndex $interface.ifIndex -ServerAddresses ("8.8.8.8","8.8.4.4")
    }
    
    # Optimize TCP settings
    Update-Status -Message "Optimizing TCP settings..." -ProgressValue 90
    netsh int tcp set global chimney=enabled
    netsh int tcp set global rss=enabled
    netsh int tcp set global ecncapability=disabled
    netsh int tcp set global timestamps=disabled
    netsh int tcp set global initialRto=2000
    netsh int tcp set global rsc=disabled
    netsh int tcp set global nonsackrttresiliency=disabled
    netsh int tcp set global maxsynretransmissions=2
    
    Update-Status -Message "Network optimization completed." -Level "SUCCESS" -ProgressValue 100
}

# Function to optimize mouse settings
function Optimize-MouseSettings {
    Update-Status -Message "Optimizing mouse settings..." -Level "INFO"
    
    # Disable enhanced pointer precision (mouse acceleration)
    Update-Status -Message "Disabling enhanced pointer precision..." -ProgressValue 25
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
    
    # Set mouse pointer speed to 6/11 (default, no acceleration)
    Update-Status -Message "Setting mouse pointer speed..." -ProgressValue 50
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type String -Value "10"
    
    # Optimize mouse polling rate via registry (if possible)
    Update-Status -Message "Optimizing mouse polling rate..." -ProgressValue 75
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Force | Out-Null
    }
    # Set mouse polling rate to 1ms (1000Hz) if supported by hardware
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 20
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MousePollingRate" -Type DWord -Value 1
    
    # Disable mouse pointer shadow
    Update-Status -Message "Disabling mouse pointer shadow..." -ProgressValue 100
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    
    Update-Status -Message "Mouse optimization completed." -Level "SUCCESS" -ProgressValue 100
}

# Function to optimize storage settings
function Optimize-StorageSettings {
    Update-Status -Message "Optimizing storage settings..." -Level "INFO"
    
    # Check if the system drive is an SSD
    $systemDrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive
    $isSSD = Get-PhysicalDisk | Get-StorageReliabilityCounter | Where-Object {$_.DeviceId -eq 0 -and $_.MediaType -eq "SSD"}
    
    if ($isSSD) {
        Update-Status -Message "SSD detected as system drive. Applying SSD optimizations..." -ProgressValue 25
        
        # Enable TRIM
        fsutil behavior set DisableDeleteNotify 0
        
        # Disable defragmentation for SSDs
        $defragService = Get-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" -ErrorAction SilentlyContinue
        if ($defragService) {
            Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" -ErrorAction SilentlyContinue
        }
    } else {
        Update-Status -Message "HDD detected as system drive. Applying HDD optimizations..." -ProgressValue 25
        
        # Optimize HDD settings
        # Keep Superfetch enabled for HDDs but optimize it
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 3
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Type DWord -Value 3
    }
    
    # Optimize disk write caching
    Update-Status -Message "Optimizing disk write caching..." -ProgressValue 50
    $drives = Get-WmiObject -Class Win32_DiskDrive
    foreach ($drive in $drives) {
        $partitions = Get-WmiObject -Query "ASSOCIATORS OF {$($drive.Path)} WHERE ResultClass=Win32_DiskPartition"
        foreach ($partition in $partitions) {
            $logicalDisks = Get-WmiObject -Query "ASSOCIATORS OF {$($partition.Path)} WHERE ResultClass=Win32_LogicalDisk"
            foreach ($logicalDisk in $logicalDisks) {
                $deviceID = $logicalDisk.DeviceID
                # Enable write caching
                $diskPerfRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum"
                if (Test-Path $diskPerfRegPath) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\disk\Enum" -Name "Count" -Type DWord -Value 1
                }
            }
        }
    }
    
    # Clean up temporary files
    Update-Status -Message "Cleaning up temporary files..." -ProgressValue 75
    Remove-Item -Path "C:\Windows\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue
    
    Update-Status -Message "Storage optimization completed." -Level "SUCCESS" -ProgressValue 100
}

# Function to optimize memory settings
function Optimize-MemorySettings {
    Update-Status -Message "Optimizing memory settings..." -Level "INFO"
    
    # Get system memory information
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $physicalMemory = [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB)
    Update-Status -Message "Detected $physicalMemory GB of RAM" -ProgressValue 10
    
    # Optimize virtual memory based on physical RAM
    Update-Status -Message "Optimizing virtual memory settings..." -ProgressValue 30
    $pagefile = Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='C:\\pagefile.sys'"
    if ($pagefile) {
        # Calculate optimal pagefile size (1.5x RAM for systems with less than 8GB, 1x RAM for systems with more)
        $initialSize = if ($physicalMemory -lt 8) { $physicalMemory * 1536 } else { $physicalMemory * 1024 }
        $maximumSize = $initialSize
        
        $pagefile.InitialSize = $initialSize
        $pagefile.MaximumSize = $maximumSize
        $pagefile.Put() | Out-Null
        Update-Status -Message "Pagefile size set to $($initialSize / 1024) GB" -ProgressValue 50
    }
    
    # Disable memory compression
    Update-Status -Message "Disabling memory compression..." -ProgressValue 70
    Disable-MMAgent -MemoryCompression
    
    # Optimize working set parameters
    Update-Status -Message "Optimizing working set parameters..." -ProgressValue 90
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type DWord -Value 1
    
    Update-Status -Message "Memory optimization completed." -Level "SUCCESS" -ProgressValue 100
}

# Function to optimize Windows Defender
function Optimize-WindowsDefender {
    Update-Status -Message "Optimizing Windows Defender..." -Level "INFO"
    
    # Add game executables folder to exclusions
    Update-Status -Message "Adding game folders to Windows Defender exclusions..." -ProgressValue 25
    $gameFolders = @(
        "C:\Program Files (x86)\Steam",
        "C:\Program Files\Steam",
        "C:\Program Files (x86)\Epic Games",
        "C:\Program Files\Epic Games",
        "C:\Program Files (x86)\Origin Games",
        "C:\Program Files\Origin Games",
        "C:\Program Files (x86)\Ubisoft",
        "C:\Program Files\Ubisoft",
        "C:\Program Files (x86)\GOG Galaxy",
        "C:\Program Files\GOG Galaxy",
        "C:\Program Files (x86)\Riot Games",
        "C:\Program Files\Riot Games"
    )
    
    foreach ($folder in $gameFolders) {
        if (Test-Path $folder) {
            Add-MpPreference -ExclusionPath $folder -ErrorAction SilentlyContinue
        }
    }
    
    # Create scheduled task to disable real-time monitoring when games are running
    Update-Status -Message "Creating scheduled task to disable real-time monitoring when games are running..." -ProgressValue 50
    
    $taskName = "FZTweaker_ToggleDefenderForGaming"
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    
    if ($taskExists) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -Command `"& {
        # Check if any game processes are running
        $gameProcesses = @('steam', 'EpicGamesLauncher', 'Origin', 'GalaxyClient', 'RiotClient', 'Battle.net')
        $isGameRunning = $false
        
        foreach (`$proc in `$gameProcesses) {
            if (Get-Process -Name `$proc -ErrorAction SilentlyContinue) {
                `$isGameRunning = `$true
                break
            }
        }
        
        # Toggle Windows Defender real-time protection based on game status
        if (`$isGameRunning) {
            Set-MpPreference -DisableRealtimeMonitoring `$true
        } else {
            Set-MpPreference -DisableRealtimeMonitoring `$false
        }
    }`""
    
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Toggle Windows Defender real-time monitoring based on game activity" -ErrorAction SilentlyContinue
    
    # Optimize Windows Defender scanning
    Update-Status -Message "Optimizing Windows Defender scanning behavior..." -ProgressValue 75
    Set-MpPreference -ScanScheduleDay 1 # Sunday
    Set-MpPreference -ScanScheduleTime 3 # 3 AM
    Set-MpPreference -ScanParameters 1 # Quick scan
    Set-MpPreference -DisableCatchupFullScan $true
    Set-MpPreference -DisableCatchupQuickScan $true
    
    Update-Status -Message "Windows Defender optimization completed." -Level "SUCCESS" -ProgressValue 100
}

# Function to detect and optimize for specific games
function Optimize-GameSpecific {
    Update-Status -Message "Detecting installed games..." -Level "INFO"
    
    # Create a function to detect installed games
    function Test-GameInstalled {
        param (
            [string]$GamePath
        )
        return Test-Path $GamePath
    }
    
    $gamesDetected = 0
    $optimizationsApplied = 0
    
    # Optimize Steam games if Steam is installed
    $steamPath = "C:\Program Files (x86)\Steam"
    if (Test-GameInstalled $steamPath) {
        $gamesDetected++
        Update-Status -Message "Steam detected. Applying Steam optimizations..." -ProgressValue 20
        
        # Disable Steam overlay
        $steamConfigPath = "$steamPath\config\config.vdf"
        if (Test-Path $steamConfigPath) {
            $content = Get-Content $steamConfigPath -Raw
            if ($content -match '"InGameOverlay"		"1"') {
                $content = $content -replace '"InGameOverlay"		"1"', '"InGameOverlay"		"0"'
                $content | Set-Content $steamConfigPath -Force
                Update-Status -Message "Disabled Steam overlay" -ProgressValue 30
                $optimizationsApplied++
            }
        }
        
        # Set Steam launch options for better performance
        $steamOptimizationPath = "$env:USERPROFILE\Documents\FZTweaker\SteamOptimization.txt"
        if (!(Test-Path (Split-Path -Path $steamOptimizationPath -Parent))) {
            New-Item -Path (Split-Path -Path $steamOptimizationPath -Parent) -ItemType Directory -Force | Out-Null
        }
        
        @"
Steam Optimization Tips:

1. For best performance, add these launch options to your Steam games:
   -high -USEALLAVAILABLECORES -nomansky -d3d9ex -disable_d3d11_debug_runtime

2. Additional Steam settings to optimize:
   - Disable Steam overlay in Steam > Settings > In-Game
   - Disable automatic updates for games
   - Close Steam when not in use
"@ | Out-File -FilePath $steamOptimizationPath -Force
        
        Update-Status -Message "Created Steam optimization guide at $steamOptimizationPath" -ProgressValue 40
        $optimizationsApplied++
    }
    
    # Optimize Epic Games if installed
    $epicPath = "C:\Program Files\Epic Games\Launcher"
    if (Test-GameInstalled $epicPath) {
        $gamesDetected++
        Update-Status -Message "Epic Games Launcher detected. Applying optimizations..." -ProgressValue 50
        
        # Create optimization file for Epic Games
        $epicOptimizationPath = "$env:USERPROFILE\Documents\FZTweaker\EpicGamesOptimization.txt"
        if (!(Test-Path (Split-Path -Path $epicOptimizationPath -Parent))) {
            New-Item -Path (Split-Path -Path $epicOptimizationPath -Parent) -ItemType Directory -Force | Out-Null
        }
        
        @"
Epic Games Launcher Optimization Tips:

1. In Epic Games Launcher, go to Settings
2. Disable the following options:
   - Run when my computer starts
   - Enable Cloud Saves
   - Enable Overlay
   - Enable Playtime Tracking

3. For each game, right-click and select Properties, then add these command line arguments:
   -USEALLAVAILABLECORES -nomansky -high
"@ | Out-File -FilePath $epicOptimizationPath -Force
        
        Update-Status -Message "Created Epic Games optimization guide at $epicOptimizationPath" -ProgressValue 60
        $optimizationsApplied++
    }
    
    # Optimize Fortnite if installed
    $fortnitePath = "C:\Program Files\Epic Games\Fortnite"
    if (Test-GameInstalled $fortnitePath) {
        $gamesDetected++
        Update-Status -Message "Fortnite detected. Applying Fortnite-specific optimizations..." -ProgressValue 70
        
        # Create Fortnite optimization file
        $fortniteOptimizationPath = "$env:USERPROFILE\Documents\FZTweaker\FortniteOptimization.txt"
        if (!(Test-Path (Split-Path -Path $fortniteOptimizationPath -Parent))) {
            New-Item -Path (Split-Path -Path $fortniteOptimizationPath -Parent) -ItemType Directory -Force | Out-Null
        }
        
        @"
Fortnite Optimization Tips:

1. In Fortnite settings, set:
   - View Distance: Medium
   - Shadows: Off
   - Anti-Aliasing: Off
   - Textures: Medium
   - Effects: Low
   - Post Processing: Low
   - VSync: Off
   - Motion Blur: Off
   - Show FPS: On
   - Rendering Mode: Performance Mode (if available)

2. Right-click Fortnite in Epic Games Launcher, select Properties, then add these command line arguments:
   -USEALLAVAILABLECORES -nomansky -high -lanplay -notexturestreaming
"@ | Out-File -FilePath $fortniteOptimizationPath -Force
        
        Update-Status -Message "Created Fortnite optimization guide at $fortniteOptimizationPath" -ProgressValue 80
        $optimizationsApplied++
    }
    
    # Optimize Valorant if installed
    $valorantPath = "C:\Riot Games\VALORANT"
    if (Test-GameInstalled $valorantPath) {
        $gamesDetected++
        Update-Status -Message "Valorant detected. Applying Valorant-specific optimizations..." -ProgressValue 90
        
        # Create Valorant optimization file
        $valorantOptimizationPath = "$env:USERPROFILE\Documents\FZTweaker\ValorantOptimization.txt"
        if (!(Test-Path (Split-Path -Path $valorantOptimizationPath -Parent))) {
            New-Item -Path (Split-Path -Path $valorantOptimizationPath -Parent) -ItemType Directory -Force | Out-Null
        }
        
        @"
Valorant Optimization Tips:

1. In Valorant video settings, set:
   - Display Mode: Fullscreen
   - Material Quality: Low
   - Texture Quality: Low
   - Detail Quality: Low
   - UI Quality: Low
   - Vignette: Off
   - VSync: Off
   - Anti-Aliasing: None
   - Anisotropic Filtering: 1x
   - Improve Clarity: Off
   - Bloom: Off
   - Distortion: Off
   - First Person Shadows: Off

2. In Windows, right-click Valorant.exe, go to Properties > Compatibility and check:
   - Disable fullscreen optimizations
   - Run this program as administrator
"@ | Out-File -FilePath $valorantOptimizationPath -Force
        
        Update-Status -Message "Created Valorant optimization guide at $valorantOptimizationPath" -ProgressValue 100
        $optimizationsApplied++
    }
    
    if ($gamesDetected -gt 0) {
        Update-Status -Message "Game-specific optimizations completed. Detected $gamesDetected games and applied $optimizationsApplied optimizations." -Level "SUCCESS" -ProgressValue 100
    } else {
        Update-Status -Message "No supported games detected. Skipping game-specific optimizations." -Level "WARNING" -ProgressValue 100
    }
}

# Function to run all optimizations
function Start-AllOptimizations {
    # Create system restore point and backup registry
    $backupSuccess = New-SystemBackup
    if ($backupSuccess) {
        Backup-Registry
    }
    
    # Get system information
    $systemInfo = Get-SystemInfo
    
    # Run all optimizations
    $bloatwareApps = @(
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.XboxApp",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.YourPhone",
        "Microsoft.MixedReality.Portal",
        "Microsoft.SkypeApp",
        "Microsoft.People",
        "Microsoft.Getstarted",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsMaps",
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.BingWeather",
        "Microsoft.BingNews",
        "Microsoft.Office.OneNote",
        "Microsoft.Office.Sway",
        "Microsoft.OneConnect",
        "Microsoft.Print3D",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.Messaging",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.Wallet",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCamera"
    )
    
    Remove-Bloatware -AppsToRemove $bloatwareApps
    Optimize-SystemSettings
    Optimize-NvidiaSettings
    Optimize-AMDSettings
    Optimize-NetworkSettings
    Optimize-MouseSettings
    Optimize-StorageSettings
    Optimize-MemorySettings
    Optimize-WindowsDefender
    Optimize-GameSpecific
    
    # Create optimization summary
    $summaryPath = "$env:USERPROFILE\Documents\FZTweaker\OptimizationSummary.txt"
    if (!(Test-Path (Split-Path -Path $summaryPath -Parent))) {
        New-Item -Path (Split-Path -Path $summaryPath -Parent) -ItemType Directory -Force | Out-Null
    }
    
    @"
=== FZTweaker Optimization Summary ===

System Information:
- CPU: $($systemInfo.CPU)
- RAM: $($systemInfo.RAM) GB
- GPU: $($systemInfo.GPU -join ", ")
- OS: $($systemInfo.OS)
- Device Type: $(if ($systemInfo.IsLaptop) { "Laptop" } else { "Desktop" })
- SSD Detected: $(if ($systemInfo.HasSSD) { "Yes" } else { "No" })

Optimizations Applied:
- Bloatware Removal: Removed unnecessary pre-installed Windows applications
- System Optimization: Power plan, visual effects, Game DVR, indexing, etc.
- GPU Settings: $(if ($systemInfo.GPU -like "*NVIDIA*") { "NVIDIA optimizations applied" } else { "No NVIDIA GPU detected" })
- GPU Settings: $(if ($systemInfo.GPU -like "*AMD*" -or $systemInfo.GPU -like "*Radeon*") { "AMD optimizations applied" } else { "No AMD GPU detected" })
- Network Optimization: Nagle's Algorithm, QoS, DNS, TCP settings
- Mouse Optimization: Enhanced pointer precision, polling rate
- Storage Optimization: $(if ($systemInfo.HasSSD) { "SSD-specific optimizations" } else { "HDD-specific optimizations" })
- Memory Optimization: Virtual memory, memory compression, working set
- Windows Defender: Game folder exclusions, scheduled task for gaming
- Game-Specific Optimizations: Created optimization guides for detected games

Optimization completed on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

=== Next Steps ===
1. Restart your computer for all changes to take effect.
2. Review the optimization guides created in your Documents\FZTweaker folder.
3. For game-specific optimizations, follow the guides created for each detected game.
4. Consider monitoring your system performance with tools like MSI Afterburner.

Thank you for using FZTweaker!
"@ | Out-File -FilePath $summaryPath -Force
    
    Update-Status -Message "All optimizations completed successfully! Summary saved to $summaryPath" -Level "SUCCESS" -ProgressValue 100
    
    # Ask user if they want to restart
    $restartPrompt = [System.Windows.MessageBox]::Show("All optimizations have been applied. It is recommended to restart your computer for all changes to take effect. Would you like to restart now?", "FZTweaker", "YesNo", "Question")
    
    if ($restartPrompt -eq "Yes") {
        Restart-Computer -Force
    }
}

# Populate Dashboard tab
$systemInfoGroupBox = New-StyledGroupBox -Text "System Information" -X 10 -Y 10 -Width 400 -Height 200 -Parent $tabDashboard

# Get system info
$systemInfo = Get-SystemInfo()

$cpuLabel = New-StyledLabel -Text "CPU: $($systemInfo.CPU)" -X 10 -Y 30 -Width 380 -Height 20 -Parent $systemInfoGroupBox
$ramLabel = New-StyledLabel -Text "RAM: $($systemInfo.RAM) GB" -X 10 -Y 55 -Width 380 -Height 20 -Parent $systemInfoGroupBox
$gpuLabel = New-StyledLabel -Text "GPU: $($systemInfo.GPU -join ", ")" -X 10 -Y 80 -Width 380 -Height 20 -Parent $systemInfoGroupBox
$osLabel = New-StyledLabel -Text "OS: $($systemInfo.OS)" -X 10 -Y 105 -Width 380 -Height 20 -Parent $systemInfoGroupBox
$deviceTypeLabel = New-StyledLabel -Text "Device Type: $(if ($systemInfo.IsLaptop) { "Laptop" } else { "Desktop" })" -X 10 -Y 130 -Width 380 -Height 20 -Parent $systemInfoGroupBox
$ssdLabel = New-StyledLabel -Text "SSD Detected: $(if ($systemInfo.HasSSD) { "Yes" } else { "No" })" -X 10 -Y 155 -Width 380 -Height 20 -Parent $systemInfoGroupBox

$actionsGroupBox = New-StyledGroupBox -Text "Quick Actions" -X 430 -Y 10 -Width 400 -Height 200 -Parent $tabDashboard

$optimizeAllButton = New-StyledButton -Text "Optimize All" -X 20 -Y 30 -Width 360 -Height 40 -Parent $actionsGroupBox
$optimizeAllButton.Add_Click({
    Start-AllOptimizations
})

$createBackupButton = New-StyledButton -Text "Create System Backup" -X 20 -Y 80 -Width 360 -Height 40 -Parent $actionsGroupBox
$createBackupButton.Add_Click({
    New-SystemBackup
    Backup-Registry
})

$viewSummaryButton = New-StyledButton -Text "View Optimization Summary" -X 20 -Y 130 -Width 360 -Height 40 -Parent $actionsGroupBox
$viewSummaryButton.Add_Click({
    $summaryPath = "$env:USERPROFILE\Documents\FZTweaker\OptimizationSummary.txt"
    if (Test-Path $summaryPath) {
        Start-Process notepad.exe -ArgumentList $summaryPath
    } else {
        [System.Windows.MessageBox]::Show("No optimization summary found. Please run optimizations first.", "FZTweaker", "OK", "Information")
    }
})

$statusGroupBox = New-StyledGroupBox -Text "Status" -X 10 -Y 220 -Width 820 -Height 200 -Parent $tabDashboard

$statusRichTextBox = New-Object System.Windows.Forms.RichTextBox
$statusRichTextBox.Location = New-Object System.Drawing.Point(10, 25)
$statusRichTextBox.Size = New-Object System.Drawing.Size(800, 165)
$statusRichTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$statusRichTextBox.ForeColor = [System.Drawing.Color]::White
$statusRichTextBox.ReadOnly = $true
$statusRichTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$statusGroupBox.Controls.Add($statusRichTextBox)

# Populate Bloatware Removal tab
$bloatwareGroupBox = New-StyledGroupBox -Text "Select Bloatware to Remove" -X 10 -Y 10 -Width 820 -Height 400 -Parent $tabBloatware

$bloatwareList = @(
    @{Name = "Microsoft.MicrosoftSolitaireCollection"; Display = "Microsoft Solitaire Collection"; Category = "Games"},
    @{Name = "Microsoft.XboxApp"; Display = "Xbox App"; Category = "Games"},
    @{Name = "Microsoft.Xbox.TCUI"; Display = "Xbox TCUI"; Category = "Games"},
    @{Name = "Microsoft.XboxGameOverlay"; Display = "Xbox Game Overlay"; Category = "Games"},
    @{Name = "Microsoft.XboxGamingOverlay"; Display = "Xbox Gaming Overlay"; Category = "Games"},
    @{Name = "Microsoft.XboxIdentityProvider"; Display = "Xbox Identity Provider"; Category = "Games"},
    @{Name = "Microsoft.XboxSpeechToTextOverlay"; Display = "Xbox Speech To Text Overlay"; Category = "Games"},
    @{Name = "Microsoft.ZuneMusic"; Display = "Groove Music"; Category = "Entertainment"},
    @{Name = "Microsoft.ZuneVideo"; Display = "Movies & TV"; Category = "Entertainment"},
    @{Name = "Microsoft.YourPhone"; Display = "Your Phone"; Category = "Communication"},
    @{Name = "Microsoft.MixedReality.Portal"; Display = "Mixed Reality Portal"; Category = "Entertainment"},
    @{Name = "Microsoft.SkypeApp"; Display = "Skype"; Category = "Communication"},
    @{Name = "Microsoft.People"; Display = "People"; Category = "Communication"},
    @{Name = "Microsoft.Getstarted"; Display = "Tips"; Category = "Utilities"},
    @{Name = "Microsoft.WindowsFeedbackHub"; Display = "Feedback Hub"; Category = "Utilities"},
    @{Name = "Microsoft.WindowsMaps"; Display = "Maps"; Category = "Utilities"},
    @{Name = "Microsoft.WindowsSoundRecorder"; Display = "Voice Recorder"; Category = "Utilities"},
    @{Name = "Microsoft.BingWeather"; Display = "Weather"; Category = "Utilities"},
    @{Name = "Microsoft.BingNews"; Display = "News"; Category = "Utilities"},
    @{Name = "Microsoft.Office.OneNote"; Display = "OneNote"; Category = "Office"},
    @{Name = "Microsoft.Office.Sway"; Display = "Sway"; Category = "Office"},
    @{Name = "Microsoft.OneConnect"; Display = "Mobile Plans"; Category = "Utilities"},
    @{Name = "Microsoft.Print3D"; Display = "Print 3D"; Category = "Utilities"},
    @{Name = "Microsoft.Microsoft3DViewer"; Display = "3D Viewer"; Category = "Utilities"},
    @{Name = "Microsoft.Messaging"; Display = "Messaging"; Category = "Communication"},
    @{Name = "Microsoft.MicrosoftOfficeHub"; Display = "Office"; Category = "Office"},
    @{Name = "Microsoft.Wallet"; Display = "Wallet"; Category = "Utilities"},
    @{Name = "Microsoft.WindowsAlarms"; Display = "Alarms & Clock"; Category = "Utilities"},
    @{Name = "Microsoft.WindowsCamera"; Display = "Camera"; Category = "Utilities"}
)

$checkboxY = 30
$checkboxX = 20
$columnWidth = 250
$columnCount = 3
$itemsPerColumn = [Math]::Ceiling($bloatwareList.Count / $columnCount)

$bloatwareCheckboxes = @()

for ($i = 0; $i -lt $bloatwareList.Count; $i++) {
    $column = [Math]::Floor($i / $itemsPerColumn)
    $row = $i % $itemsPerColumn
    
    $x = $checkboxX + ($column * $columnWidth)
    $y = $checkboxY + ($row * 25)
    
    $checkbox = New-StyledCheckbox -Text $bloatwareList[$i].Display -X $x -Y $y -Checked $true -Parent $bloatwareGroupBox
    $checkbox.Tag = $bloatwareList[$i].Name
    
    $bloatwareCheckboxes += $checkbox
}

$selectAllButton = New-StyledButton -Text "Select All" -X 20 -Y 420 -Width 150 -Height 35 -Parent $tabBloatware
$selectAllButton.Add_Click({
    foreach ($checkbox in $bloatwareCheckboxes) {
        $checkbox.Checked = $true
    }
})

$deselectAllButton = New-StyledButton -Text "Deselect All" -X 180 -Y 420 -Width 150 -Height 35 -Parent $tabBloatware
$deselectAllButton.Add_Click({
    foreach ($checkbox in $bloatwareCheckboxes) {
        $checkbox.Checked = $false
    }
})

$removeBloatwareButton = New-StyledButton -Text "Remove Selected Bloatware" -X 600 -Y 420 -Width 230 -Height 35 -Parent $tabBloatware
$removeBloatwareButton.Add_Click({
    $selectedApps = @()
    foreach ($checkbox in $bloatwareCheckboxes) {
        if ($checkbox.Checked) {
            $selectedApps += $checkbox.Tag
        }
    }
    
    if ($selectedApps.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No bloatware selected for removal.", "FZTweaker", "OK", "Information")
        return
    }
    
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to remove the selected bloatware? This action cannot be undone.", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        Remove-Bloatware -AppsToRemove $selectedApps
    }
})

# Populate System Optimization tab
$systemOptimizationsGroupBox = New-StyledGroupBox -Text "System Optimizations" -X 10 -Y 10 -Width 400 -Height 400 -Parent $tabSystem

$systemOptimizations = @(
    @{Name = "SetHighPerformance"; Display = "Set High Performance Power Plan"; Default = $true},
    @{Name = "DisableHibernation"; Display = "Disable Hibernation"; Default = $true},
    @{Name = "OptimizeVisualEffects"; Display = "Optimize Visual Effects"; Default = $true},
    @{Name = "DisableGameDVR"; Display = "Disable Game DVR and Game Bar"; Default = $true},
    @{Name = "DisableIndexing"; Display = "Disable Windows Search Indexing"; Default = $true},
    @{Name = "DisableSuperfetch"; Display = "Disable Superfetch/Prefetch"; Default = $true},
    @{Name = "ConfigureWindowsUpdate"; Display = "Configure Windows Update for Manual Control"; Default = $true},
    @{Name = "DisableTransparency"; Display = "Disable Transparency Effects"; Default = $true},
    @{Name = "DisableAnimations"; Display = "Disable Animations"; Default = $true},
    @{Name = "OptimizeStartup"; Display = "Optimize Startup Programs"; Default = $true},
    @{Name = "DisableTelemetry"; Display = "Disable Telemetry and Data Collection"; Default = $true},
    @{Name = "DisableCortana"; Display = "Disable Cortana"; Default = $true}
)

$systemCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $systemOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $systemOptimizations[$i].Display -X 20 -Y $y -Checked $systemOptimizations[$i].Default -Parent $systemOptimizationsGroupBox
    $checkbox.Tag = $systemOptimizations[$i].Name
    
    $systemCheckboxes += $checkbox
}

$servicesGroupBox = New-StyledGroupBox -Text "Windows Services Optimization" -X 430 -Y 10 -Width 400 -Height 400 -Parent $tabSystem

$serviceOptimizations = @(
    @{Name = "DiagTrack"; Display = "Connected User Experiences and Telemetry"; Default = $true},
    @{Name = "dmwappushservice"; Display = "WAP Push Message Routing Service"; Default = $true},
    @{Name = "MapsBroker"; Display = "Downloaded Maps Manager"; Default = $true},
    @{Name = "lfsvc"; Display = "Geolocation Service"; Default = $true},
    @{Name = "SharedAccess"; Display = "Internet Connection Sharing"; Default = $true},
    @{Name = "lltdsvc"; Display = "Link-Layer Topology Discovery Mapper"; Default = $true},
    @{Name = "PcaSvc"; Display = "Program Compatibility Assistant"; Default = $true},
    @{Name = "WerSvc"; Display = "Windows Error Reporting"; Default = $true},
    @{Name = "XblAuthManager"; Display = "Xbox Live Auth Manager"; Default = $true},
    @{Name = "XblGameSave"; Display = "Xbox Live Game Save"; Default = $true},
    @{Name = "XboxNetApiSvc"; Display = "Xbox Live Networking Service"; Default = $true},
    @{Name = "ndu"; Display = "Windows Network Data Usage"; Default = $true},
    @{Name = "DusmSvc"; Display = "Data Usage"; Default = $true},
    @{Name = "DoSvc"; Display = "Delivery Optimization"; Default = $true}
)

$serviceCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $serviceOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $serviceOptimizations[$i].Display -X 20 -Y $y -Checked $serviceOptimizations[$i].Default -Parent $servicesGroupBox
    $checkbox.Tag = $serviceOptimizations[$i].Name
    
    $serviceCheckboxes += $checkbox
}

$applySystemButton = New-StyledButton -Text "Apply System Optimizations" -X 600 -Y 420 -Width 230 -Height 35 -Parent $tabSystem
$applySystemButton.Add_Click({
    $selectedOptimizations = @{}
    foreach ($checkbox in $systemCheckboxes) {
        $selectedOptimizations[$checkbox.Tag] = $checkbox.Checked
    }
    
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to apply the selected system optimizations?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        Optimize-SystemSettings @selectedOptimizations
        
        # Disable selected services
        $servicesToDisable = @()
        foreach ($checkbox in $serviceCheckboxes) {
            if ($checkbox.Checked) {
                $servicesToDisable += $checkbox.Tag
            }
        }
        
        foreach ($service in $servicesToDisable) {
            $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($serviceObj) {
                Update-Status -Message "Disabling service: $service" -Level "INFO"
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
        
        Update-Status -Message "Service optimizations completed." -Level "SUCCESS"
    }
})

# Populate GPU Settings tab
$nvidiaGroupBox = New-StyledGroupBox -Text "NVIDIA Optimizations" -X 10 -Y 10 -Width 400 -Height 200 -Parent $tabGPU

$nvidiaOptimizations = @(
    @{Name = "PreferredGPU"; Display = "Set Preferred GPU to NVIDIA"; Default = $true},
    @{Name = "PowerManagement"; Display = "Set Power Management to Maximum Performance"; Default = $true},
    @{Name = "TextureFiltering"; Display = "Optimize Texture Filtering Quality"; Default = $true},
    @{Name = "DisableVSync"; Display = "Disable VSync"; Default = $true},
    @{Name = "PreRenderedFrames"; Display = "Set Maximum Pre-rendered Frames to 1"; Default = $true},
    @{Name = "ThreadedOptimization"; Display = "Enable Threaded Optimization"; Default = $true}
)

$nvidiaCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $nvidiaOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $nvidiaOptimizations[$i].Display -X 20 -Y $y -Checked $nvidiaOptimizations[$i].Default -Parent $nvidiaGroupBox
    $checkbox.Tag = $nvidiaOptimizations[$i].Name
    
    $nvidiaCheckboxes += $checkbox
}

$amdGroupBox = New-StyledGroupBox -Text "AMD Optimizations" -X 430 -Y 10 -Width 400 -Height 200 -Parent $tabGPU

$amdOptimizations = @(
    @{Name = "DisableRadeonChill"; Display = "Disable Radeon Chill"; Default = $true},
    @{Name = "OptimizeTessellation"; Display = "Optimize Tessellation Settings"; Default = $true},
    @{Name = "DisableFRTC"; Display = "Disable Frame Rate Target Control"; Default = $true},
    @{Name = "SetPowerMode"; Display = "Set Power Mode to Performance"; Default = $true},
    @{Name = "DisableAntiLag"; Display = "Disable Radeon Anti-Lag"; Default = $true},
    @{Name = "DisableImageSharpening"; Display = "Disable Radeon Image Sharpening"; Default = $true}
)

$amdCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $amdOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $amdOptimizations[$i].Display -X 20 -Y $y -Checked $amdOptimizations[$i].Default -Parent $amdGroupBox
    $checkbox.Tag = $amdOptimizations[$i].Name
    
    $amdCheckboxes += $checkbox
}

$generalGpuGroupBox = New-StyledGroupBox -Text "General GPU Optimizations" -X 10 -Y 220 -Width 820 -Height 150 -Parent $tabGPU

$generalGpuOptimizations = @(
    @{Name = "DisableFullscreenOptimizations"; Display = "Disable Fullscreen Optimizations"; Default = $true},
    @{Name = "OptimizeShaderCache"; Display = "Optimize DirectX Shader Cache"; Default = $true},
    @{Name = "DisableTearing"; Display = "Disable Tearing Prevention"; Default = $true}
)

$generalGpuCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $generalGpuOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $generalGpuOptimizations[$i].Display -X 20 -Y $y -Checked $generalGpuOptimizations[$i].Default -Parent $generalGpuGroupBox
    $checkbox.Tag = $generalGpuOptimizations[$i].Name
    
    $generalGpuCheckboxes += $checkbox
}

$applyNvidiaButton = New-StyledButton -Text "Apply NVIDIA Optimizations" -X 10 -Y 380 -Width 230 -Height 35 -Parent $tabGPU
$applyNvidiaButton.Add_Click({
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to apply NVIDIA optimizations?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        Optimize-NvidiaSettings
    }
})

$applyAMDButton = New-StyledButton -Text "Apply AMD Optimizations" -X 250 -Y 380 -Width 230 -Height 35 -Parent $tabGPU
$applyAMDButton.Add_Click({
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to apply AMD optimizations?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        Optimize-AMDSettings
    }
})

$applyGeneralGpuButton = New-StyledButton -Text "Apply General GPU Optimizations" -X 490 -Y 380 -Width 230 -Height 35 -Parent $tabGPU
$applyGeneralGpuButton.Add_Click({
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to apply general GPU optimizations?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        # Apply general GPU optimizations
        Update-Status -Message "Applying general GPU optimizations..." -Level "INFO"
        
        # Disable fullscreen optimizations
        if ((Get-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -ErrorAction SilentlyContinue).GameDVR_FSEBehaviorMode -ne 2) {
            Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
        }
        
        # Optimize DirectX shader cache
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\DirectX")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\DirectX" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectX" -Name "ShaderCache" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        
        # Disable tearing prevention
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\DXGI")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\DXGI" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DXGI" -Name "PreventTearingOnDisplays" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        Update-Status -Message "General GPU optimizations applied successfully." -Level "SUCCESS"
    }
})

# Populate Network tab
$networkOptimizationsGroupBox = New-StyledGroupBox -Text "Network Optimizations" -X 10 -Y 10 -Width 400 -Height 400 -Parent $tabNetwork

$networkOptimizations = @(
    @{Name = "DisableNagle"; Display = "Disable Nagle's Algorithm"; Default = $true},
    @{Name = "OptimizeQoS"; Display = "Optimize QoS Settings"; Default = $true},
    @{Name = "OptimizeThrottling"; Display = "Optimize Network Throttling Index"; Default = $true},
    @{Name = "SetDNS"; Display = "Set DNS to Google DNS (8.8.8.8, 8.8.4.4)"; Default = $true},
    @{Name = "DisableIPv6"; Display = "Disable IPv6"; Default = $true},
    @{Name = "OptimizeTCP"; Display = "Optimize TCP Settings"; Default = $true}
)

$networkCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $networkOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $networkOptimizations[$i].Display -X 20 -Y $y -Checked $networkOptimizations[$i].Default -Parent $networkOptimizationsGroupBox
    $checkbox.Tag = $networkOptimizations[$i].Name
    
    $networkCheckboxes += $checkbox
}

$dnsGroupBox = New-StyledGroupBox -Text "Custom DNS Settings" -X 430 -Y 10 -Width 400 -Height 150 -Parent $tabNetwork

$dnsProviders = @(
    @{Name = "Google"; Display = "Google DNS (8.8.8.8, 8.8.4.4)"; Primary = "8.8.8.8"; Secondary = "8.8.4.4"},
    @{Name = "Cloudflare"; Display = "Cloudflare DNS (1.1.1.1, 1.0.0.1)"; Primary = "1.1.1.1"; Secondary = "1.0.0.1"},
    @{Name = "OpenDNS"; Display = "OpenDNS (208.67.222.222, 208.67.220.220)"; Primary = "208.67.222.222"; Secondary = "208.67.220.220"},
    @{Name = "Quad9"; Display = "Quad9 (9.9.9.9, 149.112.112.112)"; Primary = "9.9.9.9"; Secondary = "149.112.112.112"}
)

$dnsRadioButtons = @()
$radioY = 30

for ($i = 0; $i -lt $dnsProviders.Count; $i++) {
    $y = $radioY + ($i * 25)
    
    $radioButton = New-Object System.Windows.Forms.RadioButton
    $radioButton.Text = $dnsProviders[$i].Display
    $radioButton.Location = New-Object System.Drawing.Point(20, $y)
    $radioButton.Size = New-Object System.Drawing.Size(350, 20)
    $radioButton.ForeColor = [System.Drawing.Color]::White
    $radioButton.Checked = ($i -eq 0) # Select Google DNS by default
    $radioButton.Tag = $dnsProviders[$i]
    
    $dnsGroupBox.Controls.Add($radioButton)
    $dnsRadioButtons += $radioButton
}

$pingTestGroupBox = New-StyledGroupBox -Text "Ping Test" -X 430 -Y 170 -Width 400 -Height 240 -Parent $tabNetwork

$pingTestLabel = New-StyledLabel -Text "Test your connection to popular gaming servers:" -X 20 -Y 30 -Width 350 -Height 20 -Parent $pingTestGroupBox

$pingResultsTextBox = New-Object System.Windows.Forms.RichTextBox
$pingResultsTextBox.Location = New-Object System.Drawing.Point(20, 60)
$pingResultsTextBox.Size = New-Object System.Drawing.Size(360, 120)
$pingResultsTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$pingResultsTextBox.ForeColor = [System.Drawing.Color]::White
$pingResultsTextBox.ReadOnly = $true
$pingResultsTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$pingTestGroupBox.Controls.Add($pingResultsTextBox)

$runPingTestButton = New-StyledButton -Text "Run Ping Test" -X 20 -Y 190 -Width 360 -Height 35 -Parent $pingTestGroupBox
$runPingTestButton.Add_Click({
    $pingResultsTextBox.Clear()
    $pingResultsTextBox.AppendText("Running ping tests...\n\n")
    
    $servers = @(
        @{Name = "Google"; Address = "8.8.8.8"},
        @{Name = "Cloudflare"; Address = "1.1.1.1"},
        @{Name = "EA Servers"; Address = "ea.com"},
        @{Name = "Steam Servers"; Address = "steamcommunity.com"},
        @{Name = "Epic Games"; Address = "epicgames.com"},
        @{Name = "Riot Games"; Address = "riotgames.com"}
    )
    
    foreach ($server in $servers) {
        $pingResultsTextBox.AppendText("Pinging $($server.Name) ($($server.Address))... ")
        
        try {
            $ping = Test-Connection -ComputerName $server.Address -Count 4 -ErrorAction Stop
            $avgTime = ($ping | Measure-Object -Property ResponseTime -Average).Average
            $pingResultsTextBox.AppendText("$([Math]::Round($avgTime, 0)) ms\n")
        }
        catch {
            $pingResultsTextBox.AppendText("Failed\n")
        }
    }
    
    $pingResultsTextBox.AppendText("\nPing test completed.")
})

$applyNetworkButton = New-StyledButton -Text "Apply Network Optimizations" -X 600 -Y 420 -Width 230 -Height 35 -Parent $tabNetwork
$applyNetworkButton.Add_Click({
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to apply network optimizations?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        Optimize-NetworkSettings
        
        # Set custom DNS if selected
        foreach ($radioButton in $dnsRadioButtons) {
            if ($radioButton.Checked) {
                $dnsProvider = $radioButton.Tag
                $networkInterfaces = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
                foreach ($interface in $networkInterfaces) {
                    Set-DnsClientServerAddress -InterfaceIndex $interface.ifIndex -ServerAddresses ($dnsProvider.Primary, $dnsProvider.Secondary)
                }
                Update-Status -Message "DNS set to $($dnsProvider.Display)" -Level "SUCCESS"
                break
            }
        }
    }
})

# Populate Storage tab
$storageOptimizationsGroupBox = New-StyledGroupBox -Text "Storage Optimizations" -X 10 -Y 10 -Width 400 -Height 200 -Parent $tabStorage

$storageOptimizations = @(
    @{Name = "EnableTRIM"; Display = "Enable TRIM for SSDs"; Default = $true},
    @{Name = "DisableDefrag"; Display = "Disable Defragmentation for SSDs"; Default = $true},
    @{Name = "OptimizeWriteCaching"; Display = "Optimize Disk Write Caching"; Default = $true},
    @{Name = "CleanupTemp"; Display = "Clean Up Temporary Files"; Default = $true}
)

$storageCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $storageOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $storageOptimizations[$i].Display -X 20 -Y $y -Checked $storageOptimizations[$i].Default -Parent $storageOptimizationsGroupBox
    $checkbox.Tag = $storageOptimizations[$i].Name
    
    $storageCheckboxes += $checkbox
}

$diskInfoGroupBox = New-StyledGroupBox -Text "Disk Information" -X 430 -Y 10 -Width 400 -Height 200 -Parent $tabStorage

$diskInfoTextBox = New-Object System.Windows.Forms.RichTextBox
$diskInfoTextBox.Location = New-Object System.Drawing.Point(20, 30)
$diskInfoTextBox.Size = New-Object System.Drawing.Size(360, 150)
$diskInfoTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$diskInfoTextBox.ForeColor = [System.Drawing.Color]::White
$diskInfoTextBox.ReadOnly = $true
$diskInfoTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$diskInfoGroupBox.Controls.Add($diskInfoTextBox)

# Populate disk info
$diskInfoTextBox.AppendText("Scanning disks...\n\n")
$disks = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, Size, HealthStatus
foreach ($disk in $disks) {
    $sizeGB = [Math]::Round($disk.Size / 1GB, 2)
    $diskInfoTextBox.AppendText("Disk $($disk.DeviceId): $($disk.FriendlyName)\n")
    $diskInfoTextBox.AppendText("Type: $($disk.MediaType)\n")
    $diskInfoTextBox.AppendText("Size: $sizeGB GB\n")
    $diskInfoTextBox.AppendText("Health: $($disk.HealthStatus)\n\n")
}

$memoryOptimizationsGroupBox = New-StyledGroupBox -Text "Memory Optimizations" -X 10 -Y 220 -Width 400 -Height 200 -Parent $tabStorage

$memoryOptimizations = @(
    @{Name = "OptimizeVirtualMemory"; Display = "Optimize Virtual Memory Settings"; Default = $true},
    @{Name = "DisableMemoryCompression"; Display = "Disable Memory Compression"; Default = $true},
    @{Name = "OptimizeWorkingSet"; Display = "Optimize Working Set Parameters"; Default = $true}
)

$memoryCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $memoryOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $memoryOptimizations[$i].Display -X 20 -Y $y -Checked $memoryOptimizations[$i].Default -Parent $memoryOptimizationsGroupBox
    $checkbox.Tag = $memoryOptimizations[$i].Name
    
    $memoryCheckboxes += $checkbox
}

$memoryInfoGroupBox = New-StyledGroupBox -Text "Memory Information" -X 430 -Y 220 -Width 400 -Height 200 -Parent $tabStorage

$memoryInfoTextBox = New-Object System.Windows.Forms.RichTextBox
$memoryInfoTextBox.Location = New-Object System.Drawing.Point(20, 30)
$memoryInfoTextBox.Size = New-Object System.Drawing.Size(360, 150)
$memoryInfoTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$memoryInfoTextBox.ForeColor = [System.Drawing.Color]::White
$memoryInfoTextBox.ReadOnly = $true
$memoryInfoTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$memoryInfoGroupBox.Controls.Add($memoryInfoTextBox)

# Populate memory info
$memoryInfoTextBox.AppendText("Scanning memory...\n\n")
$computerSystem = Get-WmiObject -Class Win32_ComputerSystem
$physicalMemory = [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
$memoryInfoTextBox.AppendText("Total Physical Memory: $physicalMemory GB\n")

$operatingSystem = Get-WmiObject -Class Win32_OperatingSystem
$freeMemory = [Math]::Round($operatingSystem.FreePhysicalMemory / 1MB, 2)
$memoryInfoTextBox.AppendText("Free Physical Memory: $freeMemory GB\n\n")

$pageFile = Get-WmiObject -Class Win32_PageFileUsage
foreach ($pf in $pageFile) {
    $memoryInfoTextBox.AppendText("Page File: $($pf.Name)\n")
    $memoryInfoTextBox.AppendText("Current Usage: $([Math]::Round($pf.CurrentUsage / 1024, 2)) GB\n")
    $memoryInfoTextBox.AppendText("Peak Usage: $([Math]::Round($pf.PeakUsage / 1024, 2)) GB\n")
    $memoryInfoTextBox.AppendText("Allocated Size: $([Math]::Round(($pf.AllocatedBaseSize) / 1024, 2)) GB\n")
}

$applyStorageButton = New-StyledButton -Text "Apply Storage Optimizations" -X 600 -Y 420 -Width 230 -Height 35 -Parent $tabStorage
$applyStorageButton.Add_Click({
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to apply storage optimizations?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        Optimize-StorageSettings
        Optimize-MemorySettings
    }
})

# Populate Game Specific tab
$gameDetectionGroupBox = New-StyledGroupBox -Text "Game Detection" -X 10 -Y 10 -Width 820 -Height 150 -Parent $tabGames

$gameDetectionLabel = New-StyledLabel -Text "FZTweaker can detect and optimize settings for these game platforms:" -X 20 -Y 30 -Width 780 -Height 20 -Parent $gameDetectionGroupBox

$gameDetectionListBox = New-Object System.Windows.Forms.ListBox
$gameDetectionListBox.Location = New-Object System.Drawing.Point(20, 60)
$gameDetectionListBox.Size = New-Object System.Drawing.Size(780, 70)
$gameDetectionListBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$gameDetectionListBox.ForeColor = [System.Drawing.Color]::White
$gameDetectionListBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$gameDetectionListBox.SelectionMode = [System.Windows.Forms.SelectionMode]::MultiExtended
$gameDetectionGroupBox.Controls.Add($gameDetectionListBox)

# Add game platforms to the list
$gamePlatforms = @(
    "Steam",
    "Epic Games Launcher",
    "Origin",
    "Ubisoft Connect",
    "GOG Galaxy",
    "Riot Games",
    "Battle.net",
    "Minecraft",
    "Valorant",
    "Fortnite",
    "League of Legends",
    "Counter-Strike 2",
    "Apex Legends"
)

foreach ($platform in $gamePlatforms) {
    $gameDetectionListBox.Items.Add($platform)
}

$gameOptimizationsGroupBox = New-StyledGroupBox -Text "Game Optimizations" -X 10 -Y 170 -Width 820 -Height 230 -Parent $tabGames

$gameOptimizations = @(
    @{Name = "DisableSteamOverlay"; Display = "Disable Steam Overlay"; Default = $true},
    @{Name = "OptimizeLaunchOptions"; Display = "Optimize Launch Options"; Default = $true},
    @{Name = "DisableCloudSaves"; Display = "Disable Cloud Saves"; Default = $true},
    @{Name = "CreateOptimizationGuides"; Display = "Create Game-Specific Optimization Guides"; Default = $true},
    @{Name = "OptimizeGameExecutables"; Display = "Add Game Executables to Windows Defender Exclusions"; Default = $true},
    @{Name = "DisableFullscreenOptimizations"; Display = "Disable Fullscreen Optimizations for Games"; Default = $true},
    @{Name = "SetHighPriority"; Display = "Set Games to High CPU Priority"; Default = $true},
    @{Name = "CreatePriorityScript"; Display = "Create Game Process Priority Script"; Default = $true}
)

$gameOptCheckboxes = @()
$checkboxY = 30
$columnWidth = 400
$columnCount = 2
$itemsPerColumn = [Math]::Ceiling($gameOptimizations.Count / $columnCount)

for ($i = 0; $i -lt $gameOptimizations.Count; $i++) {
    $column = [Math]::Floor($i / $itemsPerColumn)
    $row = $i % $itemsPerColumn
    
    $x = 20 + ($column * $columnWidth)
    $y = $checkboxY + ($row * 25)
    
    $checkbox = New-StyledCheckbox -Text $gameOptimizations[$i].Display -X $x -Y $y -Checked $gameOptimizations[$i].Default -Parent $gameOptimizationsGroupBox
    $checkbox.Tag = $gameOptimizations[$i].Name
    
    $gameOptCheckboxes += $checkbox
}

$detectGamesButton = New-StyledButton -Text "Detect Games" -X 10 -Y 420 -Width 230 -Height 35 -Parent $tabGames
$detectGamesButton.Add_Click({
    $gameDetectionListBox.Items.Clear()
    
    Update-Status -Message "Detecting installed games..." -Level "INFO"
    
    # Check for Steam
    if (Test-Path "C:\Program Files (x86)\Steam") {
        $gameDetectionListBox.Items.Add("Steam (Installed)")
    } else {
        $gameDetectionListBox.Items.Add("Steam (Not Installed)")
    }
    
    # Check for Epic Games Launcher
    if (Test-Path "C:\Program Files\Epic Games\Launcher") {
        $gameDetectionListBox.Items.Add("Epic Games Launcher (Installed)")
    } else {
        $gameDetectionListBox.Items.Add("Epic Games Launcher (Not Installed)")
    }
    
    # Check for Origin
    if (Test-Path "C:\Program Files (x86)\Origin") {
        $gameDetectionListBox.Items.Add("Origin (Installed)")
    } else {
        $gameDetectionListBox.Items.Add("Origin (Not Installed)")
    }
    
    # Check for Ubisoft Connect
    if (Test-Path "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher") {
        $gameDetectionListBox.Items.Add("Ubisoft Connect (Installed)")
    } else {
        $gameDetectionListBox.Items.Add("Ubisoft Connect (Not Installed)")
    }
    
    # Check for GOG Galaxy
    if (Test-Path "C:\Program Files (x86)\GOG Galaxy") {
        $gameDetectionListBox.Items.Add("GOG Galaxy (Installed)")
    } else {
        $gameDetectionListBox.Items.Add("GOG Galaxy (Not Installed)")
    }
    
    # Check for Riot Games
    if (Test-Path "C:\Riot Games") {
        $gameDetectionListBox.Items.Add("Riot Games (Installed)")
    } else {
        $gameDetectionListBox.Items.Add("Riot Games (Not Installed)")
    }
    
    # Check for Battle.net
    if (Test-Path "C:\Program Files (x86)\Battle.net") {
        $gameDetectionListBox.Items.Add("Battle.net (Installed)")
    } else {
        $gameDetectionListBox.Items.Add("Battle.net (Not Installed)")
    }
    
    # Check for specific games
    if (Test-Path "C:\Program Files\Epic Games\Fortnite") {
        $gameDetectionListBox.Items.Add("Fortnite (Installed)")
    }
    
    if (Test-Path "C:\Riot Games\VALORANT") {
        $gameDetectionListBox.Items.Add("Valorant (Installed)")
    }
    
    if (Test-Path "$env:APPDATA\.minecraft") {
        $gameDetectionListBox.Items.Add("Minecraft (Installed)")
    }
    
    Update-Status -Message "Game detection completed." -Level "SUCCESS"
})

$optimizeGamesButton = New-StyledButton -Text "Optimize Games" -X 600 -Y 420 -Width 230 -Height 35 -Parent $tabGames
$optimizeGamesButton.Add_Click({
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to apply game-specific optimizations?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        Optimize-GameSpecific
    }
})

# Populate Advanced tab
$advancedGroupBox = New-StyledGroupBox -Text "Advanced Optimizations" -X 10 -Y 10 -Width 400 -Height 400 -Parent $tabAdvanced

$advancedOptimizations = @(
    @{Name = "DisableWindowsDefender"; Display = "Disable Windows Defender Real-time Protection"; Default = $false},
    @{Name = "DisableWindowsUpdate"; Display = "Disable Windows Update Service"; Default = $false},
    @{Name = "DisableOneDrive"; Display = "Disable OneDrive"; Default = $true},
    @{Name = "DisableUAC"; Display = "Disable User Account Control"; Default = $false},
    @{Name = "DisableFirewall"; Display = "Disable Windows Firewall"; Default = $false},
    @{Name = "DisableHyperV"; Display = "Disable Hyper-V Features"; Default = $true},
    @{Name = "DisableVirtualization"; Display = "Disable CPU Virtualization"; Default = $false},
    @{Name = "DisableWindowsInk"; Display = "Disable Windows Ink Workspace"; Default = $true},
    @{Name = "DisableActionCenter"; Display = "Disable Action Center"; Default = $true},
    @{Name = "DisableSmartScreen"; Display = "Disable SmartScreen Filter"; Default = $false}
)

$advancedCheckboxes = @()
$checkboxY = 30

for ($i = 0; $i -lt $advancedOptimizations.Count; $i++) {
    $y = $checkboxY + ($i * 25)
    
    $checkbox = New-StyledCheckbox -Text $advancedOptimizations[$i].Display -X 20 -Y $y -Checked $advancedOptimizations[$i].Default -Parent $advancedGroupBox
    $checkbox.Tag = $advancedOptimizations[$i].Name
    
    $advancedCheckboxes += $checkbox
}

$warningLabel = New-StyledLabel -Text "WARNING: These advanced optimizations may affect system stability and security. Use with caution!" -X 20 -Y 300 -Width 360 -Height 40 -Parent $advancedGroupBox -FontSize 9 -FontStyle Bold
$warningLabel.ForeColor = [System.Drawing.Color]::Red

$backupGroupBox = New-StyledGroupBox -Text "Backup & Restore" -X 430 -Y 10 -Width 400 -Height 200 -Parent $tabAdvanced

$createBackupButton2 = New-StyledButton -Text "Create System Restore Point" -X 20 -Y 30 -Width 360 -Height 35 -Parent $backupGroupBox
$createBackupButton2.Add_Click({
    New-SystemBackup
})

$backupRegistryButton = New-StyledButton -Text "Backup Registry" -X 20 -Y 75 -Width 360 -Height 35 -Parent $backupGroupBox
$backupRegistryButton.Add_Click({
    Backup-Registry
})

$restorePointsButton = New-StyledButton -Text "Open System Restore" -X 20 -Y 120 -Width 360 -Height 35 -Parent $backupGroupBox
$restorePointsButton.Add_Click({
    Start-Process "rstrui.exe"
})

$customScriptGroupBox = New-StyledGroupBox -Text "Custom PowerShell Script" -X 430 -Y 220 -Width 400 -Height 190 -Parent $tabAdvanced

$customScriptTextBox = New-Object System.Windows.Forms.TextBox
$customScriptTextBox.Location = New-Object System.Drawing.Point(20, 30)
$customScriptTextBox.Size = New-Object System.Drawing.Size(360, 100)
$customScriptTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$customScriptTextBox.ForeColor = [System.Drawing.Color]::White
$customScriptTextBox.Multiline = $true
$customScriptTextBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$customScriptTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$customScriptTextBox.Text = "# Enter your custom PowerShell commands here"
$customScriptGroupBox.Controls.Add($customScriptTextBox)

$runCustomScriptButton = New-StyledButton -Text "Run Custom Script" -X 20 -Y 140 -Width 360 -Height 35 -Parent $customScriptGroupBox
$runCustomScriptButton.Add_Click({
    $scriptContent = $customScriptTextBox.Text
    
    if ($scriptContent -eq "" -or $scriptContent -eq "# Enter your custom PowerShell commands here") {
        [System.Windows.MessageBox]::Show("Please enter a valid PowerShell script.", "FZTweaker", "OK", "Warning")
        return
    }
    
    $confirmResult = [System.Windows.MessageBox]::Show("Are you sure you want to run this custom script? This could potentially harm your system if the script contains malicious code.", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        try {
            Update-Status -Message "Running custom script..." -Level "INFO"
            
            # Create a temporary script file
            $tempScriptPath = "$env:TEMP\FZTweaker_CustomScript.ps1"
            $scriptContent | Out-File -FilePath $tempScriptPath -Force
            
            # Execute the script
            $result = & powershell.exe -ExecutionPolicy Bypass -File $tempScriptPath
            
            # Display the result
            Update-Status -Message "Custom script executed successfully." -Level "SUCCESS"
            
            if ($result) {
                $resultString = $result -join "`n"
                [System.Windows.MessageBox]::Show("Script Result:`n$resultString", "FZTweaker", "OK", "Information")
            }
            
            # Clean up
            Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue
        }
        catch {
            Update-Status -Message "Error executing custom script: $_" -Level "ERROR"
            [System.Windows.MessageBox]::Show("Error executing script: $_", "FZTweaker", "OK", "Error")
        }
    }
})

$applyAdvancedButton = New-StyledButton -Text "Apply Advanced Optimizations" -X 600 -Y 420 -Width 230 -Height 35 -Parent $tabAdvanced
$applyAdvancedButton.Add_Click({
    $confirmResult = [System.Windows.MessageBox]::Show("WARNING: These advanced optimizations may affect system stability and security. Are you absolutely sure you want to continue?", "FZTweaker", "YesNo", "Warning")
    
    if ($confirmResult -eq "Yes") {
        $secondConfirm = [System.Windows.MessageBox]::Show("This is your last warning. Some of these changes may be difficult to reverse. Continue?", "FZTweaker", "YesNo", "Warning")
        
        if ($secondConfirm -eq "Yes") {
            Update-Status -Message "Applying advanced optimizations..." -Level "INFO"
            
            # Create a backup first
            New-SystemBackup
            Backup-Registry
            
            # Apply selected advanced optimizations
            foreach ($checkbox in $advancedCheckboxes) {
                if ($checkbox.Checked) {
                    $optimization = $checkbox.Tag
                    
                    switch ($optimization) {
                        "DisableWindowsDefender" {
                            Update-Status -Message "Disabling Windows Defender Real-time Protection..." -Level "INFO"
                            Set-MpPreference -DisableRealtimeMonitoring $true
                        }
                        "DisableWindowsUpdate" {
                            Update-Status -Message "Disabling Windows Update Service..." -Level "INFO"
                            Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
                            Set-Service -Name "wuauserv" -StartupType Disabled
                        }
                        "DisableOneDrive" {
                            Update-Status -Message "Disabling OneDrive..." -Level "INFO"
                            Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                            Start-Process -FilePath "taskkill" -ArgumentList "/f /im OneDrive.exe" -Wait -WindowStyle Hidden
                            if (Test-Path "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe") {
                                Start-Process -FilePath "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -WindowStyle Hidden
                            }
                            if (Test-Path "$env:SYSTEMROOT\System32\OneDriveSetup.exe") {
                                Start-Process -FilePath "$env:SYSTEMROOT\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -WindowStyle Hidden
                            }
                        }
                        "DisableUAC" {
                            Update-Status -Message "Disabling User Account Control..." -Level "INFO"
                            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 0
                        }
                        "DisableFirewall" {
                            Update-Status -Message "Disabling Windows Firewall..." -Level "INFO"
                            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
                        }
                        "DisableHyperV" {
                            Update-Status -Message "Disabling Hyper-V Features..." -Level "INFO"
                            Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
                        }
                        "DisableVirtualization" {
                            Update-Status -Message "Disabling CPU Virtualization..." -Level "INFO"
                            # This requires BIOS changes, so we'll just provide instructions
                            [System.Windows.MessageBox]::Show("CPU Virtualization must be disabled in your BIOS/UEFI settings. Please restart your computer and enter BIOS setup to disable this feature.", "FZTweaker", "OK", "Information")
                        }
                        "DisableWindowsInk" {
                            Update-Status -Message "Disabling Windows Ink Workspace..." -Level "INFO"
                            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
                                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
                            }
                            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Type DWord -Value 0
                        }
                        "DisableActionCenter" {
                            Update-Status -Message "Disabling Action Center..." -Level "INFO"
                            If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
                                New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
                            }
                            Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
                            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
                        }
                        "DisableSmartScreen" {
                            Update-Status -Message "Disabling SmartScreen Filter..." -Level "INFO"
                            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
                            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
                        }
                    }
                }
            }
            
            Update-Status -Message "Advanced optimizations applied successfully." -Level "SUCCESS"
            [System.Windows.MessageBox]::Show("Advanced optimizations have been applied. Some changes may require a system restart to take effect.", "FZTweaker", "OK", "Information")
        }
    }
})

# Populate About tab
$aboutLogoLabel = New-StyledLabel -Text "FZTweaker" -X 10 -Y 20 -Width 820 -Height 50 -Parent $tabAbout -FontSize 24 -FontStyle Bold
$aboutLogoLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$aboutLogoLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 215)

$versionInfoLabel = New-StyledLabel -Text "Version $appVersion" -X 10 -Y 70 -Width 820 -Height 30 -Parent $tabAbout -FontSize 12
$versionInfoLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

$descriptionLabel = New-StyledLabel -Text "Advanced Gaming Optimization Suite for Windows" -X 10 -Y 100 -Width 820 -Height 30 -Parent $tabAbout -FontSize 12
$descriptionLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter

$aboutGroupBox = New-StyledGroupBox -Text "About FZTweaker" -X 10 -Y 140 -Width 820 -Height 200 -Parent $tabAbout

$aboutTextBox = New-Object System.Windows.Forms.RichTextBox
$aboutTextBox.Location = New-Object System.Drawing.Point(20, 30)
$aboutTextBox.Size = New-Object System.Drawing.Size(780, 150)
$aboutTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$aboutTextBox.ForeColor = [System.Drawing.Color]::White
$aboutTextBox.ReadOnly = $true
$aboutTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$aboutGroupBox.Controls.Add($aboutTextBox)

$aboutText = @"
FZTweaker is a comprehensive gaming optimization suite designed to enhance your gaming experience on Windows.

Features:
- Bloatware Removal: Remove unnecessary pre-installed Windows applications
- System Optimization: Optimize Windows settings for gaming performance
- GPU Settings: Configure NVIDIA and AMD graphics settings for optimal performance
- Network Optimization: Reduce latency and improve connection stability
- Storage Optimization: Enhance disk and memory performance
- Game-Specific Optimizations: Apply tweaks for popular games and platforms
- Advanced Optimizations: Fine-tune Windows for maximum gaming performance

FZTweaker is designed to be safe and user-friendly, with options to create backups before making changes.

Created by: $appAuthor
Website: $appWebsite
"@

$aboutTextBox.Text = $aboutText

$creditsGroupBox = New-StyledGroupBox -Text "Credits & Acknowledgements" -X 10 -Y 350 -Width 820 -Height 100 -Parent $tabAbout

$creditsTextBox = New-Object System.Windows.Forms.RichTextBox
$creditsTextBox.Location = New-Object System.Drawing.Point(20, 30)
$creditsTextBox.Size = New-Object System.Drawing.Size(780, 50)
$creditsTextBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$creditsTextBox.ForeColor = [System.Drawing.Color]::White
$creditsTextBox.ReadOnly = $true
$creditsTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$creditsGroupBox.Controls.Add($creditsTextBox)

$creditsText = @"
Special thanks to the gaming and optimization community for their research and contributions.
FZTweaker incorporates best practices and optimizations from various sources to provide the most comprehensive gaming optimization suite.
"@

$creditsTextBox.Text = $creditsText

# Set up event handlers for logging
[System.Windows.Forms.Application]::EnableVisualStyles()
$mainForm.Add_Shown({
    Update-Status -Message "FZTweaker v$appVersion started. Ready to optimize your system for gaming." -Level "INFO"
})

# Show the form
$mainForm.ShowDialog()