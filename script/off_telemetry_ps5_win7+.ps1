<#
.SYNOPSIS
    Improved comprehensive script to disable telemetry in Microsoft development tools
.DESCRIPTION
    ====================================================================================
    Based on off_telemetry_ps5.ps1 but without "emojis" for OS win7-8.1 (works on win10/11)
	P.S. Replace to text : [INFO], [SKIP]..
	====================================================================================
    This script safely disables telemetry, crash reporting, and data collection for:
    - Visual Studio 2015-2022 (only if installed)
    - Visual Studio Code (only if installed)
    - .NET CLI
    - NuGet
    - Various Visual Studio services
	- PowerShell 7.x (Windows 8+ only)
	- Visual Studio Background Download (automatic component downloads)
.NOTES
    Must be run as Administrator
    Improved safety - only modifies existing registry paths
    Compatible with PowerShell 5.x
    Includes comprehensive backup and restore functionality
.PARAMETER CreateBackup
    Creates registry backup before making changes
.PARAMETER RestoreBackup
    Restores registry from backup file
.PARAMETER BackupPath
    Path for backup file (default: Desktop)
.EXAMPLE
    .\off_telemetry_ps5_win7+.ps1 -CreateBackup
    .\off_telemetry_ps5_win7+.ps1 -RestoreBackup -BackupPath "C:\Backup\registry_backup.reg"
#>

param(
    [switch]$CreateBackup,
    [switch]$RestoreBackup,
    [string]$BackupPath = "$env:USERPROFILE\Desktop\telemetry_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg",
    [switch]$DisableBackgroundDownload
)

$serviceProcessed = $false


# Color scheme for consistent output
$Colors = @{
    Title = 'Cyan'
    Section = 'Yellow'
    Success = 'Green'
    Info = 'Blue'
    Warning = 'Yellow'
    Error = 'Red'
    Gray = 'Gray'
}

Write-Host "======================================================" -ForegroundColor $Colors.Title
Write-Host "                     by EXLOUD" -ForegroundColor $Colors.Title
Write-Host "======================================================" -ForegroundColor $Colors.Title

# =======================================================
# BACKUP AND RESTORE FUNCTIONS
# =======================================================

function New-RegistryBackup {
    param([string]$BackupFile)
    
    Write-Host "`n--- Creating Registry Backup ---" -ForegroundColor $Colors.Section
    
    try {
        $backupKeys = @(
            "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VSCommon",
            "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VSCommon",
            "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VisualStudio",
            "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio",
			"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\Setup",
			"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\Setup"
        )
        
        $backupResult = $true
        foreach ($key in $backupKeys) {
            $regFile = $BackupFile -replace '\.reg$', "_$($key -replace '[\\:]', '_').reg"
            $null = & reg export $key $regFile /y 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] Backed up: $key" -ForegroundColor $Colors.Success
            } else {
                Write-Host "[INFO] Key not found (skipped): $key" -ForegroundColor $Colors.Gray
            }
        }
        
        Write-Host "[OK] Registry backup completed" -ForegroundColor $Colors.Success
        return $backupResult
    }
    catch {
        Write-Host "[ERROR] Failed to create backup: $_" -ForegroundColor $Colors.Error
        return $false
    }
}

function Restore-RegistryBackup {
    param([string]$BackupFile)
    
    Write-Host "`n--- Restoring Registry Backup ---" -ForegroundColor $Colors.Section
    
    if (!(Test-Path $BackupFile)) {
        Write-Host "[ERROR] Backup file not found: $BackupFile" -ForegroundColor $Colors.Error
        return $false
    }
    
    try {
        $null = & reg import $BackupFile
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Registry restored from: $BackupFile" -ForegroundColor $Colors.Success
            return $true
        } else {
            Write-Host "[ERROR] Failed to restore registry" -ForegroundColor $Colors.Error
            return $false
        }
    }
    catch {
        Write-Host "[ERROR] Error restoring backup: $_" -ForegroundColor $Colors.Error
        return $false
    }
}

# =======================================================
# SAFE REGISTRY FUNCTIONS
# =======================================================

function Set-SafeRegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = 'DWORD',
        [switch]$CreatePath
    )
    
    try {
        # Check if path exists
        if (!(Test-Path $Path)) {
            if ($CreatePath) {
                $null = New-Item -Path $Path -Force
                Write-Host "[INFO] Created registry path: $Path" -ForegroundColor $Colors.Info
            } else {
                Write-Host "[SKIP] Registry path not found, skipping: $Path" -ForegroundColor $Colors.Gray
                return $false
            }
        } else {
            Write-Host "[INFO] Found registry path: $Path" -ForegroundColor $Colors.Info
        }
        
        # Check current value
        $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($currentValue -and $currentValue.$Name -eq $Value) {
            Write-Host "[OK] $Name already set to $Value" -ForegroundColor $Colors.Success
            return $true
        }
        
        # Set new value
        $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop
        Write-Host "[OK] Set $Name to $Value in $Path" -ForegroundColor $Colors.Success
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to set $Name in $Path : $_" -ForegroundColor $Colors.Error
        return $false
    }
}

function Remove-TelemetryDirectory {
    param([string]$Path)
    
    if (Test-Path $Path) {
        try {
            $itemCount = (Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
            if ($itemCount -gt 0) {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                Write-Host "[OK] Removed telemetry directory: $Path ($itemCount items)" -ForegroundColor $Colors.Success
            } else {
                Write-Host "[INFO] Telemetry directory already empty: $Path" -ForegroundColor $Colors.Info
            }
        }
        catch {
            Write-Host "[ERROR] Failed to remove: $Path - $_" -ForegroundColor $Colors.Error
        }
    } else {
        Write-Host "[SKIP] Telemetry directory not found: $Path" -ForegroundColor $Colors.Gray
    }
}

function Disable-BackgroundDownloadTasks {
    Write-Host "[INFO] Checking for Visual Studio BackgroundDownload scheduled tasks..." -ForegroundColor $Colors.Info
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -like "*BackgroundDownload*" -or 
            ($_.TaskPath -like "*VisualStudio*" -and $_.TaskName -like "*BackgroundDownload*")
        }
        
        if ($tasks) {
            foreach ($task in $tasks) {
                Write-Host "[INFO] Found task: $($task.TaskName) at $($task.TaskPath)" -ForegroundColor $Colors.Info
                
                if ($task.State -eq "Ready") {
                    try {
                        Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
                        Write-Host "[OK] Disabled task: $($task.TaskName)" -ForegroundColor $Colors.Success
                    }
                    catch {
                        Write-Host "[ERROR] Could not disable task $($task.TaskName): $_" -ForegroundColor $Colors.Error
                    }
                } else {
                    Write-Host "[OK] Task already disabled: $($task.TaskName)" -ForegroundColor $Colors.Success
                }
            }
            return $true
        } else {
            Write-Host "[SKIP] No Visual Studio BackgroundDownload tasks found" -ForegroundColor $Colors.Gray
            return $false
        }
    } catch {
        Write-Host "[ERROR] Error checking scheduled tasks: $_" -ForegroundColor $Colors.Error
        return $false
    }
}

function Stop-BackgroundDownloadProcesses {
    Write-Host "[INFO] Checking for running BackgroundDownload processes..." -ForegroundColor $Colors.Info
    
    try {
        $processes = Get-Process -Name "BackgroundDownload" -ErrorAction SilentlyContinue
        if ($processes) {
            foreach ($process in $processes) {
                try {
                    Stop-Process -Id $process.Id -Force -ErrorAction Stop
                    Write-Host "[OK] Stopped process: BackgroundDownload.exe (PID: $($process.Id))" -ForegroundColor $Colors.Success
                }
                catch {
                    Write-Host "[ERROR] Could not stop process PID $($process.Id): $_" -ForegroundColor $Colors.Error
                }
            }
            return $true
        } else {
            Write-Host "[SKIP] No BackgroundDownload processes currently running" -ForegroundColor $Colors.Gray
            return $false
        }
    } catch {
        Write-Host "[ERROR] Error checking processes: $_" -ForegroundColor $Colors.Error
        return $false
    }
}

function Remove-BackgroundDownloadTempFolders {
    Write-Host "[INFO] Cleaning BackgroundDownload temporary folders..." -ForegroundColor $Colors.Info
    
    try {
        $tempPaths = @(
            "$env:TEMP",
            "$env:LOCALAPPDATA\Temp"
        )
        
        $foldersRemoved = 0
        foreach ($tempPath in $tempPaths) {
            if (Test-Path $tempPath) {
                $folders = Get-ChildItem -Path $tempPath -Directory -ErrorAction SilentlyContinue | 
                          Where-Object { $_.Name -match "^[a-zA-Z0-9]{8}\." }
                
                foreach ($folder in $folders) {
                    $bgDownloadPath = Join-Path $folder.FullName "resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe"
                    if (Test-Path $bgDownloadPath) {
                        try {
                            Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                            Write-Host "[OK] Removed temp folder: $($folder.Name)" -ForegroundColor $Colors.Success
                            $foldersRemoved++
                        }
                        catch {
                            Write-Host "[ERROR] Could not remove folder $($folder.Name): $_" -ForegroundColor $Colors.Error
                        }
                    }
                }
            }
        }
        
        if ($foldersRemoved -eq 0) {
            Write-Host "[SKIP] No BackgroundDownload temp folders found" -ForegroundColor $Colors.Gray
        }
        
        return $foldersRemoved -gt 0
    } catch {
        Write-Host "[ERROR] Error cleaning temp folders: $_" -ForegroundColor $Colors.Error
        return $false
    }
}

function Set-SafeEnvironmentVariable {
    param(
        [string]$Name,
        [string]$Value,
        [string]$Target = 'User'
    )
    
    try {
        $currentValue = [Environment]::GetEnvironmentVariable($Name, $Target)
        if ($currentValue -eq $Value) {
            Write-Host "[OK] $Name already set to $Value" -ForegroundColor $Colors.Success
        } else {
            [Environment]::SetEnvironmentVariable($Name, $Value, $Target)
            Write-Host "[OK] Set $Name to $Value" -ForegroundColor $Colors.Success
        }
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to set environment variable $Name : $_" -ForegroundColor $Colors.Error
        return $false
    }
}

# =======================================================
# MAIN SCRIPT LOGIC
# =======================================================

# Handle backup/restore operations
if ($RestoreBackup) {
    $null = Restore-RegistryBackup -BackupFile $BackupPath
    Write-Host "`nRestore operation completed. Press Enter to exit..." -ForegroundColor $Colors.Info
    $null = Read-Host
    exit
}

if ($CreateBackup) {
    $null = New-RegistryBackup -BackupFile $BackupPath
    Write-Host "`nBackup created at: $BackupPath" -ForegroundColor $Colors.Info
    Write-Host "You can restore with: .\off_telemetry_ps5.ps1 -RestoreBackup -BackupPath '$BackupPath'" -ForegroundColor $Colors.Info
    
    $continue = Read-Host "`nContinue with telemetry disable? (y/n)"
    if ($continue -ne 'y' -and $continue -ne 'Y') {
        exit
    }
}

# =======================================================
# DETECT INSTALLED VISUAL STUDIO VERSIONS
# =======================================================
Write-Host "`n--- Detecting Installed Visual Studio Versions ---" -ForegroundColor $Colors.Section

$vsVersions = @{
    "14.0" = "Visual Studio 2015"
    "15.0" = "Visual Studio 2017" 
    "16.0" = "Visual Studio 2019"
    "17.0" = "Visual Studio 2022"
}

$installedVersions = @()
foreach ($version in $vsVersions.Keys) {
    $vsName = $vsVersions[$version]
    
    # Check multiple detection methods
    $detected = $false
    
    # Method 1: Registry SQM paths
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\VSCommon\$version",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\$version"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $detected = $true
            break
        }
    }
    
    # Method 2: Installation paths
    if (!$detected) {
        $installPaths = @(
            "${env:ProgramFiles}\Microsoft Visual Studio\*\*\Common7\IDE\devenv.exe",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\*\*\Common7\IDE\devenv.exe",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio $version\*\Common7\IDE\devenv.exe"
        )
        
        foreach ($installPath in $installPaths) {
            if (Get-ChildItem -Path $installPath -ErrorAction SilentlyContinue) {
                $detected = $true
                break
            }
        }
    }
    
    if ($detected) {
        Write-Host "[OK] Detected: $vsName (version $version)" -ForegroundColor $Colors.Success
        $installedVersions += $version
    } else {
        Write-Host "[SKIP] Not found: $vsName (version $version)" -ForegroundColor $Colors.Gray
    }
}

if ($installedVersions.Count -eq 0) {
    Write-Host "[INFO] No Visual Studio installations detected" -ForegroundColor $Colors.Info
}

# =======================================================
# VISUAL STUDIO TELEMETRY DISABLE (EXISTING INSTALLATIONS ONLY)
# =======================================================
Write-Host "`n--- Disabling Visual Studio Telemetry (Detected Installations) ---" -ForegroundColor $Colors.Section

foreach ($version in $installedVersions) {
    $vsName = $vsVersions[$version]
    Write-Host "`n--- Processing $vsName (version $version) ---" -ForegroundColor $Colors.Info
    
    # Process both architectures
    $regPaths = @()
    if ([Environment]::Is64BitOperatingSystem) {
        $regPaths += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\$version\SQM"
    }
    $regPaths += "HKLM:\SOFTWARE\Microsoft\VSCommon\$version\SQM"
    
    foreach ($regPath in $regPaths) {
        $null = Set-SafeRegistryValue -Path $regPath -Name "OptIn" -Value 0 -Type 'DWORD'
    }
    
    # Additional paths for this version
    $additionalPaths = @(
        "HKCU:\Software\Microsoft\VisualStudio\$version\General"
    )
    
    foreach ($path in $additionalPaths) {
        $null = Set-SafeRegistryValue -Path $path -Name "EnableSQM" -Value 0 -Type 'DWORD'
    }
}

# =======================================================
# VISUAL STUDIO POLICY SETTINGS (CONSERVATIVE APPROACH)
# =======================================================
Write-Host "`n--- Checking Visual Studio Policy Settings ---" -ForegroundColor $Colors.Section

# Only create policy paths if at least one VS version is installed
if ($installedVersions.Count -gt 0) {
    Write-Host "[INFO] Visual Studio detected, configuring policies..." -ForegroundColor $Colors.Info
    
    # Policy paths (create only if VS is installed)
    $policyPaths = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" = @{
            "DisableFeedbackDialog" = 1
            "DisableEmailInput" = 1
            "DisableScreenshotCapture" = 1
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\SQM" = @{
            "OptIn" = 0
        }
        "HKCU:\Software\Microsoft\VisualStudio\Telemetry" = @{
            "TurnOffSwitch" = 1
        }
    }
    
    foreach ($path in $policyPaths.Keys) {
        $settings = $policyPaths[$path]
        foreach ($setting in $settings.GetEnumerator()) {
            $null = Set-SafeRegistryValue -Path $path -Name $setting.Key -Value $setting.Value -Type 'DWORD' -CreatePath
        }
    }
} else {
    Write-Host "[SKIP] No Visual Studio detected, skipping policy configuration" -ForegroundColor $Colors.Gray
}

# =======================================================
# EXPERIENCE IMPROVEMENT PROGRAM
# =======================================================
Write-Host "`n--- Disabling Customer Experience Improvement Program ---" -ForegroundColor $Colors.Section

$experiencePaths = @(
    "HKLM:\SOFTWARE\Microsoft\SQMClient",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\SQMClient"
)

foreach ($path in $experiencePaths) {
    $null = Set-SafeRegistryValue -Path $path -Name "CEIPEnable" -Value 0 -Type 'DWORD'
}

# =======================================================
# TELEMETRY DIRECTORIES CLEANUP
# =======================================================
Write-Host "`n--- Cleaning Telemetry Directories ---" -ForegroundColor $Colors.Section

$telemetryDirs = @(
    "$env:APPDATA\vstelemetry",
    "$env:LOCALAPPDATA\Microsoft\VSApplicationInsights",
    "$env:PROGRAMDATA\Microsoft\VSApplicationInsights",
    "$env:TEMP\Microsoft\VSApplicationInsights",
    "$env:TEMP\VSFaultInfo",
    "$env:TEMP\VSFeedbackIntelliCodeLogs",
    "$env:TEMP\VSFeedbackPerfWatsonData",
    "$env:TEMP\VSFeedbackVSRTCLogs",
    "$env:TEMP\VSRemoteControl",
    "$env:TEMP\VSTelem",
    "$env:TEMP\VSTelem.Out"
)

foreach ($dir in $telemetryDirs) {
    Remove-TelemetryDirectory -Path $dir
}

# =======================================================
# .NET AND NUGET TELEMETRY DISABLE
# =======================================================
Write-Host "`n--- Disabling .NET and NuGet Telemetry ---" -ForegroundColor $Colors.Section

$null = Set-SafeEnvironmentVariable -Name 'DOTNET_CLI_TELEMETRY_OPTOUT' -Value '1' -Target 'User'
$null = Set-SafeEnvironmentVariable -Name 'NUGET_TELEMETRY_OPTOUT' -Value 'true' -Target 'User'

# =======================================================
# VISUAL STUDIO STANDARD COLLECTOR SERVICE
# =======================================================
Write-Host "`n--- Managing VS Standard Collector Service ---" -ForegroundColor $Colors.Section

$serviceName = 'VSStandardCollectorService150'
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    Write-Host "[INFO] Found service: $serviceName" -ForegroundColor $Colors.Info
    
    # Stop service if running
    if ($service.Status -eq 'Running') {
        try {
            Stop-Service -Name $serviceName -Force -ErrorAction Stop
            Write-Host "[OK] Stopped $serviceName" -ForegroundColor $Colors.Success
        }
        catch {
            Write-Host "[ERROR] Could not stop $serviceName : $_" -ForegroundColor $Colors.Error
        }
    } else {
        Write-Host "[INFO] Service $serviceName already stopped (Status: $($service.Status))" -ForegroundColor $Colors.Info
    }
    
    # Disable service
    if ($service.StartType -eq 'Disabled') {
        Write-Host "[OK] $serviceName already disabled" -ForegroundColor $Colors.Success
    } else {
        try {
            Set-Service -Name $serviceName -StartupType Disabled -Confirm:$false -ErrorAction Stop
            Write-Host "[OK] Disabled $serviceName" -ForegroundColor $Colors.Success
        }
        catch {
            Write-Host "[ERROR] Could not disable $serviceName : $_" -ForegroundColor $Colors.Error
        }
    }
} else {
    Write-Host "[SKIP] $serviceName not found (not installed)" -ForegroundColor $Colors.Gray
}

$serviceProcessed = ($null -ne $service)

# =======================================================
# VISUAL STUDIO CODE SETTINGS
# =======================================================
Write-Host "`n--- Configuring Visual Studio Code Settings ---" -ForegroundColor $Colors.Section

$vscodeSettings = "$env:APPDATA\Code\User\settings.json"
$vscodeUserDir = "$env:APPDATA\Code\User"
$vscodeDetected = $false

if (!(Test-Path "$env:APPDATA\Code")) {
    Write-Host "[SKIP] Visual Studio Code not detected" -ForegroundColor $Colors.Gray
} else {
    Write-Host "[INFO] Visual Studio Code detected" -ForegroundColor $Colors.Info
    $vscodeDetected = $true
    
    # Create User directory if needed
    if (!(Test-Path $vscodeUserDir)) {
        try {
            $null = New-Item -Path $vscodeUserDir -ItemType Directory -Force
            Write-Host "[INFO] Created VS Code User directory" -ForegroundColor $Colors.Info
        } catch {
            Write-Host "[ERROR] Failed to create VS Code User directory: $_" -ForegroundColor $Colors.Error
        }
    }

    # Privacy settings
    $privacyConfig = @{
        "telemetry.enableTelemetry" = $false
        "telemetry.enableCrashReporter" = $false
        "workbench.enableExperiments" = $false
        "update.mode" = "manual"
        "update.showReleaseNotes" = $false
        "extensions.autoCheckUpdates" = $false
        "extensions.showRecommendationsOnlyOnDemand" = $true
        "git.autofetch" = $false
        "npm.fetchOnlinePackageInfo" = $false
    }

    try {
        # Load existing settings
        $settings = @{}
        if (Test-Path $vscodeSettings) {
            $content = Get-Content $vscodeSettings -Raw -ErrorAction SilentlyContinue
            if ($content -and $content.Trim()) {
                try {
                    # Use PowerShell's built-in JSON cmdlets
                    $settingsObj = $content | ConvertFrom-Json
                    # Convert PSCustomObject to hashtable for easier manipulation
                    $settings = @{}
                    $settingsObj.PSObject.Properties | ForEach-Object {
                        $settings[$_.Name] = $_.Value
                    }
                    Write-Host "[INFO] Found existing VS Code settings file" -ForegroundColor $Colors.Info
                }
                catch {
                    Write-Host "> Could not parse existing settings, creating new ones" -ForegroundColor $Colors.Warning
                    $settings = @{}
                }
            }
        }
        
        # Update settings
        $changesMade = $false
        foreach ($key in $privacyConfig.Keys) {
            $value = $privacyConfig[$key]
            if ($settings.ContainsKey($key) -and $settings[$key] -eq $value) {
                Write-Host "[OK] $key already set to $value" -ForegroundColor $Colors.Success
            } else {
                $settings[$key] = $value
                Write-Host "[OK] Updated $key to $value" -ForegroundColor $Colors.Success
                $changesMade = $true
            }
        }
        
        # Save settings if changes were made
        if ($changesMade -or !(Test-Path $vscodeSettings)) {
            $json = $settings | ConvertTo-Json -Depth 10
            $json | Out-File -FilePath $vscodeSettings -Encoding UTF8
            Write-Host "[OK] Saved VS Code privacy settings" -ForegroundColor $Colors.Success
        } else {
            Write-Host "[INFO] No changes needed for VS Code settings" -ForegroundColor $Colors.Info
        }
    }
    catch {
        Write-Host "[ERROR] Failed to update VS Code settings: $_" -ForegroundColor $Colors.Error
    }
}

# =======================================================
# VISUAL STUDIO BACKGROUND DOWNLOAD DISABLE
# =======================================================
Write-Host "`n--- Disabling Visual Studio Background Download ---" -ForegroundColor $Colors.Section

$backgroundDownloadProcessed = $false

# Check if any Visual Studio versions are installed before proceeding
if ($installedVersions.Count -gt 0) {
    Write-Host "[INFO] Visual Studio detected, processing BackgroundDownload settings..." -ForegroundColor $Colors.Info
    
    # 1. Disable scheduled tasks
    $tasksProcessed = Disable-BackgroundDownloadTasks
    
    # 2. Set registry keys to disable background downloads
    Write-Host "[INFO] Setting registry keys to disable background downloads..." -ForegroundColor $Colors.Info
    
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\Setup",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\Setup"
    )
    
    $regKeysSet = $false
    foreach ($regPath in $regPaths) {
        # Check if this registry path should exist (based on architecture)
        $shouldProcess = $true
        if ($regPath -like "*Wow6432Node*" -and ![Environment]::Is64BitOperatingSystem) {
            $shouldProcess = $false
        }
        
        if ($shouldProcess) {
            # Create the registry path if it doesn't exist (since we're configuring VS Setup)
            if (!(Test-Path $regPath)) {
                try {
                    $null = New-Item -Path $regPath -Force -ErrorAction Stop
                    Write-Host "[INFO] Created registry path: $regPath" -ForegroundColor $Colors.Info
                }
                catch {
                    Write-Host "[ERROR] Could not create registry path $regPath : $_" -ForegroundColor $Colors.Error
                    continue
                }
            }
            
            # Set the registry values
            $regSettings = @{
                "BackgroundDownloadDisabled" = 1
                "DisableBackgroundDownloads" = 1
                "DisableAutomaticUpdates" = 1
            }
            
            foreach ($setting in $regSettings.GetEnumerator()) {
                $success = Set-SafeRegistryValue -Path $regPath -Name $setting.Key -Value $setting.Value -Type 'DWORD'
                if ($success) {
                    $regKeysSet = $true
                }
            }
        }
    }
    
    # 3. Stop running processes
    $processesProcessed = Stop-BackgroundDownloadProcesses
    
    # 4. Clean temporary folders
    $tempFoldersProcessed = Remove-BackgroundDownloadTempFolders
    
    # 5. Verification
    Write-Host "[INFO] Verifying BackgroundDownload configuration..." -ForegroundColor $Colors.Info
    
    try {
        $verificationSuccess = $false
        
        # Check registry settings
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $regValues = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($regValues -and $regValues.BackgroundDownloadDisabled -eq 1) {
                    Write-Host "[OK] Registry verification: BackgroundDownloadDisabled = 1 in $regPath" -ForegroundColor $Colors.Success
                    $verificationSuccess = $true
                }
            }
        }
        
        if (!$verificationSuccess) {
            Write-Host "[WARNING] Could not verify registry settings" -ForegroundColor $Colors.Warning
        }
        
    } catch {
        Write-Host "[WARNING] Verification error: $_" -ForegroundColor $Colors.Warning
    }
    
    # Set processed flag if any operation was successful
    $backgroundDownloadProcessed = $tasksProcessed -or $regKeysSet -or $processesProcessed -or $tempFoldersProcessed
    
} else {
    Write-Host "[SKIP] No Visual Studio installations detected, skipping BackgroundDownload configuration" -ForegroundColor $Colors.Gray
}

# =======================================================
# POWERSHELL TELEMETRY [off] FOR PS 7.x 
# =======================================================
Write-Host "`n--- Disabling PowerShell Telemetry ---" -ForegroundColor $Colors.Section

# Check Windows version
$powershellTelemetryProcessed = $false
try {
    $osVersion = [System.Environment]::OSVersion.Version
    $windowsVersion = "$($osVersion.Major).$($osVersion.Minor)"
    
    # Windows version mapping:
    # Windows 7: 6.1
    # Windows 8: 6.2
    # Windows 8.1: 6.3
    # Windows 10: 10.0
    # Windows 11: 10.0 (build 22000+)
    
    $isWindows8Plus = ($osVersion.Major -gt 6) -or ($osVersion.Major -eq 6 -and $osVersion.Minor -ge 2)
    
    if ($isWindows8Plus) {
        Write-Host "[INFO] Windows version $windowsVersion detected (Windows 8+)" -ForegroundColor $Colors.Info
        $null = Set-SafeEnvironmentVariable -Name 'POWERSHELL_TELEMETRY_OPTOUT' -Value '1' -Target 'User'
        $powershellTelemetryProcessed = $true
    } else {
        Write-Host "[SKIP] Windows version $windowsVersion detected (Windows 7), skipping PowerShell telemetry disable" -ForegroundColor $Colors.Gray
        Write-Host "[INFO] PowerShell telemetry disable is only applied on Windows 8 and newer" -ForegroundColor $Colors.Info
    }
}
catch {
    Write-Host "[ERROR] Could not detect Windows version: $_" -ForegroundColor $Colors.Error
    Write-Host "[INFO] Attempting to disable PowerShell telemetry anyway..." -ForegroundColor $Colors.Info
    $null = Set-SafeEnvironmentVariable -Name 'POWERSHELL_TELEMETRY_OPTOUT' -Value '1' -Target 'User'
    $powershellTelemetryProcessed = $true
}

# =======================================================
# SUMMARY
# =======================================================
Write-Host "`n========================================" -ForegroundColor $Colors.Title
Write-Host "TELEMETRY DISABLE COMPLETE" -ForegroundColor $Colors.Title
Write-Host "========================================" -ForegroundColor $Colors.Title

Write-Host "`nProcessed telemetry settings for:" -ForegroundColor White

# Visual Studio versions with status colors
if ($installedVersions.Count -gt 0) {
    foreach ($version in $installedVersions) {
        Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
        Write-Host "$($vsVersions[$version]) (detected)" -ForegroundColor $Colors.Success
    }
} else {
    Write-Host "[SKIP] " -NoNewline -ForegroundColor $Colors.Gray
    Write-Host "No Visual Studio versions detected" -ForegroundColor $Colors.Gray
}

# Visual Studio Code with status colors
if ($vscodeDetected) {
    Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
    Write-Host "Visual Studio Code (detected)" -ForegroundColor $Colors.Success
} else {
    Write-Host "[SKIP] " -NoNewline -ForegroundColor $Colors.Gray
    Write-Host "Visual Studio Code (not found)" -ForegroundColor $Colors.Gray
}

# Other components with status indicators
Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
Write-Host ".NET CLI" -ForegroundColor $Colors.Success

Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
Write-Host "NuGet" -ForegroundColor $Colors.Success

Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
Write-Host "Settings Synchronization" -ForegroundColor $Colors.Success

# VS Standard Collector Service status
if ($serviceProcessed) {
    Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
    Write-Host "VS Standard Collector Service (processed)" -ForegroundColor $Colors.Success
} else {
    Write-Host "[SKIP] " -NoNewline -ForegroundColor $Colors.Gray
    Write-Host "VS Standard Collector Service (not found)" -ForegroundColor $Colors.Gray
}

# Visual Studio Background Download status
if ($backgroundDownloadProcessed) {
    Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
    Write-Host "Visual Studio Background Download (disabled)" -ForegroundColor $Colors.Success
} else {
    Write-Host "[SKIP] " -NoNewline -ForegroundColor $Colors.Gray
    Write-Host "Visual Studio Background Download (not processed)" -ForegroundColor $Colors.Gray
}

# PowerShell Telemetry status
if ($powershellTelemetryProcessed) {
    Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
    Write-Host "PowerShell 7 Telemetry (disabled)" -ForegroundColor $Colors.Success
} else {
    Write-Host "[SKIP] " -NoNewline -ForegroundColor $Colors.Gray
    Write-Host "PowerShell 7 Telemetry (Windows 7 - not supported)" -ForegroundColor $Colors.Gray
}

Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
Write-Host "Customer Experience Improvement Program" -ForegroundColor $Colors.Success

Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success
Write-Host "Telemetry Directories Cleanup" -ForegroundColor $Colors.Success

# =======================================================
# ADDITIONAL FEATURES AND ENVIRONMENT VARIABLES
# =======================================================
Write-Host "`n--- Optional: Additional Features and Environment Variables ---" -ForegroundColor $Colors.Section

Write-Host "This will perform additional configuration:" -ForegroundColor $Colors.Info
Write-Host "> Disable Visual Studio Settings Synchronization" -ForegroundColor $Colors.Info
Write-Host "> Disable Live Share" -ForegroundColor $Colors.Info
Write-Host "> Disable IntelliCode" -ForegroundColor $Colors.Info
Write-Host "> Disable CodeLens" -ForegroundColor $Colors.Info
Write-Host "> Set additional environment variables :" -ForegroundColor $Colors.Info
Write-Host "  - INTELLICODE_TELEMETRY_OPTOUT" -ForegroundColor $Colors.Info
Write-Host "  - LIVESHARE_TELEMETRY_OPTOUT" -ForegroundColor $Colors.Info
Write-Host "  - VSSDK_TELEMETRY_OPTOUT" -ForegroundColor $Colors.Info

$enableAdditional = Read-Host "`nEnable additional configuration? (y/n)"

if ($enableAdditional -eq 'y' -or $enableAdditional -eq 'Y' -or $enableAdditional -eq 'yes' -or $enableAdditional -eq 'Yes' -or $enableAdditional -eq 'YES') {
    
    # =======================================================
    # VISUAL STUDIO ADDITIONAL FEATURES DISABLE
    # =======================================================
    Write-Host "`n--- Disabling Additional Visual Studio Features ---" -ForegroundColor $Colors.Section
    
    if ($installedVersions.Count -gt 0) {
        foreach ($version in $installedVersions) {
            $vsName = $vsVersions[$version]
            Write-Host "`n--- Processing Additional Features for $vsName (version $version) ---" -ForegroundColor $Colors.Info
            
            # =======================================================
            # SETTINGS SYNCHRONIZATION
            # =======================================================
            Write-Host "[INFO] Disabling Settings Synchronization..." -ForegroundColor $Colors.Info
            
            $settingsPaths = @(
                "HKCU:\Software\Microsoft\VisualStudio\$version\Settings",
                "HKCU:\Software\Microsoft\VisualStudio\$version\ApplicationPrivateSettings\Microsoft\VisualStudio\Settings"
            )
            
            foreach ($path in $settingsPaths) {
                $null = Set-SafeRegistryValue -Path $path -Name "SyncSettings" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "EnableRoaming" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "EnableSync" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "DisableSync" -Value 1 -Type 'DWORD' -CreatePath
            }
            
            # Additional settings sync paths
            $syncPath = "HKCU:\Software\Microsoft\VisualStudio\$version\ApplicationPrivateSettings\Microsoft\VisualStudio\ConnectedServices"
            $null = Set-SafeRegistryValue -Path $syncPath -Name "Provider.Enabled" -Value 0 -Type 'DWORD' -CreatePath
            
            # =======================================================
            # LIVE SHARE
            # =======================================================
            Write-Host "[INFO] Disabling Live Share..." -ForegroundColor $Colors.Info
            
            $liveSharePaths = @(
                "HKCU:\Software\Microsoft\VisualStudio\$version\LiveShare",
                "HKCU:\Software\Microsoft\VisualStudio\$version\ApplicationPrivateSettings\Microsoft\VisualStudio\LiveShare"
            )
            
            foreach ($path in $liveSharePaths) {
                $null = Set-SafeRegistryValue -Path $path -Name "Enabled" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "EnableTelemetry" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "DisableTelemetry" -Value 1 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "OptedIn" -Value 0 -Type 'DWORD' -CreatePath
            }
            
            # Live Share telemetry
            $liveShareTelemetryPath = "HKCU:\Software\Microsoft\VisualStudio\$version\LiveShare\Telemetry"
            $null = Set-SafeRegistryValue -Path $liveShareTelemetryPath -Name "Enabled" -Value 0 -Type 'DWORD' -CreatePath
            $null = Set-SafeRegistryValue -Path $liveShareTelemetryPath -Name "OptOut" -Value 1 -Type 'DWORD' -CreatePath
            
            # =======================================================
            # INTELLICODE
            # =======================================================
            Write-Host "[INFO] Disabling IntelliCode..." -ForegroundColor $Colors.Info
            
            $intelliCodePaths = @(
                "HKCU:\Software\Microsoft\VisualStudio\$version\IntelliCode",
                "HKCU:\Software\Microsoft\VisualStudio\$version\IntelliSense\IntelliCode",
                "HKCU:\Software\Microsoft\VisualStudio\$version\ApplicationPrivateSettings\Microsoft\VisualStudio\IntelliCode"
            )
            
            foreach ($path in $intelliCodePaths) {
                $null = Set-SafeRegistryValue -Path $path -Name "DisableTelemetry" -Value 1 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "EnableTelemetry" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "OptedIn" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "Enabled" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "ModelDownloadEnabled" -Value 0 -Type 'DWORD' -CreatePath
            }
            
            # IntelliCode privacy settings
            $intelliCodePrivacyPath = "HKCU:\Software\Microsoft\VisualStudio\$version\IntelliCode\Privacy"
            $null = Set-SafeRegistryValue -Path $intelliCodePrivacyPath -Name "TelemetryOptOut" -Value 1 -Type 'DWORD' -CreatePath
            $null = Set-SafeRegistryValue -Path $intelliCodePrivacyPath -Name "DataCollection" -Value 0 -Type 'DWORD' -CreatePath
            $null = Set-SafeRegistryValue -Path $intelliCodePrivacyPath -Name "UsageDataOptOut" -Value 1 -Type 'DWORD' -CreatePath
            
            # =======================================================
            # CODELENS
            # =======================================================
            Write-Host "[INFO] Disabling CodeLens..." -ForegroundColor $Colors.Info
            
            $codeLensPaths = @(
                "HKCU:\Software\Microsoft\VisualStudio\$version\CodeLens",
                "HKCU:\Software\Microsoft\VisualStudio\$version\TextEditor\CodeLens",
                "HKCU:\Software\Microsoft\VisualStudio\$version\ApplicationPrivateSettings\Microsoft\VisualStudio\CodeLens"
            )
            
            foreach ($path in $codeLensPaths) {
                $null = Set-SafeRegistryValue -Path $path -Name "Disabled" -Value 1 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "ShowAuthorCodeLens" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "ShowReferencesCodeLens" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "ShowTestCodeLens" -Value 0 -Type 'DWORD' -CreatePath
                $null = Set-SafeRegistryValue -Path $path -Name "Enabled" -Value 0 -Type 'DWORD' -CreatePath
            }
            
            # CodeLens telemetry
            $codeLensTelemetryPath = "HKCU:\Software\Microsoft\VisualStudio\$version\CodeLens\Telemetry"
            $null = Set-SafeRegistryValue -Path $codeLensTelemetryPath -Name "Enabled" -Value 0 -Type 'DWORD' -CreatePath
            $null = Set-SafeRegistryValue -Path $codeLensTelemetryPath -Name "OptOut" -Value 1 -Type 'DWORD' -CreatePath
        }
        } else {
            Write-Host "[SKIP] No Visual Studio installations detected, skipping additional features" -ForegroundColor $Colors.Gray
        }
        
        # =======================================================
        # ADDITIONAL ENVIRONMENT VARIABLES
        # =======================================================
        Write-Host "`n--- Setting Additional Environment Variables ---" -ForegroundColor $Colors.Section
        
        $null = Set-SafeEnvironmentVariable -Name 'INTELLICODE_TELEMETRY_OPTOUT' -Value '1' -Target 'User'
        $null = Set-SafeEnvironmentVariable -Name 'LIVESHARE_TELEMETRY_OPTOUT' -Value '1' -Target 'User'
        $null = Set-SafeEnvironmentVariable -Name 'VSSDK_TELEMETRY_OPTOUT' -Value '1' -Target 'User'
        
        Write-Host "`n[OK] Additional configuration completed" -ForegroundColor $Colors.Success
    } else {
        Write-Host "[SKIP] Skipping additional configuration" -ForegroundColor $Colors.Info
    }

Write-Host "`nLegend:" -ForegroundColor White
Write-Host "[OK] " -NoNewline -ForegroundColor $Colors.Success; Write-Host "Action completed successfully"
Write-Host "[INFO] " -NoNewline -ForegroundColor $Colors.Info; Write-Host "Information or preparatory action"
Write-Host "[SKIP] " -NoNewline -ForegroundColor $Colors.Gray; Write-Host "Component not found, skipped"
Write-Host "[ERROR] " -NoNewline -ForegroundColor $Colors.Error; Write-Host "Error occurred"

if (!$CreateBackup) {
    Write-Host "`nTip: Run with -CreateBackup parameter to create registry backup first" -ForegroundColor $Colors.Warning
}

Write-Host "`nRestart may be required for all changes to take effect." -ForegroundColor $Colors.Warning
Write-Host "Press Enter to exit..." -ForegroundColor White
$null = Read-Host
