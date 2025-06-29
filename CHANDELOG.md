# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure
- Comprehensive documentation

## [1.0.0] - 2024-12-01

### Added
- **PowerShell 7.0+ Enhanced Script** (`off_telemetry_ps7.ps1`)
  - Advanced registry backup and restore functionality
  - Color-coded output with comprehensive status reporting
  - Smart detection of installed Visual Studio versions
  - Enhanced error handling and validation
  - PowerShell 7 specific optimizations

- **PowerShell 5.1 Compatible Script** (`off_telemetry_ps5.ps1`)
  - Full compatibility with Windows PowerShell 5.1
  - Core telemetry disable functionality
  - Backup and restore capabilities

- **Interactive Launcher** (`Launcher.bat`)
  - Automatic PowerShell version detection
  - Administrator privilege validation
  - User-friendly interactive interface
  - Smart script selection based on available PowerShell versions

- **Comprehensive Telemetry Disable Support**:
  - Visual Studio 2015, 2017, 2019, 2022
  - Visual Studio Code settings configuration
  - .NET CLI telemetry opt-out
  - NuGet telemetry disable
  - Windows SQM Client disable
  - VS Standard Collector Service management

- **Safety Features**:
  - Registry backup creation with timestamps
  - Registry restore functionality
  - Only modifies existing registry paths
  - Comprehensive validation and error handling
  - Administrator privilege requirements

- **Advanced Features**:
  - Environment variable management
  - Telemetry directory cleanup
  - Service management (stop/disable)
  - VS Code settings.json privacy configuration
  - Detailed status reporting with color coding

### Features by Component

#### Visual Studio Support
- ✅ Visual Studio 2015 (14.0)
- ✅ Visual Studio 2017 (15.0) 
- ✅ Visual Studio 2019 (16.0)
- ✅ Visual Studio 2022 (17.0)
- ✅ Customer Experience Improvement Program disable
- ✅ Feedback dialog disable
- ✅ Crash reporting disable

#### Visual Studio Code Support
- ✅ Telemetry reporting disable
- ✅ Crash reporter disable
- ✅ Experiments disable
- ✅ Automatic updates control
- ✅ Extension recommendations control
- ✅ Privacy-focused settings configuration

#### .NET and NuGet Support
- ✅ .NET CLI telemetry opt-out (`DOTNET_CLI_TELEMETRY_OPTOUT=1`)
- ✅ NuGet telemetry opt-out (`NUGET_TELEMETRY_OPTOUT=true`)
- ✅ PowerShell telemetry opt-out (`POWERSHELL_TELEMETRY_OPTOUT=1`)

#### System Services
- ✅ VS Standard Collector Service 150 management
- ✅ Windows SQM Client disable
- ✅ Application Insights data collection disable

#### Registry Areas Modified
- `HKLM:\SOFTWARE\Microsoft\VSCommon\*\SQM`
- `HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\*\SQM`
- `HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio`
- `HKCU:\Software\Microsoft\VisualStudio`
- `HKLM:\SOFTWARE\Microsoft\SQMClient`
- `HKLM:\SOFTWARE\Wow6432Node\Microsoft\SQMClient`

#### Telemetry Directories Cleaned
- `%APPDATA%\vstelemetry`
- `%LOCALAPPDATA%\Microsoft\VSApplicationInsights`
- `%PROGRAMDATA%\Microsoft\VSApplicationInsights`
- `%TEMP%\Microsoft\VSApplicationInsights`
- `%TEMP%\VSFaultInfo`
- `%TEMP%\VSFeedbackIntelliCodeLogs`
- `%TEMP%\VSFeedbackPerfWatsonData`
- `%TEMP%\VSFeedbackVSRTCLogs`
- `%TEMP%\VSRemoteControl`
- `%TEMP%\VSTelem`
- `%TEMP%\VSTelem.Out`

### Technical Improvements
- **PowerShell 7.0+ Optimizations**:
  - Using namespace declarations for better performance
  - Enhanced error handling with detailed reporting
  - Modern PowerShell cmdlets usage
  - Improved JSON handling for VS Code settings

- **Cross-Platform PowerShell Support**:
  - Separate scripts for PS 5.1 and PS 7.0+
  - Automatic version detection in launcher
  - Fallback mechanisms for different PowerShell versions

- **Enhanced User Experience**:
  - Color-coded output for better readability
  - Progress indicators and status reporting
  - Interactive confirmations and user choices
  - Comprehensive help and usage examples

### Documentation
- 📖 Comprehensive README.md with usage examples
- 📋 CONTRIBUTING.md for developers
- 🔒 SECURITY.md for security considerations
- 📄 MIT License
- 📝 Detailed inline code documentation

### Supported Platforms
- ✅ Windows 10 (all editions)
- ✅ Windows 11 (all editions)
- ✅ Windows 7 SP1
- ✅ Windows 8/8.1
- ✅ Windows Server 2016+

- ✅ PowerShell 5.1 (Windows PowerShell)
- ✅ PowerShell 7.0+ (Cross-platform PowerShell)

## [0.9.5] - 2025-06-26 (Pre-release)

### Added
- Initial script development
- Basic telemetry disable functionality
- Registry modification capabilities

### Changed
- Improved error handling
- Enhanced output formatting

### Fixed
- Registry path validation issues
- Service management permissions

## Release Notes

### Version 1.0.0 Highlights

This is the first stable release of the Visual Studio Telemetry Disable Tool. Key highlights include:

1. **Production Ready**: Thoroughly tested on multiple Windows configurations
2. **Comprehensive Coverage**: Supports all major Microsoft development tools
3. **Safety First**: Built-in backup and restore functionality
4. **User Friendly**: Interactive launcher and clear status reporting
5. **Developer Friendly**: Well-documented code and contribution guidelines

### Upgrade Instructions

This is the initial release. Future versions will include upgrade instructions here.

### Breaking Changes

None in this initial release.

### Deprecations

None in this initial release.

### Known Issues

- Some registry changes may require a system restart to take full effect
- VS Code must be closed during settings modification for changes to apply
- Administrator privileges are required for all operations

### Future Roadmap

See [README.md](README.md#roadmap) for planned features and improvements.

---

**Note**: This changelog follows the [Keep a Changelog](https://keepachangelog.com/) format. Each release includes:
- **Added** for new features
- **Changed** for changes in existing functionality  
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes