
# Deskside Support PowerShell Toolkit

## Overview
This repository contains a collection of PowerShell scripts and batch files designed to automate and streamline deskside support tasks. The toolkit is intended for IT professionals managing Windows environments and includes scripts for application installation, system configuration, and other common support activities.

## Features
- **RunThisAdmin.bat**: A batch file to run DISM commands, import power schemes, and execute the main PowerShell script.
- **Main.ps1**: The primary PowerShell script that performs a series of system management tasks.
- **Adobe Update (Acrobat.bat)**: Batch script for updating Adobe Acrobat.
- **Agent.msi**: Installer for a support agent.
- **CustomFileAssoc.xml**: XML file for custom file associations.
- **DCU.bat & DCU.exe**: Scripts and executables for Dell Command Update.
- **S1.bat & S1.exe**: Batch and executable files for a specific task (details not provided).
- **S1Token.txt**: A token file associated with S1 scripts.
- **scheme.pow**: Power scheme configuration file.

## Directory Structure
```
.
├── Dependencies
│   ├── CustomFileAssoc.xml
│   ├── Main.ps1
│   └── scheme.pow
├── Testing
│   └── (Testing-related files)
├── RunThisAdmin.bat
├── Acrobat.bat
├── Agent.msi
├── DCU.bat
├── DCU.exe
├── S1.bat
├── S1.exe
├── S1Token.txt
└── scheme.pow
```

## Getting Started
Follow these instructions to get the project up and running on your local machine.

### Prerequisites
- Windows operating system
- Administrator privileges
- PowerShell 5.1 or later

### Installation
1. **Clone the repository:**
    ```bash
    git clone https://github.com/phpwun/DesksideSupportPS.git
    ```
2. **Navigate to the script directory:**
    ```bash
    cd DesksideSupportPS
    ```
3. **Run the setup script with administrative privileges:**
    ```bash
    .\RunThisAdmin.bat
    ```

### RunThisAdmin.bat
This batch file performs the following actions:
- Imports default app associations using DISM.
    ```bash
    Dism.exe /online /import-defaultappassociations:%~dp0Dependencies\CustomFileAssoc.xml
    ```
- Imports a power scheme configuration.
    ```bash
    powercfg /import %~dp0Dependencies\scheme.pow
    ```
- Executes the main PowerShell script.
    ```bash
    powershell -ep Bypass %~dp0Dependencies\Main.ps1
    ```
- Pauses the command prompt to review any output or errors.
    ```bash
    pause
    ```

## Usage
### Main.ps1
The primary PowerShell script included in the Dependencies folder. The script performs various system management tasks.

To execute the script individually:
```powershell
.\Dependencies\Main.ps1
```

### Other Scripts
- **Acrobat.bat**: Run this script to update Adobe Acrobat.
    ```bash
    .\Acrobat.bat
    ```
- **DCU.bat**: Execute this script to perform updates using Dell Command Update.
    ```bash
    .\DCU.bat
    ```

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning
We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/phpwun/DesksideSupportPS/tags).

## Authors
- **phpwun** - *Initial work* - [GitHub Profile](https://github.com/phpwun)

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments
- Thanks to all contributors and community members for their support.
- Hat tip to anyone whose code was used.
