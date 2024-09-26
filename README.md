# Deskside Support PowerShell Toolkit

## Overview
This repository contains a collection of PowerShell scripts designed to automate and streamline deskside support tasks. The toolkit is intended for IT professionals managing Windows environments and includes scripts for application installation, system configuration, and other common support activities.

## Features
- **Main.ps1**: The primary PowerShell script that performs a series of system management tasks.
- **HashTokens.ps1**: A separate script to hash and store sensitive tokens securely.
- Modular and organized script structure for easy maintenance and updates.
- Integration of batch file functionality into the main PowerShell script.
- Enhanced security measures for handling sensitive tokens and information.
- Improved error handling and informative output messages.
- Consistent naming conventions and code formatting for better readability.

## Directory Structure
```
.
├── Dependencies
│   ├── Configurations
│   │   └── CustomFileAssoc.xml
│   ├── Executables
│   │   ├── Agent.msi
│   │   ├── DCU.exe
│   │   └── S1.exe
│   ├── Hashes_Tokens
│   │   ├── acrobat_serial.txt
│   │   └── s1token.txt
│   └── Scripts
│       ├── HashTokens.ps1
│       └── Main.ps1
└── README.md
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
   git clone https://github.com/yourusername/DesksideSupportPS.git
   ```

2. **Navigate to the script directory:**
   ```bash
   cd DesksideSupportPS
   ```

3. **Run the HashTokens.ps1 script to hash and store sensitive tokens:**
   ```powershell
   .\Dependencies\Scripts\HashTokens.ps1
   ```

   Make sure to update the script with your actual token values before running it.

4. **Execute the main PowerShell script with administrative privileges:**
   ```powershell
   .\Dependencies\Scripts\Main.ps1
   ```

## Usage
### Main.ps1
The primary PowerShell script included in the `Dependencies\Scripts` directory. The script performs various system management tasks and provides a menu-driven interface for executing different deskside support tasks.

To execute the script individually:
```powershell
.\Dependencies\Scripts\Main.ps1
```

### HashTokens.ps1
A separate PowerShell script located in the `Dependencies\Scripts` directory. This script is responsible for hashing sensitive tokens and storing them securely in the `Dependencies\Hashes_Tokens` directory.

To hash and store the tokens:
1. Open the `HashTokens.ps1` script and replace the placeholder token values with your actual tokens.
2. Run the script:
   ```powershell
   .\Dependencies\Scripts\HashTokens.ps1
   ```
3. The script will hash the tokens using the SHA-256 algorithm and store the hashed values in the respective files within the `Dependencies\Hashes_Tokens` directory.
4. Delete the plaintext tokens from the `HashTokens.ps1` script and ensure they are not stored anywhere else.

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments
- Thanks to all contributors and community members for their support.
- Hat tip to anyone whose code was used.
