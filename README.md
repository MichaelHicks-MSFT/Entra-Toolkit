# Entra Toolkit

## Purpose

This toolkit provides administrators with practical PowerShell scripts to:
- Identify exemptions from app management policies

## What's Included

### App Management Scripts
- **[Get-AppManagementPolicyExemptions](./Scripts/AppManagement/)** - Audit all exemptions from app management policies including both applications and caller exemptions (users/service principals)

### Coming Soon
- TBD

## Quick Start

### Prerequisites
- PowerShell 5.1 or later
- Appropriate Microsoft Entra ID permissions
- Microsoft.graph.Authentication module

### Installation

1. Clone this repository:
   ```powershell
   git clone https://github.com/MichaelHicks-MSFT/Entra-Toolkit.git
   cd entra-toolkit
   ```

2. Connect to Microsoft Graph:
   ```powershell
   Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All","User.Read.All"
   ```

3. Run a script:
   ```powershell
   . .\Scripts\AppManagement\Get-AppManagementPolicyExemptions.ps1
   Get-AppManagementPolicyExemptions
   ```

## Documentation

Each script folder contains detailed documentation:
- [App Management Scripts](./Scripts/AppManagement/README.md)

## Security & Permissions

All scripts use Microsoft Graph API. Review the permission requirements in each script's documentation before running.

## Contributing

Contributions are welcome! Feel free to:
- Submit bug reports or feature requests via Issues
- Fork the repository and submit Pull Requests

## Disclaimer

These scripts are provided as-is without warranty. Always test in a non-production environment first.
