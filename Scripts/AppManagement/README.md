# Get-AppManagementPolicyExemptions

A PowerShell function to identify all exemptions from Application Management Policies in Microsoft Entra ID.

## Overview

This function queries Microsoft Graph API to discover:
- **Application Exemptions**: Applications exempt from app management policies via custom policies
- **Caller Exemptions**: Users and service principals (enterprise applications) exempt via custom security attributes

Returns a unified view showing exemption type, principal details, and exemption methods.

## Requirements

### Microsoft Graph Permissions
- `Policy.Read.All`
- `Application.Read.All`
- `User.Read.All`

## Installation

1. Download the `Get-AppManagementPolicyExemptions.ps1` file
2. Import the function:
   ```powershell
   . .\Get-AppManagementPolicyExemptions.ps1
   ```

## Usage

### Basic Usage
```powershell
# Get all exemptions (applications and callers)
$exemptions = Get-AppManagementPolicyExemptions
```

### View Results
```powershell
# Display in table format
$exemptions | Format-Table -AutoSize

# Export to CSV
$exemptions | Export-Csv -Path "AllExemptions.csv" -NoTypeInformation
```

### Filter by Type
```powershell
# Get only application exemptions
$appExemptions = Get-AppManagementPolicyExemptions -IncludeCallers $false

# Get only caller exemptions
$callerExemptions = Get-AppManagementPolicyExemptions -IncludeApps $false
```

### Use Friendly Names
```powershell
# Display human-readable restriction names
$exemptions = Get-AppManagementPolicyExemptions -UseFriendlyNames
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `IncludeApps` | Boolean | `$true` | Include application exemptions in results |
| `IncludeCallers` | Boolean | `$true` | Include caller (user/service principal) exemptions in results |
| `UseFriendlyNames` | Switch | `$false` | Display human-readable restriction names instead of technical names |

## Output

The function returns an array of objects with the following properties:

| Property | Description | Example |
|----------|-------------|---------|
| `ExemptionType` | Type of exemption | `Application` or `Caller` |
| `DisplayName` | Name of the exempt entity | `App1` |
| `PrincipalType` | Type of principal | `User` or `ServicePrincipal` |
| `ExemptedFrom` | Which restrictions are exempted | `passwordAddition, symmetricKeyAddition` |
| `ExemptionMethod` | How exemption is applied | `Custom Policy` or `Custom Security Attribute` |

### Example Output

```
ExemptionType DisplayName        PrincipalType     ExemptedFrom                           ExemptionMethod
------------- -----------        -------------     ------------                           ---------------
Application   App1               Application       passwordAddition, symmetricKeyAddition Custom Policy
Caller        User1              User              passwordAddition                       Custom Security Attribute
Caller        MyEnterpriseApp    ServicePrincipal  passwordAddition                       Custom Security Attribute
Caller        User2              User              asymmetricKeyLifetime                  Custom Security Attribute
```

### With Friendly Names

```powershell
Get-AppManagementPolicyExemptions -UseFriendlyNames
```

```
ExemptionType DisplayName        PrincipalType     ExemptedFrom                                           ExemptionMethod
------------- -----------        -------------     ------------                                           ---------------
Application   App1               Application       Block Password Addition, Block Symmetric Key Addition  Custom Policy
Caller        User1              User              Block Password Addition                                Custom Security Attribute
Caller        MyEnterpriseApp    ServicePrincipal  Block Password Addition                                Custom Security Attribute
Caller        User2              User              Restrict Certificate Lifetime                          Custom Security Attribute
```

## Restriction Type Mappings

| Technical Name | Friendly Name |
|----------------|---------------|
| `passwordAddition` | Block Password Addition |
| `passwordLifetime` | Restrict Max Password Lifetime |
| `customPasswordAddition` | Block Custom Passwords |
| `asymmetricKeyLifetime` | Restrict Max Certificate Lifetime |
| `customIdentifierUriAddition` | Block Custom Identifier URIs |
| `identifierUriAddition` | Block Identifier URIs Without Unique Tenant Identifiers |

## How It Works

### Application Exemptions
1. Queries all custom app management policies: `GET /beta/policies/appManagementPolicies`
2. For each policy, retrieves assigned applications: `GET /beta/policies/appManagementPolicies/{id}/appliesTo`
3. Identifies exemptions by finding restrictions with `state='disabled'`

### Caller Exemptions
1. Retrieves all users with pagination: `GET /v1.0/users?$select=id,displayName,userPrincipalName,customSecurityAttributes`
2. Retrieves all service principals with pagination: `GET /v1.0/servicePrincipals?$select=id,displayName,appId,customSecurityAttributes`
3. Filters users and service principals with custom security attributes in the `appManagementPolicySet` attribute set
4. Exemptions are indicated by attributes like `appManagementPolicySet.passwordAdditionExempted = "true"`

## Graph API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /v1.0/policies/appManagementPolicies` | List custom app management policies |
| `GET /v1.0/policies/appManagementPolicies/{id}/appliesTo` | List applications assigned to policy |
| `GET /v1.0/users?$select=...customSecurityAttributes` | Retrieve users with custom security attributes |
| `GET /v1.0/servicePrincipals?$select=...customSecurityAttributes` | Retrieve service principals with custom security attributes |
| `GET /v1.0/servicePrincipals?$select=...customSecurityAttributes` | Retrieve service principals with custom security attributes |

## Exemption Architecture

### Application Exemptions
- Created via **custom policies** with disabled restrictions
- Applied to specific applications
- Managed through custom app management policies

### Caller Exemptions
- Assigned via **custom security attributes** on user or service principal objects
- Uses the `appManagementPolicySet` attribute set
- Example: `appManagementPolicySet.passwordAdditionExempted = "true"`

### Default Policy
- Contains `excludedActors` with custom security attribute rules
- Defines which attributes grant exemptions

## Microsoft Documentation

- [App Management Policies Overview](https://learn.microsoft.com/en-us/graph/api/resources/appmanagementpolicy)
- [Application Management Policy API](https://learn.microsoft.com/en-us/graph/api/appmanagementpolicy-list)
- [Custom Security Attributes](https://learn.microsoft.com/en-us/graph/api/resources/customsecurityattributedefinition)
- [Manage App Registration Restrictions](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal)

## Examples

### Find All Exemptions and Export
```powershell
# Get all exemptions with friendly names
$exemptions = Get-AppManagementPolicyExemptions -UseFriendlyNames

# Export to CSV
$exemptions | Export-Csv -Path "AppManagementExemptions_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Display summary
Write-Host "Total Exemptions: $($exemptions.Count)"
Write-Host "Applications: $(($exemptions | Where-Object ExemptionType -eq 'Application').Count)"
Write-Host "Callers: $(($exemptions | Where-Object ExemptionType -eq 'Caller').Count)"
```

### Find Specific User Exemptions
```powershell
# Get only caller exemptions
$callers = Get-AppManagementPolicyExemptions -IncludeApps $false

# Search for specific user
$callers | Where-Object DisplayName -like "*User1*"
```

### Audit Application Exemptions
```powershell
# Get only application exemptions with friendly names
$apps = Get-AppManagementPolicyExemptions -IncludeCallers $false -UseFriendlyNames

# Group by exemption type
$apps | Group-Object ExemptedFrom | Format-Table Count, Name -AutoSize
```

## Troubleshooting

### No Results Returned
- Verify you have the required Graph API permissions
- Check if custom security attributes are actually assigned in your tenant
- Ensure you're connected to Microsoft Graph: `Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All","User.Read.All"`

### Partial Results
- The function uses pagination for users, so large tenants are supported
- Check for API throttling if you have a very large tenant (100k+ users)

### Permission Errors
```powershell
# Connect with required scopes
Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All","User.Read.All"
```

## Contributing

Feel free to submit issues or pull requests to improve this function.

## License

MIT License

## Version History

- **1.1** (November 26, 2025) - Service Principal Support
  - Added support for service principal (enterprise application) caller exemptions
  - Enhanced documentation with service principal examples
  - Corrected required permissions documentation

- **1.0** (November 25, 2025) - Initial release
  - Support for application and caller exemptions
  - Pagination support for large user bases
  - Friendly name mapping for restrictions
  - Comprehensive documentation
