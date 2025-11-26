function Get-AppManagementPolicyExemptions {
    <#
    .SYNOPSIS
        Retrieves all exemptions from Application Management Policies including both applications and callers.

    .DESCRIPTION
        This function queries Microsoft Graph API to identify:
        - Applications exempt from app management policies (via custom policies)
        - Callers (users and service principals) exempt via custom security attributes
        Returns a unified view showing exemption type and details.

    .PARAMETER IncludeApps
        Include application exemptions in the results (default: true)

    .PARAMETER IncludeCallers
        Include caller (user/service principal) exemptions in the results (default: true)

    .PARAMETER UseFriendlyNames
        If specified, converts restriction types to human-readable names in the output.

    .EXAMPLE
        Get-AppManagementPolicyExemptions
        Returns all exemptions (both apps and callers)

    .EXAMPLE
        Get-AppManagementPolicyExemptions -IncludeApps $false
        Returns only caller exemptions

    .EXAMPLE
        $exemptions = Get-AppManagementPolicyExemptions
        $exemptions | Export-Csv -Path "AllExemptions.csv" -NoTypeInformation

    .EXAMPLE
        Get-AppManagementPolicyExemptions -UseFriendlyNames
        Returns exemptions with human-readable restriction names (e.g., "Block Password Addition" instead of "passwordAddition")

    .NOTES
        REQUIRED PERMISSIONS:
        - Policy.Read.All
        - Application.Read.All
        - User.Read.All

        Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All","User.Read.All"

        To view caller exemptions, user needs to be assigned one of the below roles (Global Admin isn't enough):
        Link: https://learn.microsoft.com/en-us/graph/api/resources/custom-security-attributes-overview?view=graph-rest-1.0#permissions
        - Attribute Definition Reader
        - Attribute Assignment Reader
        - Attribute Assignment Administrator
        - Attribute Definition Administrator

        GRAPH API ENDPOINTS USED:

        Application Exemptions:
        1. GET https://graph.microsoft.com/v1.0/policies/appManagementPolicies
           Lists all custom app management policies

        2. GET https://graph.microsoft.com/v1.0/policies/appManagementPolicies/{id}/appliesTo
           Lists applications assigned to each custom policy
           Exemptions are identified by restrictions with state='disabled'

        Caller Exemptions (Users and Enterprise Applications):
        Users:
        3. GET https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,customSecurityAttributes
           Retrieves users with custom security attributes
           Uses pagination (@odata.nextLink) to handle large result sets

        4. Custom security attributes in the 'appManagementPolicySet' attribute set indicate caller exemptions
           Example: appManagementPolicySet.passwordAdditionExempted = "true"

        Service Principals:
        5. GET https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,customSecurityAttributes
           Retrieves service principals with custom security attributes
           Uses pagination (@odata.nextLink) to handle large result sets

        6. Custom security attributes in the 'appManagementPolicySet' attribute set indicate caller exemptions
            Example: appManagementPolicySet.passwordAdditionExempted = "true"

        VERSION: 1.1
        DATE: November 26, 2025
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$IncludeApps = $true,

        [Parameter()]
        [bool]$IncludeCallers = $true,

        [Parameter()]
        [switch]$UseFriendlyNames,

        [Parameter()]
        [ValidateSet('v1.0', 'beta')]
        [string]$Version = 'v1.0'
    )

    # Mapping of restriction types to friendly names (based on Azure Portal display names)
    $friendlyNameMap = @{
        'passwordAddition' = 'Block Password Addition'
        'passwordLifetime' = 'Restrict Max Password Lifetime'
        'customPasswordAddition' = 'Block Custom Passwords'
        'asymmetricKeyLifetime' = 'Restrict Max Certificate Lifetime'
        'customIdentifierUriAddition' = 'Block Custom Identifier URIs'
        'identifierUriAddition' = 'Block Identifier URIs Without Unique Tenant Identifiers'
    }

    $allExemptions = @()

    # ===== APPLICATION EXEMPTIONS =====
    if ($IncludeApps) {
        Write-Host "`n=== FETCHING APPLICATION EXEMPTIONS ===" -ForegroundColor Cyan

        try {
            $policies = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$Version/policies/appManagementPolicies").Value
            Write-Host "Found $($policies.Count) custom app management policies" -ForegroundColor Gray

            foreach ($policy in $policies) {
                # Get applications assigned to this policy
                $appliesTo = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$Version/policies/appManagementPolicies/$($policy.id)/appliesTo"

                foreach ($app in $appliesTo.value) {
                    # Only process application objects (not service principals)
                    if ($app.'@odata.type' -eq '#microsoft.graph.application') {

                        # Determine which restrictions are disabled (exempted)
                        $exemptedRestrictions = @()

                        # Check password credential restrictions
                        foreach ($pwdRestriction in $policy.restrictions.passwordCredentials) {
                            if ($pwdRestriction.state -eq 'disabled') {
                                $exemptedRestrictions += $pwdRestriction.restrictionType
                            }
                        }

                        # Check key credential restrictions
                        foreach ($keyRestriction in $policy.restrictions.keyCredentials) {
                            if ($keyRestriction.state -eq 'disabled') {
                                $exemptedRestrictions += $keyRestriction.restrictionType
                            }
                        }

                        # Convert to friendly names if requested
                        if ($UseFriendlyNames) {
                            $displayRestrictions = $exemptedRestrictions | ForEach-Object {
                                if ($friendlyNameMap.ContainsKey($_)) { $friendlyNameMap[$_] } else { $_ }
                            }
                            $exemptedFromValue = ($displayRestrictions -join ', ')
                        } else {
                            $exemptedFromValue = ($exemptedRestrictions -join ', ')
                        }

                        $allExemptions += [PSCustomObject]@{
                            ExemptionType = 'Application'
                            DisplayName = $app.displayName
                            PrincipalType = 'Application'
                            ExemptedFrom = $exemptedFromValue
                            ExemptionMethod = 'Custom Policy'
                        }
                    }
                }
            }

            Write-Host "Found $($allExemptions.Count) application exemptions" -ForegroundColor Green
        }
        catch {
            Write-Warning "Error fetching application exemptions: $($_.Exception.Message)"
        }
    }

    # ===== CALLER EXEMPTIONS (USERS AND SERVICE PRINCIPALS) =====
    if ($IncludeCallers) {
        Write-Host "`n=== FETCHING CALLER EXEMPTIONS (USERS) ===" -ForegroundColor Cyan

        try {
            $allUsersData = @()
            $uri = "https://graph.microsoft.com/$Version/users?`$select=id,displayName,userPrincipalName,customSecurityAttributes&`$top=999"
            $pageCount = 0

            do {
                $pageCount++
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri

                # Only keep users that have customSecurityAttributes to save memory
                $usersWithAttrs = $response.value | Where-Object { $_.customSecurityAttributes }
                $allUsersData += $usersWithAttrs

                $uri = $response.'@odata.nextLink'

                Write-Host "  Page $pageCount : Processed $($response.value.Count) users, kept $($usersWithAttrs.Count) with attributes" -ForegroundColor Gray
            } while ($uri)

            Write-Host "Total users with custom security attributes: $($allUsersData.Count)" -ForegroundColor Gray

            # Filter to only users with appManagementPolicySet
            $usersWithExemptions = $allUsersData | Where-Object { $_.customSecurityAttributes.appManagementPolicySet }
            Write-Host "Users with app management exemptions: $($usersWithExemptions.Count)" -ForegroundColor Gray

            # Process user exemptions
            foreach ($user in $usersWithExemptions) {
                $appMgmtSet = $user.customSecurityAttributes.appManagementPolicySet

                # Convert to JSON and back to get clean object
                $cleanSet = $appMgmtSet | ConvertTo-Json -Depth 5 | ConvertFrom-Json

                foreach ($propName in $cleanSet.PSObject.Properties.Name) {
                    if ($propName -notlike "@odata*") {
                        # Convert attribute name to friendly restriction type
                        $restrictionType = $propName -replace 'Exempted$', ''

                        # Use friendly name if requested
                        if ($UseFriendlyNames -and $friendlyNameMap.ContainsKey($restrictionType)) {
                            $exemptedFromValue = $friendlyNameMap[$restrictionType]
                        } else {
                            $exemptedFromValue = $restrictionType
                        }

                        $allExemptions += [PSCustomObject]@{
                            ExemptionType = 'Caller'
                            DisplayName = $user.displayName
                            PrincipalType = 'User'
                            ExemptedFrom = $exemptedFromValue
                            ExemptionMethod = 'Custom Security Attribute'
                        }
                    }
                }
            }

            $userCallerCount = ($allExemptions | Where-Object { $_.ExemptionType -eq 'Caller' -and $_.PrincipalType -eq 'User' }).Count
            Write-Host "Found $userCallerCount caller exemptions (users)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Error fetching user caller exemptions: $($_.Exception.Message)"
        }

        # ===== CALLER EXEMPTIONS (SERVICE PRINCIPALS) =====
        Write-Host "`n=== FETCHING CALLER EXEMPTIONS (SERVICE PRINCIPALS) ===" -ForegroundColor Cyan

        try {
            $allServicePrincipalsData = @()
            $uri = "https://graph.microsoft.com/$Version/servicePrincipals?`$select=id,displayName,appId,customSecurityAttributes&`$top=999"
            $pageCount = 0

            do {
                $pageCount++
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri

                # Only keep service principals that have customSecurityAttributes to save memory
                $spWithAttrs = $response.value | Where-Object { $_.customSecurityAttributes }
                $allServicePrincipalsData += $spWithAttrs

                $uri = $response.'@odata.nextLink'

                Write-Host "  Page $pageCount : Processed $($response.value.Count) service principals, kept $($spWithAttrs.Count) with attributes" -ForegroundColor Gray
            } while ($uri)

            Write-Host "Total service principals with custom security attributes: $($allServicePrincipalsData.Count)" -ForegroundColor Gray

            # Filter to only service principals with appManagementPolicySet
            $spWithExemptions = $allServicePrincipalsData | Where-Object { $_.customSecurityAttributes.appManagementPolicySet }
            Write-Host "Service principals with app management exemptions: $($spWithExemptions.Count)" -ForegroundColor Gray

            # Process service principal exemptions
            foreach ($sp in $spWithExemptions) {
                $appMgmtSet = $sp.customSecurityAttributes.appManagementPolicySet

                # Convert to JSON and back to get clean object
                $cleanSet = $appMgmtSet | ConvertTo-Json -Depth 5 | ConvertFrom-Json

                foreach ($propName in $cleanSet.PSObject.Properties.Name) {
                    if ($propName -notlike "@odata*") {
                        # Convert attribute name to friendly restriction type
                        $restrictionType = $propName -replace 'Exempted$', ''

                        # Use friendly name if requested
                        if ($UseFriendlyNames -and $friendlyNameMap.ContainsKey($restrictionType)) {
                            $exemptedFromValue = $friendlyNameMap[$restrictionType]
                        } else {
                            $exemptedFromValue = $restrictionType
                        }

                        $allExemptions += [PSCustomObject]@{
                            ExemptionType = 'Caller'
                            DisplayName = $sp.displayName
                            PrincipalType = 'ServicePrincipal'
                            ExemptedFrom = $exemptedFromValue
                            ExemptionMethod = 'Custom Security Attribute'
                        }
                    }
                }
            }

            $spCallerCount = ($allExemptions | Where-Object { $_.ExemptionType -eq 'Caller' -and $_.PrincipalType -eq 'ServicePrincipal' }).Count
            Write-Host "Found $spCallerCount caller exemptions (service principals)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Error fetching service principal caller exemptions: $($_.Exception.Message)"
        }
    }

    # ===== SUMMARY AND RESULTS =====
    Write-Host "`n=== EXEMPTION SUMMARY ===" -ForegroundColor Yellow

    $appExemptions = @($allExemptions | Where-Object { $_.ExemptionType -eq 'Application' })
    $callerExemptions = @($allExemptions | Where-Object { $_.ExemptionType -eq 'Caller' })

    Write-Host "Application Exemptions: $($appExemptions.Count)" -ForegroundColor Cyan
    Write-Host "Caller Exemptions: $($callerExemptions.Count)" -ForegroundColor Cyan
    Write-Host "Total Exemptions: $($allExemptions.Count)" -ForegroundColor Green

    if ($allExemptions.Count -gt 0) {
        Write-Host "`n=== ALL EXEMPTIONS ===" -ForegroundColor Green
    } else {
        Write-Host "`nNo exemptions found" -ForegroundColor Yellow
    }

    # Return the collection
    return $allExemptions
}
