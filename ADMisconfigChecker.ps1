# ADMisconfigChecker.ps1
# PowerShell script to check for common Active Directory misconfigurations and problems.
# Requires RSAT tools installed and run as Domain Admin or with appropriate permissions.
# Modules: ActiveDirectory, GroupPolicy (import if needed).

param (
    [string]$Domain = (Get-ADDomain).DNSRoot,  # Default to current domain
    [switch]$VerboseOutput = $false  # Enable verbose logging
)

# Function to log messages
function Log-Message {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
    if ($VerboseOutput) {
        Add-Content -Path "ADMisconfigLog.txt" -Value "[$timestamp] [$Level] $Message"
    }
}

# Import required modules
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

if (-not (Get-Module -Name ActiveDirectory)) {
    Log-Message "ActiveDirectory module not available. Install RSAT and try again." "ERROR"
    exit
}

Log-Message "Starting AD misconfiguration checks for domain: $Domain"

# Check 1: Stale User Accounts (inactive > 90 days)
Log-Message "Checking for stale user accounts..."
$staleUsers = Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) -UsersOnly | Select Name, LastLogonDate
if ($staleUsers.Count -gt 0) {
    Log-Message "Found $($staleUsers.Count) stale users:" "WARNING"
    $staleUsers | Format-Table
} else {
    Log-Message "No stale user accounts found." "INFO"
}

# Check 2: Users with Never-Expiring Passwords
Log-Message "Checking for users with never-expiring passwords..."
$neverExpire = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties Name, PasswordNeverExpires | Select Name
if ($neverExpire.Count -gt 0) {
    Log-Message "Found $($neverExpire.Count) users with never-expiring passwords:" "WARNING"
    $neverExpire | Format-Table
} else {
    Log-Message "No users with never-expiring passwords." "INFO"
}

# Check 3: Weak Password Policies (basic)
Log-Message "Checking password policies..."
$passwordPolicy = Get-ADDefaultDomainPasswordPolicy
if ($passwordPolicy.MinPasswordLength -lt 12 -or $passwordPolicy.PasswordHistoryCount -lt 12 -or -not $passwordPolicy.ComplexityEnabled) {
    Log-Message "Weak password policy detected: Min Length=$($passwordPolicy.MinPasswordLength), History=$($passwordPolicy.PasswordHistoryCount), Complexity=$($passwordPolicy.ComplexityEnabled)" "WARNING"
} else {
    Log-Message "Password policy appears adequate." "INFO"
}

# Check 4: Privileged Group Membership (e.g., Domain Admins with too many members)
Log-Message "Checking privileged group membership..."
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Select Name
if ($domainAdmins.Count -gt 5) {  # Arbitrary threshold; adjust as needed
    Log-Message "Domain Admins group has $($domainAdmins.Count) members (potential over-privilege):" "WARNING"
    $domainAdmins | Format-Table
} else {
    Log-Message "Domain Admins membership looks reasonable." "INFO"
}

# Check 5: Unconstrained Delegation (Kerberos risks)
Log-Message "Checking for unconstrained delegation..."
$delegated = Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo | Select Name
if ($delegated.Count -gt 0) {
    Log-Message "Found $($delegated.Count) objects with unconstrained delegation:" "WARNING"
    $delegated | Format-Table
} else {
    Log-Message "No unconstrained delegation found." "INFO"
}

# Check 6: Orphaned SIDs in Groups (stale memberships)
Log-Message "Checking for orphaned SIDs in groups..."
$groups = Get-ADGroup -Filter * | Select -ExpandProperty DistinguishedName
$orphaned = @()
foreach ($group in $groups) {
    $members = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.objectClass -eq 'foreignSecurityPrincipal' }
    if ($members) {
        $orphaned += $members
    }
}
if ($orphaned.Count -gt 0) {
    Log-Message "Found $($orphaned.Count) orphaned SIDs in groups:" "WARNING"
    $orphaned | Format-Table
} else {
    Log-Message "No orphaned SIDs found." "INFO"
}

# Check 7: GPO with Weak Permissions (basic)
Log-Message "Checking GPO permissions..."
$gpos = Get-GPO -All
$weakGPOs = @()
foreach ($gpo in $gpos) {
    $perms = Get-GPPermission -Name $gpo.DisplayName -All | Where-Object { $_.Trustee.Name -eq 'Authenticated Users' -and $_.Permission -eq 'GpoEdit' }
    if ($perms) {
        $weakGPOs += $gpo.DisplayName
    }
}
if ($weakGPOs.Count -gt 0) {
    Log-Message "Found $($weakGPOs.Count) GPOs with weak permissions (Authenticated Users can edit):" "WARNING"
    $weakGPOs | ForEach-Object { Write-Output "- $_" }
} else {
    Log-Message "No GPOs with weak permissions." "INFO"
}

# Check 8: Domain Controllers with Outdated OS (basic)
Log-Message "Checking Domain Controller OS versions..."
$dcs = Get-ADDomainController -Filter * | Select Name, OperatingSystem, OperatingSystemVersion
$outdated = $dcs | Where-Object { $_.OperatingSystemVersion -lt '10.0' }  # Below Windows Server 2019
if ($outdated.Count -gt 0) {
    Log-Message "Found $($outdated.Count) outdated DCs:" "WARNING"
    $outdated | Format-Table
} else {
    Log-Message "All DCs up to date." "INFO"
}

Log-Message "AD misconfiguration checks complete."
