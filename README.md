# ADMisconfigChecker

PowerShell script to check for common Active Directory misconfigurations and problems, such as stale accounts, weak policies, and privileged group issues.

## Features
- Checks stale user accounts (inactive > 90 days).
- Detects users with never-expiring passwords.
- Evaluates basic password policy strength.
- Reviews privileged group membership (e.g., Domain Admins).
- Identifies unconstrained delegation risks.
- Finds orphaned SIDs in groups.
- Scans GPOs for weak permissions.
- Checks Domain Controller OS versions for outdated systems.

## Requirements
- Windows machine with PowerShell 5.1+ (built-in on Windows 10+).
- Remote Server Administration Tools (RSAT) installed for Active Directory and Group Policy modules.
  - Install RSAT: Settings > Apps > Optional Features > Add a feature > Search "RSAT" and select "Active Directory Domain Services and Lightweight Directory Tools" and "Group Policy Management Tools".
- Run as a user with Domain Admin privileges or appropriate read permissions on AD objects.
- No internet access needed; all checks are local to the domain.

## Installation
1. Clone the repo: `git clone https://github.com/mbrocato/ADMisconfigChecker.git` or download as ZIP.
2. Navigate to the folder: `cd ADMisconfigChecker`.
3. Ensure modules are available: Run `Get-Module -ListAvailable ActiveDirectory, GroupPolicy`. If missing, enable RSAT as above.

## Usage
Run the script in PowerShell (elevated prompt recommended):

- Basic run: `.\ADMisconfigChecker.ps1`
- With verbose logging (creates ADMisconfigLog.txt): `.\ADMisconfigChecker.ps1 -VerboseOutput`
- Specify domain: `.\ADMisconfigChecker.ps1 -Domain "example.com"`

Output is to console; verbose mode logs to file for auditing.

### Example Output
