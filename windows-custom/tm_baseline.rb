# =====================================================================
# Telekom Malaysia (TM) Windows Server Security Baseline (WSB)
# Complete Automated Audit Profile (WSB11 - WSB90 Technical Controls)
# =====================================================================

# =======================================================
# SECTION 1: System Initialization, Updates & Core
# =======================================================
control "WSB11-windows-updates" do
  impact 1.0
  title "Ensure Windows Update service is enabled for patching"
  describe service('wuauserv') do
    it { should be_installed }
    it { should be_enabled }
    # Using 'startmode' instead of 'start_type' is more compatible with Windows SSH connections
    its('startmode') { should eq 'Auto' }
  end
end

control "WSB12-ad-integration" do
  impact 1.0
  title "Configure to join TM Active Directory"
  desc "Ensure the system is explicitly joined to the official TM Active Directory domain."

  describe sys_info do
    # BAD: its('domain') { should_not cmp 'WORKGROUP' }
    
    # GOOD: Explicitly check for the correct domain
    its('domain') { should cmp 'tm.com.my' } 
  end
end

control "WSB13-sccm-agent" do
  impact 1.0
  title "Install System Center Configuration Manager (SCCM) agent"
  describe service('CcmExec') do
    it { should be_installed }
  end
end

control "WSB14-ntp-configuration" do
  impact 1.0
  title "Configure synchronization against official TM NTP servers"
  
  # Path for settings configured via Group Policy Administrative Templates
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient') do
    it { should exist }
    its('Enabled') { should eq 1 }
    its('NtpServer') { should match /10\.14\.6\.51/ }
    its('NtpServer') { should match /10\.43\.10\.51/ }
  end

  # This ensures the service is set to 'NTP' mode (not Domain mode)
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\Parameters') do
    its('Type') { should eq 'NTP' }
  end

  # Verifies the Time Service is actually running to avoid the RPC error
  describe service('w32time') do
    it { should be_installed }
    it { should be_running }
  end
end

control "WSB16-antivirus-running" do
  impact 1.0
  title "Enable Corporate Anti-Virus software"
  describe service('WinDefend') do
    it { should be_installed }
    it { should be_running }
  end
end

control "WSB21-logon-banner" do
  impact 0.5
  title "Place TM warning banner for users attempting to log on"
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('legalnoticecaption') { should_not be_empty }
    its('legalnoticetext') { should_not be_empty }
  end
end

# ====================================================================
# WSB23 - NTFS VOLUMES
# ====================================================================
control "WSB23-ntfs-volumes" do
  impact 1.0
  title "Ensure all active volumes use NTFS"
  desc "Checks all mounted drives to ensure they are formatted securely using NTFS."
  
  # Queries Windows for all drives with a letter and lists their file system type
  describe powershell("Get-Volume | Where-Object { $_.DriveLetter -ne $null } | Select-Object -ExpandProperty FileSystemType") do
    its('stdout') { should_not match /FAT32/i }
    its('stdout') { should_not match /exFAT/i }
    its('stdout') { should match /NTFS/i }
  end
end

control "WSB76-wsl-disabled" do
  impact 1.0
  title "Avoid installing WSL on the windows server"
  describe windows_feature('Microsoft-Windows-Subsystem-Linux') do
    it { should_not be_installed }
  end
end


# =======================================================
# SECTION 2: User Account & Password Policies
# =======================================================
control "WSB24-disable-admin-account" do
  impact 1.0
  title "Disable existing Administrator account"
  
  # 1. Check if the physical account is disabled (The Truth)
  describe user('Administrator') do
    it { should exist }
    it { should be_disabled }
  end

  # 2. Check the Security Policy database (The Auditor GUI Check)
  # EnableAdminAccount = 0 means "Disabled" in the security database
  describe security_policy do
    its('EnableAdminAccount') { should cmp 0 }
  end
end

control "WSB28-password-length" do
  impact 1.0
  title "Set minimum password length of 10 characters"
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 10 }
  end
end

control "WSB29-password-history" do
  impact 1.0
  title "Set minimum password history to 5 last passwords"
  describe security_policy do
    its('PasswordHistorySize') { should be >= 5 }
  end
end

control "WSB30-password-complexity" do
  impact 1.0
  title "Enable password complexity"
  describe security_policy do
    its('PasswordComplexity') { should eq 1 }
  end
end

control "WSB33-reversible-encryption" do
  impact 1.0
  title "Do not store passwords using reversible encryption"
  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end

control "WSB34-account-lockout" do
  impact 1.0
  title "Configure Windows OS account lockout policy"
  describe security_policy do
    its('LockoutBadCount') { should be <= 3 }
    its('LockoutDuration') { should be >= 30 }
    its('ResetLockoutCount') { should be >= 15 }
  end
end

control "WSB35-maximum-password-age" do
  impact 1.0
  title "Rotate all authorized local user account passwords every 90 days"
  describe security_policy do
    its('MaximumPasswordAge') { should be <= 90 }
  end
end

control "WSB40-disable-guest" do
  impact 1.0
  title "Disable the guest account"
  describe user('Guest') do
    it { should be_disabled }
  end
end

# =======================================================
# SECTION 3: Local Policies & Security Options
# =======================================================
control "WSB27-network-access" do
  impact 1.0
  title "Limit network access to Administrators and Authenticated Users"
  describe security_policy do
    its('SeNetworkLogonRight') { should include 'S-1-5-32-544' } # Administrators
    its('SeNetworkLogonRight') { should include 'S-1-5-11' }      # Authenticated Users
  end
end

control "WSB36-act-as-os" do
  impact 1.0
  title "Do not grant any users the 'act as part of the operating system' right"
  describe security_policy do
    its('SeTcbPrivilege') { should eq [] } 
  end
end

control "WSB37-restrict-local-logon" do
  impact 1.0
  title "Restrict local logon access to Administrators"
  describe security_policy do
    its('SeInteractiveLogonRight') { should eq ['S-1-5-32-544'] } 
  end
end

control "WSB38-deny-guest-logons" do
  impact 1.0
  title "Deny guest accounts the ability to logon as a service, batch, locally, or RDP"
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include 'S-1-5-32-546' } # Guests
    its('SeDenyInteractiveLogonRight') { should include 'S-1-5-32-546' }
    its('SeDenyServiceLogonRight') { should include 'S-1-5-32-546' }
    its('SeDenyRemoteInteractiveLogonRight') { should include 'S-1-5-32-546' }
  end
end

control "WSB41-require-cad" do
  impact 1.0
  title "Require Ctrl+Alt+Del for interactive logins"
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DisableCAD') { should eq 0 }
  end
end

control "WSB42-inactivity-limit" do
  impact 1.0
  title "Configure machine inactivity limit of 10 minutes (600 seconds)"
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('InactivityTimeoutSecs') { should be <= 600 }
  end
end


# =======================================================
# SECTION 4: Network Security & Cryptography
# =======================================================
control "WSB39-rdp-encryption-both" do
  impact 1.0
  title "RDP Encryption Level: Registry and GUI Verification"

  # Test 1: Technical Registry Check (Using 'cmp' instead of 'eq')
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should exist }
    its('MinEncryptionLevel') { should cmp 3 }
  end

  # Test 2: Policy/GUI Check (Using a more flexible regex)
  describe command('gpresult /scope computer /v') do
    its('stdout') { should match /MinEncryptionLevel/ }
    # This regex allows for varying amounts of spaces between the numbers
    its('stdout') { should match /3,\s*0,\s*0,\s*0/ } 
  end
end

control "WSB43-44-network-client-signing" do
  impact 1.0
  title "Configure Microsoft Network Client digital signing"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('RequireSecuritySignature') { should eq 1 } 
    its('EnableSecuritySignature') { should eq 1 }  
  end
end

control "WSB45-smb-unencrypted-passwords" do
  impact 1.0
  title "Disable the sending of unencrypted passwords to third party SMB servers"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    its('EnablePlainTextPassword') { should eq 0 }
  end
end

control "WSB46-47-network-server-signing" do
  impact 1.0
  title "Configure Microsoft Network Server digital signing"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('RequireSecuritySignature') { should eq 1 } 
    its('EnableSecuritySignature') { should eq 1 }  
  end
end

control "WSB50-disable-anonymous-sid" do
  impact 1.0
  title "Disable anonymous SID/Name translation"
  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end

control "WSB51-52-anonymous-enumeration" do
  impact 1.0
  title "Do not allow anonymous enumeration of SAM accounts and shares"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('RestrictAnonymousSAM') { should eq 1 }
    its('RestrictAnonymous') { should eq 1 }
  end
end

control "WSB53-anonymous-everyone-permissions" do
  impact 1.0
  title "Do not allow everyone permissions to apply to anonymous users"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('EveryoneIncludesAnonymous') { should eq 0 }
  end
end

control "WSB54-56-anonymous-pipes-shares" do
  impact 1.0
  title "Do not allow named pipes and shares to be accessed anonymously"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    # We join the array into a string and strip whitespace. 
    # If it's empty, the result is "". 
    # We use 'cmp' because it is case-insensitive and handles 'nil' safely.
    its('NullSessionPipes.to_a.join.strip') { should cmp '' }
    its('NullSessionShares.to_a.join.strip') { should cmp '' }
  end
end

control "WSB55-restrict-anonymous-pipes" do
  impact 1.0
  title "Restrict anonymous access to named pipes and shares"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('RestrictNullSessAccess') { should eq 1 }
  end
end

control "WSB57-classic-sharing" do
  impact 1.0
  title "Require the Classic sharing and security model for local accounts"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('ForceGuest') { should eq 0 }
  end
end

control "WSB58-local-system-identity" do
  impact 1.0
  title "Allow Local System to use computer identity for NTLM"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('UseMachineId') { should eq 1 }
  end
end

control "WSB59-null-session-fallback" do
  impact 1.0
  title "Disable Local System NULL session fallback"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0') do
    its('allownullsessionfallback') { should eq 0 }
  end
end

control "WSB60-no-lm-hash" do
  impact 1.0
  title "Do not store LAN Manager hash values"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('NoLMHash') { should eq 1 }
  end
end

control "WSB61-lan-manager-auth" do
  impact 1.0
  title "Set LAN Manager authentication level to NTLMv2 only"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
    its('LmCompatibilityLevel') { should eq 5 }
  end
end

# =======================================================
# SECTION 5: Active Directory Domain Member Settings
# =======================================================
control "WSB64-66-secure-channel" do
  impact 1.0
  title "Digitally encrypt or sign secure channel data"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('RequireSignOrSeal') { should eq 1 }
    its('SealSecureChannel') { should eq 1 }
    its('SignSecureChannel') { should eq 1 }
  end
end

control "WSB67-strong-session-keys" do
  impact 1.0
  title "Require strong session keys"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
    its('RequireStrongKey') { should eq 1 }
  end
end

control "WSB68-cached-logons" do
  impact 1.0
  title "Configure the number of previous logons to cache to 2"
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    its('CachedLogonsCount') { should cmp <= 2 }
  end
end

# =======================================================
# SECTION 6: Firewall & Auditing
# =======================================================
control "WSB62-windows-firewall-both" do
  impact 1.0
  title "Windows Firewall: Inbound Block and Enabled (Registry + GUI)"

  # Test 1: Policy/GUI Check (Ensures it is officially managed by Group Policy)
  # 1 = Enabled/Block. Windows uses 'StandardProfile' for the Public network.
  ['DomainProfile', 'PrivateProfile', 'StandardProfile'].each do |profile|
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\#{profile}") do
      it { should exist }
      its('EnableFirewall') { should cmp 1 }
      its('DefaultInboundAction') { should cmp 1 }
    end
  end

  # Test 2: Engine Check (The actual network stack - using your netsh command!)
  describe command('netsh advfirewall show allprofiles') do
    its('stdout') { should match /State\s+ON/ }
    its('stdout') { should match /Firewall Policy\s+BlockInbound,AllowOutbound/ }
  end
end

control "WSB63-rdp-jumphost-only" do
  impact 1.0
  title "Restrict RDP access from designated Jumphost server only"
  describe command('Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress') do
    its('stdout.strip') { should_not match /Any|\*/i }
  end
end

# ====================================================================
# WSB69 to WSB73 - ADVANCED AUDIT POLICIES (ENGINE + GUI)
# ====================================================================

# The audit_policy resource checks the active Windows Engine.
# The file resource checks the audit.csv file, which drives the secpol.msc GUI.

control "WSB69-audit-credential-validation-both" do
  impact 1.0
  title "Audit Credential Validation (Failure)"
  
  describe audit_policy do
    its('Credential Validation') { should cmp 'Failure' }
  end
  describe file('C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv') do
    it { should exist }
    its('content') { should match /Credential Validation/i }
  end
end

control "WSB70-audit-user-account-management-both" do
  impact 1.0
  title "Audit User Account Management (Success)"
  
  describe audit_policy do
    its('User Account Management') { should cmp 'Success' }
  end
  describe file('C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv') do
    it { should exist }
    its('content') { should match /User Account Management/i }
  end
end

control "WSB71-audit-other-logon-logoff-both" do
  impact 1.0
  title "Audit Other Logon/Logoff Events (Success)"
  
  describe audit_policy do
    its('Other Logon/Logoff Events') { should cmp 'Success' }
  end
  describe file('C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv') do
    it { should exist }
    its('content') { should match /Other Logon\/Logoff Events/i }
  end
end

control "WSB72-audit-policy-change-both" do
  impact 1.0
  title "Audit Policy Change (Failure)"
  
  describe audit_policy do
    its('Audit Policy Change') { should cmp 'Failure' }
  end
  describe file('C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv') do
    it { should exist }
    its('content') { should match /Audit Policy Change/i }
  end
end

control "WSB73-audit-sensitive-privilege-use-both" do
  impact 1.0
  title "Audit Sensitive Privilege Use (Success)"
  
  describe audit_policy do
    its('Sensitive Privilege Use') { should cmp 'Success' }
  end
  describe file('C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv') do
    it { should exist }
    its('content') { should match /Sensitive Privilege Use/i }
  end
end

control "WSB74-event-log-size" do
  impact 0.5
  title "Configure Event Log retention size"
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\Security') do
    its('MaxSize') { should be >= 1048576000 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\System') do
    its('MaxSize') { should be >= 1048576000 }
  end
end

# ====================================================================
# WSB81 - SCREENSAVER TIMEOUT (ENGINE + GUI)
# ====================================================================
control "WSB81-screensaver-timeout-both" do
  impact 1.0
  title "Interactive logon: Machine inactivity limit (10 minutes)"
  
  # 1. Technical Engine Check
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('InactivityTimeoutSecs') { should cmp 600 }
  end

  # 2. GUI/Policy Check (Native InSpec Resource)
  describe security_policy do
    its('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs') { should match /4,\s*600/ }
  end
end

# ====================================================================
# WSB79 - SHUTDOWN WITHOUT LOGON (ENGINE + GUI)
# ====================================================================
control "WSB79-shutdown-without-logon-both" do
  impact 1.0
  title "Do not allow the system to be shut down without having to log on"
  
  # 1. Technical Engine Check
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('shutdownwithoutlogon') { should cmp 0 }
  end

  # 2. GUI/Policy Check (Native InSpec Resource)
  describe security_policy do
    its('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon') { should match /4,\s*0/ }
  end
end

# ====================================================================
# WBS90 - UNINSTALL SNMP
# ====================================================================
control "WBS90-uninstall-snmp" do
  impact 1.0
  title "Uninstall Simple Network Management Protocol (SNMP)"
  desc "SNMP is considered an insecure protocol and should be removed if not strictly required."
  
  describe windows_feature('SNMP-Service') do
    it { should_not be_installed }
  end
end
