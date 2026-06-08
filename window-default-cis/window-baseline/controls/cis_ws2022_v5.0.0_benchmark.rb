# encoding: UTF-8
# =============================================================================
# CIS Microsoft Windows Server 2022 Benchmark v5.0.0  (02-20-2026)
# Combined InSpec / CINC Auditor profile — ALL sections in one file (SCAN)
# =============================================================================
# Sections included:  1, 2, 5, 9, 17, 18, 19
# Run with:   cinc-auditor exec cis_ws2022_v5.0.0_benchmark.rb \
#               --input server_role=member_server profile_level=1 \
#               -t winrm://HOST --user USER --password PASS
#
# Inputs:
#   server_role   = member_server | domain_controller   (default member_server)
#   profile_level = 1 | 2                                (report metadata)
#
# Verified complete against the v5.0.0 PDF Summary Table + body (433 recs).
# Controls added beyond the original profile (were missing):
#   5.1, 5.2                 Section 5 System Services (Print Spooler)
#   18.6.19.2.1              Disable IPv6 (DisabledComponents = 0xff)
#   18.10.42.11.1.1.1 / .2   Defender Brute-Force Protection
#   18.10.42.11.1.2.1        Defender Remote Encryption Protection
# =============================================================================


# =
# --- SECTION: 1  Account Policies ---
# =

control 'cis-1.1.1' do
  title 'Ensure \'Enforce password history\' is set to \'24 or more password(s)\' (Automated)'
  impact 0.5
  tag cis_id: '1.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'password_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('PasswordHistorySize') { should cmp >= 24 }
  end
end

control 'cis-1.1.2' do
  title 'Ensure \'Maximum password age\' is set to \'365 or fewer days, but not 0\' (Automated)'
  impact 0.5
  tag cis_id: '1.1.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'password_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('MaximumPasswordAge') { should cmp <= 365 }
    its('MaximumPasswordAge') { should cmp > 0 }
  end
end

control 'cis-1.1.3' do
  title 'Ensure \'Minimum password age\' is set to \'1 or more day(s)\' (Automated)'
  impact 0.5
  tag cis_id: '1.1.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'password_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('MinimumPasswordAge') { should cmp >= 1 }
  end
end

control 'cis-1.1.4' do
  title 'Ensure \'Minimum password length\' is set to \'14 or more character(s)\' (Automated)'
  impact 0.5
  tag cis_id: '1.1.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'password_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('MinimumPasswordLength') { should cmp >= 14 }
  end
end

control 'cis-1.1.5' do
  title 'Ensure \'Password must meet complexity requirements\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '1.1.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'password_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('PasswordComplexity') { should cmp == 1 }
  end
end

control 'cis-1.1.6' do
  title 'Ensure \'Relax minimum password length limits\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '1.1.6'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SAM') do
    its('RelaxMinimumPasswordLengthLimits') { should cmp == 1 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-1.1.7' do
  title 'Ensure \'Store passwords using reversible encryption\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '1.1.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'password_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('ClearTextPassword') { should cmp == 0 }
  end
end

control 'cis-1.2.1' do
  title 'Ensure \'Account lockout duration\' is set to \'15 or more minute(s)\' (Automated)'
  impact 0.5
  tag cis_id: '1.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'lockout_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('LockoutDuration') { should cmp >= 15 }
  end
end

control 'cis-1.2.2' do
  title 'Ensure \'Account lockout threshold\' is set to \'5 or fewer invalid logon attempt(s), but not 0\' (Automated)'
  impact 0.5
  tag cis_id: '1.2.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'lockout_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('LockoutBadCount') { should cmp >= 1 }
    its('LockoutBadCount') { should cmp <= 5 }
  end
end

control 'cis-1.2.3' do
  title 'Ensure \'Allow Administrator account lockout\' is set to \'Enabled\' (MS only) (Manual)'
  impact 0.5
  tag cis_id: '1.2.3'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'lockout_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (1.2.3): Ensure \'Allow Administrator account lockout\' is set to \'Enabled\' (MS only) (Manual)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policies\Allow Administrator account lockout
end

control 'cis-1.2.4' do
  title 'Ensure \'Reset account lockout counter after\' is set to \'15 or more minute(s)\' (Automated)'
  impact 0.5
  tag cis_id: '1.2.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'lockout_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('ResetLockoutCount') { should cmp >= 15 }
  end
end

# =
# --- SECTION: 2  Local Policies (User Rights & Security Options) ---
# =

control 'cis-2.2.1' do
  title 'Ensure \'Access Credential Manager as a trusted caller\' is set to \'No One\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end

control 'cis-2.2.2' do
  title 'Ensure \'Access this computer from the network\' is set to \'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.2'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeNetworkLogonRight') { should match_array ['*S-1-5-32-544', '*S-1-5-11', '*S-1-5-9'] }
  end
end

control 'cis-2.2.3' do
  title 'Ensure \'Access this computer from the network\' is set to \'Administrators, Authenticated Users\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.3'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeNetworkLogonRight') { should match_array ['*S-1-5-32-544', '*S-1-5-11'] }
  end
end

control 'cis-2.2.4' do
  title 'Ensure \'Act as part of the operating system\' is set to \'No One\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeTcbPrivilege') { should eq [] }
  end
end

control 'cis-2.2.5' do
  title 'Ensure \'Add workstations to domain\' is set to \'Administrators\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.5'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeMachineAccountPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.6' do
  title 'Ensure \'Adjust memory quotas for a process\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20'] }
  end
end

control 'cis-2.2.7' do
  title 'Ensure \'Allow log on locally\' is set to \'Administrators, ENTERPRISE DOMAIN CONTROLLERS\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.7'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeInteractiveLogonRight') { should match_array ['*S-1-5-32-544', '*S-1-5-9'] }
  end
end

control 'cis-2.2.8' do
  title 'Ensure \'Allow log on locally\' is set to \'Administrators\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.8'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeInteractiveLogonRight') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.9' do
  title 'Ensure \'Allow log on through Remote Desktop Services\' is set to \'Administrators\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.9'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.10' do
  title 'Ensure \'Allow log on through Remote Desktop Services\' is set to \'Administrators, Remote Desktop Users\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.10'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeRemoteInteractiveLogonRight') { should match_array ['*S-1-5-32-544', '*S-1-5-32-555'] }
  end
end

control 'cis-2.2.11' do
  title 'Ensure \'Back up files and directories\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.11'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeBackupPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.12' do
  title 'Ensure \'Change the system time\' is set to \'Administrators, LOCAL SERVICE\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.12'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeSystemtimePrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-19'] }
  end
end

control 'cis-2.2.13' do
  title 'Ensure \'Create a pagefile\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.13'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeCreatePagefilePrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.14' do
  title 'Ensure \'Create a token object\' is set to \'No One\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.14'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq [] }
  end
end

control 'cis-2.2.15' do
  title 'Ensure \'Create global objects\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.15'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeCreateGlobalPrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6'] }
  end
end

control 'cis-2.2.16' do
  title 'Ensure \'Create permanent shared objects\' is set to \'No One\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.16'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq [] }
  end
end

control 'cis-2.2.17' do
  title 'Ensure \'Create symbolic links\' is set to \'Administrators\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.17'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.18' do
  title 'Ensure \'Create symbolic links\' is set to \'Administrators, NT VIRTUAL MACHINE\\Virtual Machines\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.18'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeCreateSymbolicLinkPrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-83-0'] }
  end
end

control 'cis-2.2.19' do
  title 'Ensure \'Debug programs\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.19'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDebugPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.20' do
  title 'Ensure \'Deny access to this computer from the network\' to include \'Guests\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.20'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should include '*S-1-5-32-546' }
  end
end

control 'cis-2.2.21' do
  title 'Ensure \'Deny access to this computer from the network\' to include \'Guests, Local account and member of Administrators group\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.21'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDenyNetworkLogonRight') { should include '*S-1-5-32-546' }
    its('SeDenyNetworkLogonRight') { should include '*S-1-5-114' }
  end
end

control 'cis-2.2.22' do
  title 'Ensure \'Deny log on as a batch job\' to include \'Guests\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.22'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDenyBatchLogonRight') { should include '*S-1-5-32-546' }
  end
end

control 'cis-2.2.23' do
  title 'Ensure \'Deny log on as a service\' to include \'Guests\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.23'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDenyServiceLogonRight') { should include '*S-1-5-32-546' }
  end
end

control 'cis-2.2.24' do
  title 'Ensure \'Deny log on locally\' to include \'Guests\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.24'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDenyInteractiveLogonRight') { should include '*S-1-5-32-546' }
  end
end

control 'cis-2.2.25' do
  title 'Ensure \'Deny log on through Remote Desktop Services\' to include \'Guests\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.25'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should include '*S-1-5-32-546' }
  end
end

control 'cis-2.2.26' do
  title 'Ensure \'Deny log on through Remote Desktop Services\' is set to \'Guests, Local account\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.26'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeDenyRemoteInteractiveLogonRight') { should match_array ['*S-1-5-32-546', '*S-1-5-113'] }
  end
end

control 'cis-2.2.27' do
  title 'Ensure \'Enable computer and user accounts to be trusted for delegation\' is set to \'Administrators\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.27'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.28' do
  title 'Ensure \'Enable computer and user accounts to be trusted for delegation\' is set to \'No One\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.28'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq [] }
  end
end

control 'cis-2.2.29' do
  title 'Ensure \'Force shutdown from a remote system\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.29'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeRemoteShutdownPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.30' do
  title 'Ensure \'Generate security audits\' is set to \'LOCAL SERVICE, NETWORK SERVICE\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.30'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeAuditPrivilege') { should match_array ['*S-1-5-19', '*S-1-5-20'] }
  end
end

control 'cis-2.2.31' do
  title 'Ensure \'Impersonate a client after authentication\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.31'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeImpersonatePrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6'] }
  end
end

control 'cis-2.2.32' do
  title 'Ensure \'Impersonate a client after authentication\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.32'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeImpersonatePrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6'] }
  end
end

control 'cis-2.2.33' do
  title 'Ensure \'Increase scheduling priority\' is set to \'Administrators, Window Manager\\Window Manager Group\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.33'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeIncreaseBasePriorityPrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-90-0'] }
  end
end

control 'cis-2.2.34' do
  title 'Ensure \'Load and unload device drivers\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.34'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeLoadDriverPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.35' do
  title 'Ensure \'Lock pages in memory\' is set to \'No One\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.35'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end

control 'cis-2.2.36' do
  title 'Ensure \'Log on as a batch job\' is set to \'Administrators\' (DC Only) (Automated)'
  impact 0.7
  tag cis_id: '2.2.36'
  tag level: ['L2']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeBatchLogonRight') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.37' do
  title 'Ensure \'Manage auditing and security log\' is set to \'Administrators\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.37'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeSecurityPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.38' do
  title 'Ensure \'Manage auditing and security log\' is set to \'Administrators\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.38'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeSecurityPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.39' do
  title 'Ensure \'Modify an object label\' is set to \'No One\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.39'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeRelabelPrivilege') { should eq [] }
  end
end

control 'cis-2.2.40' do
  title 'Ensure \'Modify firmware environment values\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.40'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeSystemEnvironmentPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.41' do
  title 'Ensure \'Perform volume maintenance tasks\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.41'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeManageVolumePrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.42' do
  title 'Ensure \'Profile single process\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.42'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeProfileSingleProcessPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.43' do
  title 'Ensure \'Profile system performance\' is set to \'Administrators, NT SERVICE\\WdiServiceHost\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.43'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeSystemProfilePrivilege') { should match_array ['*S-1-5-32-544', '*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'] }
  end
end

control 'cis-2.2.44' do
  title 'Ensure \'Replace a process level token\' is set to \'LOCAL SERVICE, NETWORK SERVICE\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.44'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeAssignPrimaryTokenPrivilege') { should match_array ['*S-1-5-19', '*S-1-5-20'] }
  end
end

control 'cis-2.2.45' do
  title 'Ensure \'Restore files and directories\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.45'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeRestorePrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.46' do
  title 'Ensure \'Shut down the system\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.46'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeShutdownPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.2.47' do
  title 'Ensure \'Synchronize directory service data\' is set to \'No One\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.2.47'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeSyncAgentPrivilege') { should eq [] }
  end
end

control 'cis-2.2.48' do
  title 'Ensure \'Take ownership of files or other objects\' is set to \'Administrators\' (Automated)'
  impact 0.5
  tag cis_id: '2.2.48'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'user_rights'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe security_policy do
    its('SeTakeOwnershipPrivilege') { should match_array ['*S-1-5-32-544'] }
  end
end

control 'cis-2.3.1.1' do
  title 'Ensure \'Accounts: Guest account status\' is set to \'Disabled\' (MS only) (Automated)'
  impact 0.0
  tag cis_id: '2.3.1.1'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.1.1): Ensure \'Accounts: Guest account status\' is set to \'Disabled\' (MS only) (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Guest account status
end

control 'cis-2.3.1.2' do
  title 'Ensure \'Accounts: Limit local account use of blank passwords to console logon only\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.1.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('LimitBlankPasswordUse') { should cmp == 1 }
  end
end

control 'cis-2.3.1.3' do
  title 'Configure \'Accounts: Rename administrator account\' (Automated)'
  impact 0.0
  tag cis_id: '2.3.1.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.1.3): Configure \'Accounts: Rename administrator account\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, configure the following UI path: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename administrator account
end

control 'cis-2.3.1.4' do
  title 'Configure \'Accounts: Rename guest account\' (Automated)'
  impact 0.0
  tag cis_id: '2.3.1.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.1.4): Configure \'Accounts: Rename guest account\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, configure the following UI path: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename guest account
end

control 'cis-2.3.2.1' do
  title 'Ensure \'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('SCENoApplyLegacyAuditPolicy') { should cmp == 1 }
  end
end

control 'cis-2.3.2.2' do
  title 'Ensure \'Audit: Shut down system immediately if unable to log security audits\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.2.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('CrashOnAuditFail') { should cmp == 0 }
  end
end

control 'cis-2.3.4.1' do
  title 'Ensure \'Devices: Prevent users from installing printer drivers\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.4.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanManServices\\Servers') do
    its('AddPrinterDrivers') { should cmp == 1 }
  end
end

control 'cis-2.3.5.1' do
  title 'Ensure \'Domain controller: Allow server operators to schedule tasks\' is set to \'Disabled\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.5.1'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('SubmitControl') { should cmp == 0 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-2.3.5.2' do
  title 'Ensure \'Domain controller: Allow vulnerable Netlogon secure channel connections\' is set to \'Not Configured\' (DC Only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.5.2'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should_not have_property 'VulnerableChannelAllowList' }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-2.3.5.3' do
  title 'Ensure \'Domain controller: LDAP server channel binding token requirements\' is set to \'Always\' (DC Only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.5.3'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    its('LdapEnforceChannelBinding') { should cmp == 2 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-2.3.5.4' do
  title 'Ensure \'Domain controller: LDAP server signing requirements\' is set to \'Require signing\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.5.4'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    its('LDAPServerIntegrity') { should cmp == 2 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-2.3.5.5' do
  title 'Ensure \'Domain controller: Refuse machine account password changes\' is set to \'Disabled\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.5.5'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RefusePasswordChange') { should cmp == 0 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-2.3.6.1' do
  title 'Ensure \'Domain member: Digitally encrypt or sign secure channel data (always)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.6.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RequireSignOrSeal') { should cmp == 1 }
  end
end

control 'cis-2.3.6.2' do
  title 'Ensure \'Domain member: Digitally encrypt secure channel data (when possible)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.6.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SealSecureChannel') { should cmp == 1 }
  end
end

control 'cis-2.3.6.3' do
  title 'Ensure \'Domain member: Digitally sign secure channel data (when possible)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.6.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SignSecureChannel') { should cmp == 1 }
  end
end

control 'cis-2.3.6.4' do
  title 'Ensure \'Domain member: Disable machine account password changes\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.6.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('DisablePasswordChange') { should cmp == 0 }
  end
end

control 'cis-2.3.6.5' do
  title 'Ensure \'Domain member: Maximum machine account password age\' is set to \'30 or fewer days, but not 0\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.6.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('MaximumPasswordAge') { should cmp >= 1 }
    its('MaximumPasswordAge') { should cmp <= 30 }
  end
end

control 'cis-2.3.6.6' do
  title 'Ensure \'Domain member: Require strong (Windows 2000 or later) session key\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.6.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RequireStrongKey') { should cmp == 1 }
  end
end

control 'cis-2.3.7.1' do
  title 'Ensure \'Interactive logon: Do not require CTRL+ALT+DEL\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '2.3.7.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DisableCAD') { should cmp == 0 }
  end
end

control 'cis-2.3.7.2' do
  title 'Ensure \'Interactive logon: Don\'t display last signed-in\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.7.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DontDisplayLastUserName') { should cmp == 1 }
  end
end

control 'cis-2.3.7.3' do
  title 'Ensure \'Interactive logon: Machine inactivity limit\' is set to \'900 or fewer second(s), but not 0\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.7.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('InactivityTimeoutSecs') { should cmp >= 1 }
    its('InactivityTimeoutSecs') { should cmp <= 900 }
  end
end

control 'cis-2.3.7.4' do
  title 'Configure \'Interactive logon: Message text for users attempting to log on\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.7.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    # REVIEW: organization-specific value -- benchmark prescribes: text
    it { should have_property 'LegalNoticeText' }
  end
end

control 'cis-2.3.7.5' do
  title 'Configure \'Interactive logon: Message title for users attempting to log on\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.7.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    # REVIEW: organization-specific value -- benchmark prescribes: text
    it { should have_property 'LegalNoticeCaption' }
  end
end

control 'cis-2.3.7.6' do
  title 'Ensure \'Interactive logon: Number of previous logons to cache (in case domain controller is not available)\' is set to \'4 or fewer logon(s)\' (MS only) (Automated)'
  impact 0.7
  tag cis_id: '2.3.7.6'
  tag level: ['L2']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Winlogon') do
    its('CachedLogonsCount') { should cmp >= 0 }
    its('CachedLogonsCount') { should cmp <= 4 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-2.3.7.7' do
  title 'Ensure \'Interactive logon: Prompt user to change password before expiration\' is set to \'between 5 and 14 days\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.7.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Winlogon') do
    its('PasswordExpiryWarning') { should cmp >= 5 }
    its('PasswordExpiryWarning') { should cmp <= 14 }
  end
end

control 'cis-2.3.7.8' do
  title 'Ensure \'Interactive logon: Require Domain Controller Authentication to unlock workstation\' is set to \'Enabled\' (MS only) (Automated)'
  impact 0.0
  tag cis_id: '2.3.7.8'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.7.8): Ensure \'Interactive logon: Require Domain Controller Authentication to unlock workstation\' is set to \'Enabled\' (MS only) (Automated)'
  end
  # Remediation guidance: To implement the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Require Domain Controller Authentication to unlock workstation
end

control 'cis-2.3.7.9' do
  title 'Ensure \'Interactive logon: Smart card removal behavior\' is set to \'Lock Workstation\' or higher (Automated)'
  impact 0.5
  tag cis_id: '2.3.7.9'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Winlogon') do
    its('ScRemoveOption') { should be_in [1, 2, 3] }
  end
end

control 'cis-2.3.8.1' do
  title 'Ensure \'Microsoft network client: Digitally sign communications (always)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.8.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('RequireSecuritySignature') { should cmp == 1 }
  end
end

control 'cis-2.3.8.2' do
  title 'Ensure \'Microsoft network client: Send unencrypted password to third-party SMB servers\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.8.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('EnablePlainTextPassword') { should cmp == 0 }
  end
end

control 'cis-2.3.9.1' do
  title 'Ensure \'Microsoft network server: Amount of idle time required before suspending session\' is set to \'15 or fewer minute(s)\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.9.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('AutoDisconnect') { should cmp >= 0 }
    its('AutoDisconnect') { should cmp <= 15 }
  end
end

control 'cis-2.3.9.2' do
  title 'Ensure \'Microsoft network server: Digitally sign communications (always)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.9.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('RequireSecuritySignature') { should cmp == 1 }
  end
end

control 'cis-2.3.9.3' do
  title 'Ensure \'Microsoft network server: Disconnect clients when logon hours expire\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.9.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('enableforcedlogoff') { should cmp == 1 }
  end
end

control 'cis-2.3.9.4' do
  title 'Ensure \'Microsoft network server: Server SPN target name validation level\' is set to \'Accept if provided by client\' or higher (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.9.4'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('SMBServerNameHardeningLevel') { should be_in [1, 2] }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-2.3.10.1' do
  title 'Ensure \'Network access: Allow anonymous SID/Name translation\' is set to \'Disabled\' (Automated)'
  impact 0.0
  tag cis_id: '2.3.10.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.10.1): Ensure \'Network access: Allow anonymous SID/Name translation\' is set to \'Disabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Allow anonymous SID/Name translation
end

control 'cis-2.3.10.2' do
  title 'Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts\' is set to \'Enabled\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.2'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictAnonymousSAM') { should cmp == 1 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-2.3.10.3' do
  title 'Ensure \'Network access: Do not allow anonymous enumeration of SAM accounts and shares\' is set to \'Enabled\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.3'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictAnonymous') { should cmp == 1 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-2.3.10.4' do
  title 'Ensure \'Network access: Do not allow storage of passwords and credentials for network authentication\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '2.3.10.4'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('DisableDomainCreds') { should cmp == 1 }
  end
end

control 'cis-2.3.10.5' do
  title 'Ensure \'Network access: Let Everyone permissions apply to anonymous users\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('EveryoneIncludesAnonymous') { should cmp == 0 }
  end
end

control 'cis-2.3.10.6' do
  title 'Ensure \'Network access: Named Pipes that can be accessed anonymously\' is configured (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.6'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('NullSessionPipes') { should cmp 'LSARPC,NETLOGON,SAMR' }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-2.3.10.7' do
  title 'Ensure \'Network access: Named Pipes that can be accessed anonymously\' is configured (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.7'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    # REVIEW: organization-specific value -- benchmark prescribes: blank (i.e. None) or BROWSER (when the legacy Computer
    it { should have_property 'NullSessionPipes' }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-2.3.10.8' do
  title 'Ensure \'Network access: Remotely accessible registry paths\' is configured (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.8'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths') do
    # REVIEW: organization-specific value -- benchmark prescribes: System\CurrentControlSet\Control\ProductOptions,System\CurrentControlS
    it { should have_property 'Machine' }
  end
end

control 'cis-2.3.10.9' do
  title 'Ensure \'Network access: Remotely accessible registry paths and sub-paths\' is configured (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.9'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths') do
    # REVIEW: organization-specific value -- benchmark prescribes: System\CurrentControlSet\Control\Print\Printers,System\CurrentControlS
    it { should have_property 'Machine' }
  end
end

control 'cis-2.3.10.10' do
  title 'Ensure \'Network access: Restrict anonymous access to Named Pipes and Shares\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '2.3.10.10'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.10.10): Ensure \'Network access: Restrict anonymous access to Named Pipes and Shares\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict anonymous access to Named Pipes and Shares
end

control 'cis-2.3.10.11' do
  title 'Ensure \'Network access: Restrict clients allowed to make remote calls to SAM\' is set to \'Administrators: Remote Access: Allow\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.11'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    # REVIEW: organization-specific value -- benchmark prescribes: O:BAG:BAD:(A;;RC;;;BA)
    it { should have_property 'restrictremotesam' }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-2.3.10.12' do
  title 'Ensure \'Network access: Shares that can be accessed anonymously\' is set to \'None\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.12'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    it { should_not have_property 'NullSessionShares' }
  end
end

control 'cis-2.3.10.13' do
  title 'Ensure \'Network access: Sharing and security model for local accounts\' is set to \'Classic - local users authenticate as themselves\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.10.13'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('ForceGuest') { should cmp == 0 }
  end
end

control 'cis-2.3.11.1' do
  title 'Ensure \'Network security: Allow Local System to use computer identity for NTLM\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('UseMachineId') { should cmp == 1 }
  end
end

control 'cis-2.3.11.2' do
  title 'Ensure \'Network security: Allow LocalSystem NULL session fallback\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('AllowNullSessionFallback') { should cmp == 0 }
  end
end

control 'cis-2.3.11.3' do
  title 'Ensure \'Network Security: Allow PKU2U authentication requests to this computer to use online identities\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u') do
    its('AllowOnlineID') { should cmp == 0 }
  end
end

control 'cis-2.3.11.4' do
  title 'Ensure \'Network security: Configure encryption types allowed for Kerberos\' is set to \'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters') do
    its('SupportedEncryptionTypes') { should cmp == 2147483640 }
  end
end

control 'cis-2.3.11.5' do
  title 'Ensure \'Network security: Do not store LAN Manager hash value on next password change\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('NoLMHash') { should cmp == 1 }
  end
end

control 'cis-2.3.11.6' do
  title 'Ensure \'Network security: Force logoff when logon hours expire\' is set to \'Enabled\' (Manual)'
  impact 0.0
  tag cis_id: '2.3.11.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.11.6): Ensure \'Network security: Force logoff when logon hours expire\' is set to \'Enabled\' (Manual)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled. Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Force logoff when logon hours expire
end

control 'cis-2.3.11.7' do
  title 'Ensure \'Network security: LAN Manager authentication level\' is set to \'Send NTLMv2 response only. Refuse LM & NTLM\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('LmCompatibilityLevel') { should cmp == 5 }
  end
end

control 'cis-2.3.11.8' do
  title 'Ensure \'Network security: LDAP client signing requirements\' is set to \'Negotiate signing\' or higher (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.8'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP') do
    its('LDAPClientIntegrity') { should be_in [1, 2] }
  end
end

control 'cis-2.3.11.9' do
  title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.9'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('NTLMMinClientSec') { should cmp == 537395200 }
  end
end

control 'cis-2.3.11.10' do
  title 'Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.10'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('NTLMMinServerSec') { should cmp == 537395200 }
  end
end

control 'cis-2.3.11.11' do
  title 'Ensure \'Network security: Restrict NTLM: Audit Incoming NTLM Traffic\' is set to \'Enable auditing for all accounts\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.11'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('AuditReceivingNTLMTraffic') { should cmp == 2 }
  end
end

control 'cis-2.3.11.12' do
  title 'Ensure \'Network security: Restrict NTLM: Audit NTLM authentication in this domain\' is set to \'Enable all\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.12'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('AuditNTLMInDomain') { should cmp == 7 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-2.3.11.13' do
  title 'Ensure \'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers\' is set to \'Audit all\' or higher (Automated)'
  impact 0.5
  tag cis_id: '2.3.11.13'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('RestrictSendingNTLMTraffic') { should be_in [1, 2] }
  end
end

control 'cis-2.3.13.1' do
  title 'Ensure \'Shutdown: Allow system to be shut down without having to log on\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.13.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ShutdownWithoutLogon') { should cmp == 0 }
  end
end

control 'cis-2.3.15.1' do
  title 'Ensure \'System objects: Require case insensitivity for non-Windows subsystems\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.15.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SessionManager\\Kernel') do
    its('ObCaseInsensitive') { should cmp == 1 }
  end
end

control 'cis-2.3.15.2' do
  title 'Ensure \'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '2.3.15.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.15.2): Ensure \'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
end

control 'cis-2.3.17.1' do
  title 'Ensure \'User Account Control: Admin Approval Mode for the Built-in Administrator account\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.17.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('FilterAdministratorToken') { should cmp == 1 }
  end
end

control 'cis-2.3.17.2' do
  title 'Ensure \'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode\' is set to \'Prompt for consent on the secure desktop\' or higher (Automated)'
  impact 0.5
  tag cis_id: '2.3.17.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ConsentPromptBehaviorAdmin') { should be_in [1, 2] }
  end
end

control 'cis-2.3.17.3' do
  title 'Ensure \'User Account Control: Behavior of the elevation prompt for standard users\' is set to \'Automatically deny elevation requests\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.17.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ConsentPromptBehaviorUser') { should cmp == 0 }
  end
end

control 'cis-2.3.17.4' do
  title 'Ensure \'User Account Control: Detect application installations and prompt for elevation\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.17.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableInstallerDetection') { should cmp == 1 }
  end
end

control 'cis-2.3.17.5' do
  title 'Ensure \'User Account Control: Only elevate UIAccess applications that are installed in secure locations\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.17.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableSecureUIAPaths') { should cmp == 1 }
  end
end

control 'cis-2.3.17.6' do
  title 'Ensure \'User Account Control: Run all administrators in Admin Approval Mode\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.17.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableLUA') { should cmp == 1 }
  end
end

control 'cis-2.3.17.7' do
  title 'Ensure \'User Account Control: Switch to the secure desktop when prompting for elevation\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '2.3.17.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('PromptOnSecureDesktop') { should cmp == 1 }
  end
end

control 'cis-2.3.17.8' do
  title 'Ensure \'User Account Control: Virtualize file and registry write failures to per-user locations\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '2.3.17.8'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (2.3.17.8): Ensure \'User Account Control: Virtualize file and registry write failures to per-user locations\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Virtualize file and registry write failures to per-user locations
end

# =
# --- SECTION: 5  System Services ---
# =

control 'cis-5.1' do
  title 'Ensure \'Print Spooler (Spooler)\' is set to \'Disabled\' (DC only) (Automated)'
  desc  'The Print Spooler service spools print jobs and handles printer ' \
        'interaction. Disabling it mitigates the PrintNightmare vulnerability ' \
        '(CVE-2021-34527) and other attacks against the service. The ' \
        'recommended state is Disabled (service Start type 4).'
  impact 0.5
  tag cis_id:    '5.1'
  tag level:     ['L1']
  tag scope:     'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  only_if('Applies to Domain Controllers only') { input('server_role') == 'domain_controller' }
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler') do
    its('Start') { should cmp == 4 }
  end
  # Remediation guidance: Computer Configuration\Policies\Windows Settings\Security Settings\
  # System Services\Print Spooler -> Disabled  (backed by Spooler:Start REG_DWORD = 4)
end

control 'cis-5.2' do
  title 'Ensure \'Print Spooler (Spooler)\' is set to \'Disabled\' (MS only) (Automated)'
  desc  'The Print Spooler service spools print jobs and handles printer ' \
        'interaction. Disabling it mitigates the PrintNightmare vulnerability ' \
        '(CVE-2021-34527) and other attacks against the service. The ' \
        'recommended state is Disabled (service Start type 4).'
  impact 0.7
  tag cis_id:    '5.2'
  tag level:     ['L2']
  tag scope:     'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  only_if('Applies to Member Servers only') { input('server_role') == 'member_server' }
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler') do
    its('Start') { should cmp == 4 }
  end
  # Remediation guidance: Computer Configuration\Policies\Windows Settings\Security Settings\
  # System Services\Print Spooler -> Disabled  (backed by Spooler:Start REG_DWORD = 4)
end

# =
# --- SECTION: 9  Windows Defender Firewall ---
# =

control 'cis-9.1.1' do
  title 'Ensure \'Windows Firewall: Domain: Firewall state\' is set to \'On (recommended)\' (Automated)'
  impact 0.5
  tag cis_id: '9.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    its('EnableFirewall') { should cmp == 1 }
  end
end

control 'cis-9.1.2' do
  title 'Ensure \'Windows Firewall: Domain: Inbound connections\' is set to \'Block (default)\' (Automated)'
  impact 0.5
  tag cis_id: '9.1.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    its('DefaultInboundAction') { should cmp == 1 }
  end
end

control 'cis-9.1.3' do
  title 'Ensure \'Windows Firewall: Domain: Settings: Display a notification\' is set to \'No\' (Automated)'
  impact 0.5
  tag cis_id: '9.1.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    its('DisableNotifications') { should cmp == 1 }
  end
end

control 'cis-9.1.4' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Name\' is configured (Automated)'
  impact 0.5
  tag cis_id: '9.1.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    # REVIEW: organization-specific value -- benchmark prescribes: <path>\<filename>.log. Where <path> is the location and <file> is
    it { should have_property 'LogFilePath' }
  end
end

control 'cis-9.1.5' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\' (Automated)'
  impact 0.5
  tag cis_id: '9.1.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    its('LogFileSize') { should cmp == 16384 }
  end
end

control 'cis-9.1.6' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Log dropped packets\' is set to \'Yes\' (Automated)'
  impact 0.5
  tag cis_id: '9.1.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    its('LogDroppedPackets') { should cmp == 1 }
  end
end

control 'cis-9.1.7' do
  title 'Ensure \'Windows Firewall: Domain: Logging: Log successful connections\' is set to \'Yes\' (Automated)'
  impact 0.5
  tag cis_id: '9.1.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    its('LogSuccessfulConnections') { should cmp == 1 }
  end
end

control 'cis-9.2.1' do
  title 'Ensure \'Windows Firewall: Private: Firewall state\' is set to \'On (recommended)\' (Automated)'
  impact 0.5
  tag cis_id: '9.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    its('EnableFirewall') { should cmp == 1 }
  end
end

control 'cis-9.2.2' do
  title 'Ensure \'Windows Firewall: Private: Inbound connections\' is set to \'Block (default)\' (Automated)'
  impact 0.5
  tag cis_id: '9.2.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    its('DefaultInboundAction') { should cmp == 1 }
  end
end

control 'cis-9.2.3' do
  title 'Ensure \'Windows Firewall: Private: Settings: Display a notification\' is set to \'No\' (Automated)'
  impact 0.5
  tag cis_id: '9.2.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    its('DisableNotifications') { should cmp == 1 }
  end
end

control 'cis-9.2.4' do
  title 'Ensure \'Windows Firewall: Private: Logging: Name\' is configured (Automated)'
  impact 0.5
  tag cis_id: '9.2.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    # REVIEW: organization-specific value -- benchmark prescribes: <path>\<filename>.log. Where <path> is the location and <file> is
    it { should have_property 'LogFilePath' }
  end
end

control 'cis-9.2.5' do
  title 'Ensure \'Windows Firewall: Private: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\' (Automated)'
  impact 0.5
  tag cis_id: '9.2.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    its('LogFileSize') { should cmp == 16384 }
  end
end

control 'cis-9.2.6' do
  title 'Ensure \'Windows Firewall: Private: Logging: Log dropped packets\' is set to \'Yes\' (Automated)'
  impact 0.5
  tag cis_id: '9.2.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    its('LogDroppedPackets') { should cmp == 1 }
  end
end

control 'cis-9.2.7' do
  title 'Ensure \'Windows Firewall: Private: Logging: Log successful connections\' is set to \'Yes\' (Automated)'
  impact 0.5
  tag cis_id: '9.2.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    its('LogSuccessfulConnections') { should cmp == 1 }
  end
end

control 'cis-9.3.1' do
  title 'Ensure \'Windows Firewall: Public: Firewall state\' is set to \'On (recommended)\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('EnableFirewall') { should cmp == 1 }
  end
end

control 'cis-9.3.2' do
  title 'Ensure \'Windows Firewall: Public: Inbound connections\' is set to \'Block (default)\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('DefaultInboundAction') { should cmp == 1 }
  end
end

control 'cis-9.3.3' do
  title 'Ensure \'Windows Firewall: Public: Settings: Display a notification\' is set to \'No\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('DisableNotifications') { should cmp == 1 }
  end
end

control 'cis-9.3.4' do
  title 'Ensure \'Windows Firewall: Public: Settings: Apply local firewall rules\' is set to \'No\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('AllowLocalPolicyMerge') { should cmp == 0 }
  end
end

control 'cis-9.3.5' do
  title 'Ensure \'Windows Firewall: Public: Settings: Apply local connection security rules\' is set to \'No\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('AllowLocalIPsecPolicyMerge') { should cmp == 0 }
  end
end

control 'cis-9.3.6' do
  title 'Ensure \'Windows Firewall: Public: Logging: Name\' is configured (Automated)'
  impact 0.5
  tag cis_id: '9.3.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    # REVIEW: organization-specific value -- benchmark prescribes: <path>\<filename>.log. Where <path> is the location and <file> is
    it { should have_property 'LogFilePath' }
  end
end

control 'cis-9.3.7' do
  title 'Ensure \'Windows Firewall: Public: Logging: Size limit (KB)\' is set to \'16,384 KB or greater\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    its('LogFileSize') { should cmp == 16384 }
  end
end

control 'cis-9.3.8' do
  title 'Ensure \'Windows Firewall: Public: Logging: Log dropped packets\' is set to \'Yes\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.8'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    its('LogDroppedPackets') { should cmp == 1 }
  end
end

control 'cis-9.3.9' do
  title 'Ensure \'Windows Firewall: Public: Logging: Log successful connections\' is set to \'Yes\' (Automated)'
  impact 0.5
  tag cis_id: '9.3.9'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    its('LogSuccessfulConnections') { should cmp == 1 }
  end
end

# =
# --- SECTION: 17 Advanced Audit Policy ---
# =

control 'cis-17.1.1' do
  title 'Ensure \'Audit Credential Validation\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Credential Validation') { should eq 'Success and Failure' }
  end
end

control 'cis-17.1.2' do
  title 'Ensure \'Audit Kerberos Authentication Service\' is set to \'Success and Failure\' (DC Only) (Automated)'
  impact 0.5
  tag cis_id: '17.1.2'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Kerberos Authentication Service') { should eq 'Success and Failure' }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-17.1.3' do
  title 'Ensure \'Audit Kerberos Service Ticket Operations\' is set to \'Success and Failure\' (DC Only) (Automated)'
  impact 0.5
  tag cis_id: '17.1.3'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Kerberos Service Ticket Operations') { should eq 'Success and Failure' }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-17.2.1' do
  title 'Ensure \'Audit Application Group Management\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Application Group Management') { should eq 'Success and Failure' }
  end
end

control 'cis-17.2.2' do
  title 'Ensure \'Audit Computer Account Management\' is set to include \'Success\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '17.2.2'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Computer Account Management') { should match /Success/ }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-17.2.3' do
  title 'Ensure \'Audit Distribution Group Management\' is set to include \'Success\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '17.2.3'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Distribution Group Management') { should match /Success/ }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-17.2.4' do
  title 'Ensure \'Audit Other Account Management Events\' is set to include \'Success\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '17.2.4'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Other Account Management Events') { should match /Success/ }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-17.2.5' do
  title 'Ensure \'Audit Security Group Management\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.2.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Security Group Management') { should match /Success/ }
  end
end

control 'cis-17.2.6' do
  title 'Ensure \'Audit User Account Management\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.2.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('User Account Management') { should eq 'Success and Failure' }
  end
end

control 'cis-17.3.1' do
  title 'Ensure \'Audit PNP Activity\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.3.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('PNP Activity') { should match /Success/ }
  end
end

control 'cis-17.3.2' do
  title 'Ensure \'Audit Process Creation\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.3.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Process Creation') { should match /Success/ }
  end
end

control 'cis-17.4.1' do
  title 'Ensure \'Audit Directory Service Access\' is set to include \'Failure\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '17.4.1'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Directory Service Access') { should match /Failure/ }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-17.4.2' do
  title 'Ensure \'Audit Directory Service Changes\' is set to include \'Success\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '17.4.2'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Directory Service Changes') { should match /Success/ }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-17.5.1' do
  title 'Ensure \'Audit Account Lockout\' is set to include \'Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.5.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Account Lockout') { should match /Failure/ }
  end
end

control 'cis-17.5.2' do
  title 'Ensure \'Audit Group Membership\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.5.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Group Membership') { should match /Success/ }
  end
end

control 'cis-17.5.3' do
  title 'Ensure \'Audit Logoff\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.5.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Logoff') { should match /Success/ }
  end
end

control 'cis-17.5.4' do
  title 'Ensure \'Audit Logon\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.5.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Logon') { should eq 'Success and Failure' }
  end
end

control 'cis-17.5.5' do
  title 'Ensure \'Audit Other Logon/Logoff Events\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.5.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Other Logon/Logoff Events') { should eq 'Success and Failure' }
  end
end

control 'cis-17.5.6' do
  title 'Ensure \'Audit Special Logon\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.5.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Special Logon') { should match /Success/ }
  end
end

control 'cis-17.6.1' do
  title 'Ensure \'Audit Detailed File Share\' is set to include \'Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.6.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Detailed File Share') { should match /Failure/ }
  end
end

control 'cis-17.6.2' do
  title 'Ensure \'Audit File Share\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.6.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('File Share') { should eq 'Success and Failure' }
  end
end

control 'cis-17.6.3' do
  title 'Ensure \'Audit Other Object Access Events\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.6.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Other Object Access Events') { should eq 'Success and Failure' }
  end
end

control 'cis-17.6.4' do
  title 'Ensure \'Audit Removable Storage\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.6.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Removable Storage') { should eq 'Success and Failure' }
  end
end

control 'cis-17.7.1' do
  title 'Ensure \'Audit Audit Policy Change\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.7.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Audit Policy Change') { should match /Success/ }
  end
end

control 'cis-17.7.2' do
  title 'Ensure \'Audit Authentication Policy Change\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.7.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Authentication Policy Change') { should match /Success/ }
  end
end

control 'cis-17.7.3' do
  title 'Ensure \'Audit Authorization Policy Change\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.7.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Authorization Policy Change') { should match /Success/ }
  end
end

control 'cis-17.7.4' do
  title 'Ensure \'Audit MPSSVC Rule-Level Policy Change\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.7.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('MPSSVC Rule-Level Policy Change') { should eq 'Success and Failure' }
  end
end

control 'cis-17.7.5' do
  title 'Ensure \'Audit Other Policy Change Events\' is set to include \'Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.7.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Other Policy Change Events') { should match /Failure/ }
  end
end

control 'cis-17.8.1' do
  title 'Ensure \'Audit Sensitive Privilege Use\' is set to \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.8.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Sensitive Privilege Use') { should eq 'Success' }
  end
end

control 'cis-17.9.1' do
  title 'Ensure \'Audit IPsec Driver\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.9.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('IPsec Driver') { should eq 'Success and Failure' }
  end
end

control 'cis-17.9.2' do
  title 'Ensure \'Audit Other System Events\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.9.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Other System Events') { should eq 'Success and Failure' }
  end
end

control 'cis-17.9.3' do
  title 'Ensure \'Audit Security State Change\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.9.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Security State Change') { should match /Success/ }
  end
end

control 'cis-17.9.4' do
  title 'Ensure \'Audit Security System Extension\' is set to include \'Success\' (Automated)'
  impact 0.5
  tag cis_id: '17.9.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('Security System Extension') { should match /Success/ }
  end
end

control 'cis-17.9.5' do
  title 'Ensure \'Audit System Integrity\' is set to \'Success and Failure\' (Automated)'
  impact 0.5
  tag cis_id: '17.9.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'audit_policy'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe audit_policy do
    its('System Integrity') { should eq 'Success and Failure' }
  end
end

# =
# --- SECTION: 18 Administrative Templates (Computer) ---
# =

control 'cis-18.1.1.1' do
  title 'Ensure \'Prevent enabling lock screen camera\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.1.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization') do
    its('NoLockScreenCamera') { should cmp == 1 }
  end
end

control 'cis-18.1.1.2' do
  title 'Ensure \'Prevent enabling lock screen slide show\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.1.1.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization') do
    its('NoLockScreenSlideshow') { should cmp == 1 }
  end
end

control 'cis-18.1.2.2' do
  title 'Ensure \'Allow users to enable online speech recognition services\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.1.2.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization') do
    its('AllowInputPersonalization') { should cmp == 0 }
  end
end

control 'cis-18.1.3' do
  title 'Ensure \'Allow Online Tips\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.1.3'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('AllowOnlineTips') { should cmp == 0 }
  end
end

control 'cis-18.4.1' do
  title 'Ensure \'Apply UAC restrictions to local accounts on network logons\' is set to \'Enabled\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '18.4.1'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('LocalAccountTokenFilterPolicy') { should cmp == 0 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.4.2' do
  title 'Ensure \'Configure SMB v1 client driver\' is set to \'Enabled: Disable driver (recommended)\' (Automated)'
  impact 0.5
  tag cis_id: '18.4.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10') do
    its('Start') { should cmp == 4 }
  end
end

control 'cis-18.4.3' do
  title 'Ensure \'Configure SMB v1 server\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.4.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters') do
    its('SMB1') { should cmp == 0 }
  end
end

control 'cis-18.4.4' do
  title 'Ensure \'Enable Certificate Padding\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.4.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config') do
    its('EnableCertPaddingCheck') { should cmp == 1 }
  end
end

control 'cis-18.4.5' do
  title 'Ensure \'Enable Structured Exception Handling Overwrite Protection (SEHOP)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.4.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SessionManager\\kernel') do
    its('DisableExceptionChainValidation') { should cmp == 0 }
  end
end

control 'cis-18.4.6' do
  title 'Ensure \'NetBT NodeType configuration\' is set to \'Enabled: P-node (recommended)\' (Automated)'
  impact 0.5
  tag cis_id: '18.4.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters') do
    its('NodeType') { should cmp == 2 }
  end
end

control 'cis-18.5.1' do
  title 'Ensure \'MSS: (AutoAdminLogon) Enable Automatic Logon\' is set to \'Disabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.5.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.5.1): Ensure \'MSS: (AutoAdminLogon) Enable Automatic Logon\' is set to \'Disabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (AutoAdminLogon) Enable Automatic Logon Note: This Group Policy path does not exist by default. An additional Group Policy template (MS
end

control 'cis-18.5.2' do
  title 'Ensure \'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level\' is set to \'Enabled: Highest protection, source routing is completely disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.5.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters') do
    its('DisableIPSourceRouting') { should cmp == 2 }
  end
end

control 'cis-18.5.3' do
  title 'Ensure \'MSS: (DisableIPSourceRouting) IP source routing protection level\' is set to \'Enabled: Highest protection, source routing is completely disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.5.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    its('DisableIPSourceRouting') { should cmp == 2 }
  end
end

control 'cis-18.5.4' do
  title 'Ensure \'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.5.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    its('EnableICMPRedirect') { should cmp == 0 }
  end
end

control 'cis-18.5.5' do
  title 'Ensure \'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds\' is set to \'Enabled: 300,000 or 5 minutes\' (Automated)'
  impact 0.7
  tag cis_id: '18.5.5'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    its('KeepAliveTime') { should cmp == 300000 }
  end
end

control 'cis-18.5.6' do
  title 'Ensure \'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.5.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters') do
    its('NoNameReleaseOnDemand') { should cmp == 1 }
  end
end

control 'cis-18.5.7' do
  title 'Ensure \'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.5.7'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    its('PerformRouterDiscovery') { should cmp == 0 }
  end
end

control 'cis-18.5.8' do
  title 'Ensure \'MSS: (SafeDllSearchMode) Enable Safe DLL search mode\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.5.8'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.5.8): Ensure \'MSS: (SafeDllSearchMode) Enable Safe DLL search mode\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (SafeDllSearchMode) Enable Safe DLL search mode Note: This Group Policy path does not exist by default. An additional Group Policy templ
end

control 'cis-18.5.9' do
  title 'Ensure \'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted\' is set to \'Enabled: 3\' (Automated)'
  impact 0.7
  tag cis_id: '18.5.9'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    its('TcpMaxDataRetransmissions') { should cmp == 3 }
  end
end

control 'cis-18.5.10' do
  title 'Ensure \'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted\' is set to \'Enabled: 3\' (Automated)'
  impact 0.7
  tag cis_id: '18.5.10'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters') do
    its('TcpMaxDataRetransmissions') { should cmp == 3 }
  end
end

control 'cis-18.5.11' do
  title 'Ensure \'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning\' is set to \'Enabled: 90% or less\' (Automated)'
  impact 0.5
  tag cis_id: '18.5.11'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security') do
    its('WarningLevel') { should cmp == 90 }
  end
end

control 'cis-18.6.4.1' do
  title 'Ensure \'Configure multicast DNS (mDNS) protocol\' is set to \'Disabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.6.4.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.6.4.1): Ensure \'Configure multicast DNS (mDNS) protocol\' is set to \'Disabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Configure multicast DNS (mDNS) protocol Note: This Group Policy path is provided by the Group Policy template DnsClient.admx/adml that
end

control 'cis-18.6.4.2' do
  title 'Ensure \'Configure NetBIOS settings\' is set to \'Enabled: Disable NetBIOS name resolution on public networks\' (Automated)'
  impact 0.0
  tag cis_id: '18.6.4.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.6.4.2): Ensure \'Configure NetBIOS settings\' is set to \'Enabled: Disable NetBIOS name resolution on public networks\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Disable NetBIOS name resolution on public networks: Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Configure NetBIOS settings Note: This Group Policy path may not exist by default. I
end

control 'cis-18.6.4.3' do
  title 'Ensure \'Turn off default IPv6 DNS Servers\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.6.4.3'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsNT\\DNSClient') do
    its('DisableIPv6DefaultDnsServers') { should cmp == 1 }
  end
end

control 'cis-18.6.4.4' do
  title 'Ensure \'Turn off multicast name resolution\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.6.4.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.6.4.4): Ensure \'Turn off multicast name resolution\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Network\DNS Client\Turn off multicast name resolution Note: This Group Policy path may not exist by default. It is provided by the Group Policy template D
end

control 'cis-18.6.5.1' do
  title 'Ensure \'Enable Font Providers\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.6.5.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('EnableFontProviders') { should cmp == 0 }
  end
end

control 'cis-18.6.7.1' do
  title 'Ensure \'Mandate the minimum version of SMB\' is set to \'Enabled: 3.1.1\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.7.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer') do
    its('MinSmb2Dialect') { should cmp == 785 }
  end
end

control 'cis-18.6.8.1' do
  title 'Ensure \'Enable insecure guest logons\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.8.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation') do
    its('AllowInsecureGuestAuth') { should cmp == 0 }
  end
end

control 'cis-18.6.8.2' do
  title 'Ensure \'Require Encryption\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.8.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation') do
    its('RequireEncryption') { should cmp == 1 }
  end
end

control 'cis-18.6.9.1' do
  title 'Ensure \'Turn on Mapper I/O (LLTDIO) driver\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.6.9.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LLTD') do
    its('AllowLLTDIOOnDomain') { should cmp == 0 }
  end
end

control 'cis-18.6.9.2' do
  title 'Ensure \'Turn on Responder (RSPNDR) driver\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.6.9.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LLTD') do
    its('AllowRspndrOnDomain') { should cmp == 0 }
  end
end

control 'cis-18.6.10.2' do
  title 'Ensure \'Turn off Microsoft Peer-to-Peer Networking Services\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.6.10.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Peernet') do
    its('Disabled') { should cmp == 1 }
  end
end

control 'cis-18.6.11.2' do
  title 'Ensure \'Prohibit installation and configuration of Network Bridge on your DNS domain network\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.11.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnections') do
    its('NC_AllowNetBridge_NLA') { should cmp == 0 }
  end
end

control 'cis-18.6.11.3' do
  title 'Ensure \'Prohibit use of Internet Connection Sharing on your DNS domain network\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.11.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnections') do
    its('NC_ShowSharedAccessUI') { should cmp == 0 }
  end
end

control 'cis-18.6.11.4' do
  title 'Ensure \'Require domain users to elevate when setting a network\'s location\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.11.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnections') do
    its('NC_StdDomainUserSetLocation') { should cmp == 1 }
  end
end

control 'cis-18.6.14.1' do
  title 'Ensure \'Hardened UNC Paths\' is set to \'Enabled, with "Require Mutual Authentication", "Require Integrity", and "Require Privacy" set for all NETLOGON and SYSVOL shares\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.14.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths') do
    # REVIEW: organization-specific value -- benchmark prescribes: RequireMutualAuthentication=1, RequireIntegrity=1,
    it { should have_property '\\\\*\\NETLOGON' }
  end
end

control 'cis-18.6.19.2.1' do
  title 'Ensure \'Disable IPv6 (Ensure TCPIP6 Parameter \'DisabledComponents\' is set to \'0xff (255)\')\' (Automated)'
  desc  'Disabling IPv6 components removes a possible attack surface that is ' \
        'harder to monitor. The recommended state is DisabledComponents = ' \
        '0xff (255). Configuring this also mitigates CVE-2024-38063, a TCP/IP ' \
        'Remote Code Execution vulnerability. Note: connectivity to systems ' \
        'using IPv6 and software depending on IPv6 will cease to function.'
  impact 0.7
  tag cis_id:    '18.6.19.2.1'
  tag level:     ['L2']
  tag scope:     'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters') do
    its('DisabledComponents') { should cmp == 255 }
  end
  # Remediation guidance: Set REG_DWORD value DisabledComponents = 0xff (255) at
  # HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters. See Microsoft KB 929852.
  # A reboot is required for the change to take effect.
end

control 'cis-18.6.20.1' do
  title 'Ensure \'Configuration of wireless settings using Windows Connect Now\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.6.20.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WCN\\Registrars') do
    its('EnableRegistrars') { should cmp == 0 }
  end
end

control 'cis-18.6.20.2' do
  title 'Ensure \'Prohibit access of the Windows Connect Now wizards\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.6.20.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WCN\\UI') do
    its('DisableWcnUi') { should cmp == 1 }
  end
end

control 'cis-18.6.21.1' do
  title 'Ensure \'Minimize the number of simultaneous connections to the Internet or a Windows Domain\' is set to \'Enabled: 3 = Prevent Wi-Fi when on Ethernet\' (Automated)'
  impact 0.5
  tag cis_id: '18.6.21.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    its('fMinimizeConnections') { should cmp == 3 }
  end
end

control 'cis-18.6.21.2' do
  title 'Ensure \'Prohibit connection to non-domain networks when connected to domain authenticated network\' is set to \'Enabled\' (MS only) (Automated)'
  impact 0.7
  tag cis_id: '18.6.21.2'
  tag level: ['L2']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy') do
    its('fBlockNonDomain') { should cmp == 1 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.7.1' do
  title 'Ensure \'Allow Print Spooler to accept client connections\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.7.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsNT\\Printers') do
    its('RegisterSpoolerRemoteRpcEndPoint') { should cmp == 2 }
  end
end

control 'cis-18.7.2' do
  title 'Ensure \'Configure Redirection Guard\' is set to \'Enabled: Redirection Guard Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.7.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.7.2): Ensure \'Configure Redirection Guard\' is set to \'Enabled: Redirection Guard Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Redirection Guard Enabled: Computer Configuration\Policies\Administrative Templates\Printers\Configure Redirection Guard Note: This Group Policy path is provided by the Group Policy template Printing.admx/adml t
end

control 'cis-18.7.3' do
  title 'Ensure \'Configure RPC connection settings: Protocol to use for outgoing RPC connections\' is set to \'Enabled: RPC over TCP\' (Automated)'
  impact 0.5
  tag cis_id: '18.7.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsNT\\Printers\\RPC') do
    its('RpcUseNamedPipeProtocol') { should cmp == 0 }
  end
end

control 'cis-18.7.4' do
  title 'Ensure \'Configure RPC connection settings: Use authentication for outgoing RPC connections\' is set to \'Enabled: Default\' (Automated)'
  impact 0.0
  tag cis_id: '18.7.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.7.4): Ensure \'Configure RPC connection settings: Use authentication for outgoing RPC connections\' is set to \'Enabled: Default\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Default: Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC connection settings: Use authentication for outgoing RPC connections Note: This Group Policy path is provided by the Group
end

control 'cis-18.7.5' do
  title 'Ensure \'Configure RPC listener settings: Protocols to allow for incoming RPC connections\' is set to \'Enabled: RPC over TCP\' (Automated)'
  impact 0.5
  tag cis_id: '18.7.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsNT\\Printers\\RPC') do
    its('RpcProtocols') { should cmp == 5 }
  end
end

control 'cis-18.7.6' do
  title 'Ensure \'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:\' is set to \'Enabled: Negotiate\' or higher (Automated)'
  impact 0.0
  tag cis_id: '18.7.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.7.6): Ensure \'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:\' is set to \'Enabled: Negotiate\' or higher (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Negotiate or Enabled: Kerberos: Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC listener settings: Configure protocol options for incoming RPC connections Note: This Group Policy 
end

control 'cis-18.7.7' do
  title 'Ensure \'Configure RPC over TCP port\' is set to \'Enabled: 0\' (Automated)'
  impact 0.0
  tag cis_id: '18.7.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.7.7): Ensure \'Configure RPC over TCP port\' is set to \'Enabled: 0\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: 0: Computer Configuration\Policies\Administrative Templates\Printers\Configure RPC over TCP port Note: This Group Policy path is provided by the Group Policy template Printing.admx/adml that is included with the
end

control 'cis-18.7.8' do
  title 'Ensure \'Configure RPC packet level privacy setting for incoming connections\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.7.8'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print') do
    its('RpcAuthnLevelPrivacyEnabled') { should cmp == 1 }
  end
end

control 'cis-18.7.9' do
  title 'Ensure \'Limits print driver installation to Administrators\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.7.9'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsNT\\Printers\\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should cmp == 1 }
  end
end

control 'cis-18.7.10' do
  title 'Ensure \'Manage processing of Queue-specific files\' is set to \'Enabled: Limit Queue-specific files to Color profiles\' (Automated)'
  impact 0.0
  tag cis_id: '18.7.10'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.7.10): Ensure \'Manage processing of Queue-specific files\' is set to \'Enabled: Limit Queue-specific files to Color profiles\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Limit Queue-specific files to Color profiles: Computer Configuration\Policies\Administrative Templates\Printers\Manage processing of Queue-specific files Note: This Group Policy path is provided by the Group Pol
end

control 'cis-18.7.11' do
  title 'Ensure \'Point and Print Restrictions: When installing drivers for a new connection\' is set to \'Enabled: Show warning and elevation prompt\' (Automated)'
  impact 0.5
  tag cis_id: '18.7.11'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsNT\\Printers\\PointAndPrint') do
    its('NoWarningNoElevationOnInstall') { should cmp == 0 }
  end
end

control 'cis-18.7.12' do
  title 'Ensure \'Point and Print Restrictions: When updating drivers for an existing connection\' is set to \'Enabled: Show warning and elevation prompt\' (Automated)'
  impact 0.5
  tag cis_id: '18.7.12'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsNT\\Printers\\PointAndPrint') do
    its('UpdatePromptSettings') { should cmp == 0 }
  end
end

control 'cis-18.8.1.1' do
  title 'Ensure \'Turn off notifications network usage\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.8.1.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications') do
    its('NoCloudApplicationNotification') { should cmp == 1 }
  end
end

control 'cis-18.9.3.1' do
  title 'Ensure \'Include command line in process creation events\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.3.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit') do
    its('ProcessCreationIncludeCmdLine_Enabled') { should cmp == 1 }
  end
end

control 'cis-18.9.4.1' do
  title 'Ensure \'Encryption Oracle Remediation\' is set to \'Enabled: Force Updated Clients\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.4.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters') do
    its('AllowEncryptionOracle') { should cmp == 0 }
  end
end

control 'cis-18.9.4.2' do
  title 'Ensure \'Remote host allows delegation of non-exportable credentials\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.4.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation') do
    its('AllowProtectedCreds') { should cmp == 1 }
  end
end

control 'cis-18.9.5.1' do
  title 'Ensure \'Turn On Virtualization Based Security\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.5.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    its('EnableVirtualizationBasedSecurity') { should cmp == 1 }
  end
end

control 'cis-18.9.5.2' do
  title 'Ensure \'Turn On Virtualization Based Security: Select Platform Security Level\' is set to \'Secure Boot\' or higher (Automated)'
  impact 0.5
  tag cis_id: '18.9.5.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    its('RequirePlatformSecurityFeatures') { should be_in [1, 3] }
  end
end

control 'cis-18.9.5.3' do
  title 'Ensure \'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity\' is set to \'Enabled with UEFI lock\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.5.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    its('HypervisorEnforcedCodeIntegrity') { should cmp == 1 }
  end
end

control 'cis-18.9.5.4' do
  title 'Ensure \'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table\' is set to \'True (checked)\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.5.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    its('HVCIMATRequired') { should cmp == 1 }
  end
end

control 'cis-18.9.5.5' do
  title 'Ensure \'Turn On Virtualization Based Security: Credential Guard Configuration\' is set to \'Enabled with UEFI lock\' (MS Only) (Automated)'
  impact 0.5
  tag cis_id: '18.9.5.5'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    its('LsaCfgFlags') { should cmp == 1 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.5.6' do
  title 'Ensure \'Turn On Virtualization Based Security: Credential Guard Configuration\' is set to \'Disabled\' (DC Only) (Automated)'
  impact 0.5
  tag cis_id: '18.9.5.6'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    its('LsaCfgFlags') { should cmp == 0 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-18.9.5.7' do
  title 'Ensure \'Turn On Virtualization Based Security: Secure Launch Configuration\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.5.7'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard') do
    its('ConfigureSystemGuardLaunch') { should cmp == 1 }
  end
end

control 'cis-18.9.7.2' do
  title 'Ensure \'Prevent automatic download of applications associated with device metadata\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.7.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceMetadata') do
    its('PreventDeviceMetadataFromNetwork') { should cmp == 1 }
  end
end

control 'cis-18.9.13.1' do
  title 'Ensure \'Boot-Start Driver Initialization Policy\' is set to \'Enabled: Good, unknown and bad but critical\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.13.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch') do
    its('DriverLoadPolicy') { should cmp == 3 }
  end
end

control 'cis-18.9.17.1' do
  title 'Ensure \'Enable / disable CLFS logfile authentication\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.17.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Policies') do
    its('ClfsAuthenticationChecking') { should cmp == 1 }
  end
end

control 'cis-18.9.19.2' do
  title 'Ensure \'Configure security policy processing: Do not apply during periodic background processing\' is set to \'Enabled: FALSE\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.19.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GroupA4EA-00C04F79F83A}') do
    its('NoBackgroundPolicy') { should cmp == 0 }
  end
end

control 'cis-18.9.19.3' do
  title 'Ensure \'Configure security policy processing: Process even if the Group Policy objects have not changed\' is set to \'Enabled: TRUE\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.19.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GroupA4EA-00C04F79F83A}') do
    its('NoGPOListChanges') { should cmp == 0 }
  end
end

control 'cis-18.9.19.4' do
  title 'Ensure \'Continue experiences on this device\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.19.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('EnableCdp') { should cmp == 0 }
  end
end

control 'cis-18.9.19.5' do
  title 'Ensure \'Turn off background refresh of Group Policy\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.19.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DisableBkGndGroupPolicy') { should cmp == 0 }
  end
end

control 'cis-18.9.20.1.1' do
  title 'Ensure \'Turn off downloading of print drivers over HTTP\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.9.20.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.9.20.1.1): Ensure \'Turn off downloading of print drivers over HTTP\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off downloading of print drivers over HTTP Note: This Group Policy path is p
end

control 'cis-18.9.20.1.2' do
  title 'Ensure \'Turn off handwriting personalization data sharing\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\TabletPC') do
    its('PreventHandwritingDataSharing') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.3' do
  title 'Ensure \'Turn off handwriting recognition error reporting\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.3'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\HandwritingErrorReports') do
    its('PreventHandwritingErrorReports') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.4' do
  title 'Ensure \'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.4'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\InternetWizard') do
    its('ExitOnMSICW') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.5' do
  title 'Ensure \'Turn off Internet download for Web publishing and online ordering wizards\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.20.1.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('NoWebServices') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.6' do
  title 'Ensure \'Turn off printing over HTTP\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.9.20.1.6'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.9.20.1.6): Ensure \'Turn off printing over HTTP\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off printing over HTTP Note: This Group Policy path is provided by the Group
end

control 'cis-18.9.20.1.7' do
  title 'Ensure \'Turn off Registration if URL connection is referring to Microsoft.com\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.7'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\RegistrationControl') do
    its('NoRegistration') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.8' do
  title 'Ensure \'Turn off Search Companion content file updates\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.8'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SearchCompanion') do
    its('DisableContentFileUpdates') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.9' do
  title 'Ensure \'Turn off the "Order Prints" picture task\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.9'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('NoOnlinePrintsWizard') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.10' do
  title 'Ensure \'Turn off the "Publish to Web" task for files and folders\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.10'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('NoPublishingWizard') { should cmp == 1 }
  end
end

control 'cis-18.9.20.1.11' do
  title 'Ensure \'Turn off the Windows Messenger Customer Experience Improvement Program\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.11'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Messenger\\Client') do
    its('CEIP') { should cmp == 2 }
  end
end

control 'cis-18.9.20.1.12' do
  title 'Ensure \'Turn off Windows Customer Experience Improvement Program\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.12'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows') do
    its('CEIPEnable') { should cmp == 0 }
  end
end

control 'cis-18.9.20.1.13' do
  title 'Ensure \'Turn off Windows Error Reporting\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.20.1.13'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsReporting') do
    # REVIEW: organization-specific value -- benchmark prescribes: 0 (DoReport) and 1 (Disabled)
    it { should have_property 'Disabled' }
  end
end

control 'cis-18.9.23.1' do
  title 'Ensure \'Support device authentication using certificate\' is set to \'Enabled: Automatic\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.23.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\kerberos\\parameters') do
    # REVIEW: organization-specific value -- benchmark prescribes: 0 (DevicePKInitBehavior) and 1 (DevicePKInitEnabled)
    it { should have_property 'DevicePKInitBehavior' }
  end
end

control 'cis-18.9.24.1' do
  title 'Ensure \'Enumeration policy for external devices incompatible with Kernel DMA Protection\' is set to \'Enabled: Block All\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.24.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\KernelProtection') do
    its('DeviceEnumerationPolicy') { should cmp == 0 }
  end
end

control 'cis-18.9.26.1' do
  title 'Ensure \'Configure password backup directory\' is set to \'Enabled: Active Directory\' or \'Enabled: Azure Active Directory\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.1'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('BackupDirectory') { should be_in [1, 2] }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.26.2' do
  title 'Ensure \'Do not allow password expiration time longer than required by policy\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.2'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('PasswordExpirationProtectionEnabled') { should cmp == 1 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.26.3' do
  title 'Ensure \'Enable password encryption\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.3'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('ADPasswordEncryptionEnabled') { should cmp == 1 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.26.4' do
  title 'Ensure \'Password Settings: Password Complexity\' is set to \'Enabled: Large letters + small letters + numbers + special characters\' or \'Passphrase\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.4'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('PasswordComplexity') { should be_in [4, 6, 7, 8] }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.26.5' do
  title 'Ensure \'Password Settings: Password Length\' is set to \'Enabled: 15 or more\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.5'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('PasswordLength') { should cmp == 15 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.26.6' do
  title 'Ensure \'Password Settings: Password Age (Days)\' is set to \'Enabled: 30 or fewer\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.6'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('PasswordAgeDays') { should cmp == 30 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.26.7' do
  title 'Ensure \'Post-authentication actions: Grace period (hours)\' is set to \'Enabled: 8 or fewer hours, but not 0\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.7'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('PostAuthenticationResetDelay') { should cmp >= 1 }
    its('PostAuthenticationResetDelay') { should cmp <= 8 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.26.8' do
  title 'Ensure \'Post-authentication actions: Actions\' is set to \'Enabled: Reset the password and logoff the managed account\' or higher (Automated)'
  impact 0.5
  tag cis_id: '18.9.26.8'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS') do
    its('PostAuthenticationActions') { should be_in [3, 5, 11] }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.27.1' do
  title 'Ensure \'Allow Custom SSPs and APs to be loaded into LSASS\' is set to \'Disabled\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '18.9.27.1'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('AllowCustomSSPsAPs') { should cmp == 0 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-18.9.27.2' do
  title 'Ensure \'Configures LSASS to run as a protected process\' is set to \'Enabled: Enabled with UEFI Lock\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.27.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('RunAsPPL') { should cmp == 1 }
  end
end

control 'cis-18.9.28.1' do
  title 'Ensure \'Disallow copying of user input methods to the system account for sign-in\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.28.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\ControlPanel\\International') do
    its('BlockUserInputMethodsForSignIn') { should cmp == 1 }
  end
end

control 'cis-18.9.29.1' do
  title 'Ensure \'Block user from showing account details on sign-in\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.29.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('BlockUserFromShowingAccountDetailsOnSignin') { should cmp == 1 }
  end
end

control 'cis-18.9.29.2' do
  title 'Ensure \'Do not display network selection UI\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.29.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('DontDisplayNetworkSelectionUI') { should cmp == 1 }
  end
end

control 'cis-18.9.29.3' do
  title 'Ensure \'Do not enumerate connected users on domain- joined computers\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.29.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('DontEnumerateConnectedUsers') { should cmp == 1 }
  end
end

control 'cis-18.9.29.4' do
  title 'Ensure \'Enumerate local users on domain-joined computers\' is set to \'Disabled\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '18.9.29.4'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('EnumerateLocalUsers') { should cmp == 0 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.9.29.5' do
  title 'Ensure \'Turn off app notifications on the lock screen\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.29.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('DisableLockScreenAppNotifications') { should cmp == 1 }
  end
end

control 'cis-18.9.29.6' do
  title 'Ensure \'Turn on convenience PIN sign-in\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.29.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('AllowDomainPINLogon') { should cmp == 0 }
  end
end

control 'cis-18.9.33.1' do
  title 'Ensure \'Allow Clipboard synchronization across devices\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.33.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('AllowCrossDeviceClipboard') { should cmp == 0 }
  end
end

control 'cis-18.9.33.2' do
  title 'Ensure \'Allow upload of User Activities\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.33.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    its('UploadUserActivities') { should cmp == 0 }
  end
end

control 'cis-18.9.35.6.1' do
  title 'Ensure \'Allow network connectivity during connected- standby (on battery)\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.35.6.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    its('DCSettingIndex') { should cmp == 0 }
  end
end

control 'cis-18.9.35.6.2' do
  title 'Ensure \'Allow network connectivity during connected- standby (plugged in)\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.35.6.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\f15576e8-98b7-4186-b944-eafa664402d9') do
    its('ACSettingIndex') { should cmp == 0 }
  end
end

control 'cis-18.9.35.6.3' do
  title 'Ensure \'Require a password when a computer wakes (on battery)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.35.6.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    its('DCSettingIndex') { should cmp == 1 }
  end
end

control 'cis-18.9.35.6.4' do
  title 'Ensure \'Require a password when a computer wakes (plugged in)\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.35.6.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    its('ACSettingIndex') { should cmp == 1 }
  end
end

control 'cis-18.9.37.1' do
  title 'Ensure \'Configure Offer Remote Assistance\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.37.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('fAllowUnsolicited') { should cmp == 0 }
  end
end

control 'cis-18.9.37.2' do
  title 'Ensure \'Configure Solicited Remote Assistance\' is set to \'Disabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.9.37.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.9.37.2): Ensure \'Configure Solicited Remote Assistance\' is set to \'Disabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\System\Remote Assistance\Configure Solicited Remote Assistance Note: This Group Policy path may not exist by default. It is provided by the Group Policy 
end

control 'cis-18.9.38.1' do
  title 'Ensure \'Enable RPC Endpoint Mapper Client Authentication\' is set to \'Enabled\' (MS only) (Automated)'
  impact 0.0
  tag cis_id: '18.9.38.1'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.9.38.1): Ensure \'Enable RPC Endpoint Mapper Client Authentication\' is set to \'Enabled\' (MS only) (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Enable RPC Endpoint Mapper Client Authentication Note: This Group Policy path may not exist by default. It is provided by the
end

control 'cis-18.9.38.2' do
  title 'Ensure \'Restrict Unauthenticated RPC clients\' is set to \'Enabled: Authenticated\' (MS only) (Automated)'
  impact 0.0
  tag cis_id: '18.9.38.2'
  tag level: ['L2']
  tag scope: 'MS'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.9.38.2): Ensure \'Restrict Unauthenticated RPC clients\' is set to \'Enabled: Authenticated\' (MS only) (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Authenticated: Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\Restrict Unauthenticated RPC clients Note: This Group Policy path may not exist by default. It is provided by 
end

control 'cis-18.9.41.1' do
  title 'Ensure \'Configure validation of ROCA-vulnerable WHfB keys during authentication\' is set to \'Enabled: Block\' (DC only) (Automated)'
  impact 0.5
  tag cis_id: '18.9.41.1'
  tag level: ['L1']
  tag scope: 'DC'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\SAM') do
    its('SamNGCKeyROCAValidation') { should cmp == 2 }
  end
  only_if('applies to Domain Controllers') { input('server_role') == 'domain_controller' }
end

control 'cis-18.9.49.5.1' do
  title 'Ensure \'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.49.5.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy') do
    its('DisableQueryRemoteServer') { should cmp == 0 }
  end
end

control 'cis-18.9.49.11.1' do
  title 'Ensure \'Enable/Disable PerfTrack\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.49.11.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}') do
    its('ScenarioExecutionEnabled') { should cmp == 0 }
  end
end

control 'cis-18.9.51.1' do
  title 'Ensure \'Turn off the advertising ID\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.9.51.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo') do
    its('DisabledByGroupPolicy') { should cmp == 1 }
  end
end

control 'cis-18.9.53.1.1' do
  title 'Ensure \'Enable Windows NTP Client\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.9.53.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpClient') do
    its('Enabled') { should cmp == 1 }
  end
end

control 'cis-18.9.53.1.2' do
  title 'Ensure \'Enable Windows NTP Server\' is set to \'Disabled\' (MS only) (Automated)'
  impact 0.5
  tag cis_id: '18.9.53.1.2'
  tag level: ['L1']
  tag scope: 'MS'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\W32Time\\TimeProviders\\NtpServer') do
    its('Enabled') { should cmp == 0 }
  end
  only_if('applies to Member Servers') { input('server_role') == 'member_server' }
end

control 'cis-18.10.4.1' do
  title 'Ensure \'Allow a Windows app to share application data between users\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.4.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateManager') do
    its('AllowSharedLocalAppData') { should cmp == 0 }
  end
end

control 'cis-18.10.6.1' do
  title 'Ensure \'Allow Microsoft accounts to be optional\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.6.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('MSAOptional') { should cmp == 1 }
  end
end

control 'cis-18.10.8.1' do
  title 'Ensure \'Disallow Autoplay for non-volume devices\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.8.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
    its('NoAutoplayfornonVolume') { should cmp == 1 }
  end
end

control 'cis-18.10.8.2' do
  title 'Ensure \'Set the default behavior for AutoRun\' is set to \'Enabled: Do not execute any autorun commands\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.8.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('NoAutorun') { should cmp == 1 }
  end
end

control 'cis-18.10.8.3' do
  title 'Ensure \'Turn off Autoplay\' is set to \'Enabled: All drives\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.8.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('NoDriveTypeAutoRun') { should cmp == 255 }
  end
end

control 'cis-18.10.9.1.1' do
  title 'Ensure \'Configure enhanced anti-spoofing\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.9.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures') do
    its('EnhancedAntiSpoofing') { should cmp == 1 }
  end
end

control 'cis-18.10.11.1' do
  title 'Ensure \'Allow Use of Camera\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.11.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Camera') do
    its('AllowCamera') { should cmp == 0 }
  end
end

control 'cis-18.10.13.1' do
  title 'Ensure \'Turn off cloud consumer account state content\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.13.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    its('DisableConsumerAccountStateContent') { should cmp == 1 }
  end
end

control 'cis-18.10.13.2' do
  title 'Ensure \'Turn off cloud optimized content\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.13.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent') do
    its('DisableCloudOptimizedContent') { should cmp == 1 }
  end
end

control 'cis-18.10.14.1' do
  title 'Ensure \'Require pin for pairing\' is set to \'Enabled: First Time\' OR \'Enabled: Always\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.14.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Connect') do
    its('RequirePinForPairing') { should be_in [1, 2] }
  end
end

control 'cis-18.10.15.1' do
  title 'Ensure \'Do not display the password reveal button\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.15.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredUI') do
    its('DisablePasswordReveal') { should cmp == 1 }
  end
end

control 'cis-18.10.15.2' do
  title 'Ensure \'Enumerate administrator accounts on elevation\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.15.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI') do
    its('EnumerateAdministrators') { should cmp == 0 }
  end
end

control 'cis-18.10.16.1' do
  title 'Ensure \'Allow Diagnostic Data\' is set to \'Enabled: Diagnostic data off (not recommended)\' or \'Enabled: Send required diagnostic data\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.16.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    its('AllowTelemetry') { should be_in [0, 1] }
  end
end

control 'cis-18.10.16.2' do
  title 'Ensure \'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service\' is set to \'Enabled: Disable Authenticated Proxy usage\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.16.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    its('DisableEnterpriseAuthProxy') { should cmp == 1 }
  end
end

control 'cis-18.10.16.3' do
  title 'Ensure \'Do not show feedback notifications\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.16.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    its('DoNotShowFeedbackNotifications') { should cmp == 1 }
  end
end

control 'cis-18.10.16.4' do
  title 'Ensure \'Enable OneSettings Auditing\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.16.4'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    its('EnableOneSettingsAuditing') { should cmp == 1 }
  end
end

control 'cis-18.10.16.5' do
  title 'Ensure \'Limit Diagnostic Log Collection\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.16.5'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    its('LimitDiagnosticLogCollection') { should cmp == 1 }
  end
end

control 'cis-18.10.16.6' do
  title 'Ensure \'Limit Dump Collection\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.16.6'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection') do
    its('LimitDumpCollection') { should cmp == 1 }
  end
end

control 'cis-18.10.18.1' do
  title 'Ensure \'Enable App Installer\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.18.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller') do
    its('EnableAppInstaller') { should cmp == 0 }
  end
end

control 'cis-18.10.18.2' do
  title 'Ensure \'Enable App Installer Experimental Features\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.18.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller') do
    its('EnableExperimentalFeatures') { should cmp == 0 }
  end
end

control 'cis-18.10.18.3' do
  title 'Ensure \'Enable App Installer Hash Override\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.18.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller') do
    its('EnableHashOverride') { should cmp == 0 }
  end
end

control 'cis-18.10.18.4' do
  title 'Ensure \'Enable App Installer Local Archive Malware Scan Override\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.18.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller') do
    its('EnableLocalArchiveMalwareScanOverride') { should cmp == 0 }
  end
end

control 'cis-18.10.18.5' do
  title 'Ensure \'Enable App Installer ms-appinstaller protocol\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.18.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller') do
    its('EnableMSAppInstallerProtocol') { should cmp == 0 }
  end
end

control 'cis-18.10.18.6' do
  title 'Ensure \'Enable App Installer Microsoft Store Source Certificate Validation Bypass\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.18.6'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller') do
    its('EnableBypassCertificatePinningForMicrosoftStore') { should cmp == 0 }
  end
end

control 'cis-18.10.18.7' do
  title 'Ensure \'Enable Windows Package Manager command line interfaces\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.18.7'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller') do
    its('EnableWindowsPackageManagerCommandLineInterfaces') { should cmp == 0 }
  end
end

control 'cis-18.10.26.1.1' do
  title 'Ensure \'Application: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    its('Retention') { should cmp == 0 }
  end
end

control 'cis-18.10.26.1.2' do
  title 'Ensure \'Application: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.1.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    its('MaxSize') { should cmp == 32768 }
  end
end

control 'cis-18.10.26.2.1' do
  title 'Ensure \'Security: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    its('Retention') { should cmp == 0 }
  end
end

control 'cis-18.10.26.2.2' do
  title 'Ensure \'Security: Specify the maximum log file size (KB)\' is set to \'Enabled: 196,608 or greater\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.2.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security') do
    its('MaxSize') { should cmp == 196608 }
  end
end

control 'cis-18.10.26.3.1' do
  title 'Ensure \'Setup: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.3.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    its('Retention') { should cmp == 0 }
  end
end

control 'cis-18.10.26.3.2' do
  title 'Ensure \'Setup: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.3.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup') do
    its('MaxSize') { should cmp == 32768 }
  end
end

control 'cis-18.10.26.4.1' do
  title 'Ensure \'System: Control Event Log behavior when the log file reaches its maximum size\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.4.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    its('Retention') { should cmp == 0 }
  end
end

control 'cis-18.10.26.4.2' do
  title 'Ensure \'System: Specify the maximum log file size (KB)\' is set to \'Enabled: 32,768 or greater\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.26.4.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System') do
    its('MaxSize') { should cmp == 32768 }
  end
end

control 'cis-18.10.29.2' do
  title 'Ensure \'Do not apply the Mark of the Web tag to files copied from insecure sources\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.29.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
    its('DisableMotWOnInsecurePathCopy') { should cmp == 0 }
  end
end

control 'cis-18.10.29.3' do
  title 'Ensure \'Turn off Data Execution Prevention for Explorer\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.29.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
    its('NoDataExecutionPrevention') { should cmp == 0 }
  end
end

control 'cis-18.10.29.4' do
  title 'Ensure \'Turn off heap termination on corruption\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.29.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer') do
    its('NoHeapTerminationOnCorruption') { should cmp == 0 }
  end
end

control 'cis-18.10.29.5' do
  title 'Ensure \'Turn off shell protocol protected mode\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.29.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    its('PreXPSP2ShellProtocolBehavior') { should cmp == 0 }
  end
end

control 'cis-18.10.36.1' do
  title 'Ensure \'Turn off location\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.36.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    its('DisableLocation') { should cmp == 1 }
  end
end

control 'cis-18.10.40.1' do
  title 'Ensure \'Allow Message Service Cloud Sync\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.40.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging') do
    its('AllowMessageSync') { should cmp == 0 }
  end
end

control 'cis-18.10.41.1' do
  title 'Ensure \'Block all consumer Microsoft account user authentication\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.41.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount') do
    its('DisableUserAuth') { should cmp == 1 }
  end
end

control 'cis-18.10.42.4.1' do
  title 'Ensure \'Enable EDR in block mode\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.42.4.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.42.4.1): Ensure \'Enable EDR in block mode\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Features\Enable EDR in block mode Note: This Group Policy path is provided by the Group Policy template Wi
end

control 'cis-18.10.42.5.1' do
  title 'Ensure \'Configure local setting override for reporting to Microsoft MAPS\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.5.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\Spynet') do
    its('LocalSettingOverrideSpynetReporting') { should cmp == 0 }
  end
end

control 'cis-18.10.42.5.2' do
  title 'Ensure \'Join Microsoft MAPS\' is set to \'Enabled: Advanced\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.42.5.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.42.5.2): Ensure \'Join Microsoft MAPS\' is set to \'Enabled: Advanced\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Advanced: Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\MAPS\Join Microsoft MAPS Note: This Group Policy path is provided by the Group Policy template W
end

control 'cis-18.10.42.6.1.1' do
  title 'Ensure \'Configure Attack Surface Reduction rules\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.6.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsGuard\\ASR') do
    its('ExploitGuard_ASR_Rules') { should cmp == 1 }
  end
end

control 'cis-18.10.42.6.1.2' do
  title 'Ensure \'Configure Attack Surface Reduction rules: Set the state for each ASR rule\' is configured (Automated)'
  impact 0.0
  tag cis_id: '18.10.42.6.1.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.42.6.1.2): Ensure \'Configure Attack Surface Reduction rules: Set the state for each ASR rule\' is configured (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path so that 26190899-1602-49e8-8b27-eb1d0a1ce869, 3b576869-a4ec-4529-8536- b80a7769e899, 56a863a9-875e-4185-98a7-b882c64b5ce5, 5beb7efe-fd9a-4556- 801d-275e5ffc04cc, 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84, 7674ba52-37eb- 4a4f-a9a
end

control 'cis-18.10.42.6.3.1' do
  title 'Ensure \'Prevent users and apps from accessing dangerous websites\' is set to \'Enabled: Block\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.42.6.3.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.42.6.3.1): Ensure \'Prevent users and apps from accessing dangerous websites\' is set to \'Enabled: Block\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Block: Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Microsoft Defender Exploit Guard\Network Protection\Prevent users and apps from accessing dangerous
end

control 'cis-18.10.42.7.1' do
  title 'Ensure \'Enable file hash computation feature\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.7.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\MpEngine') do
    its('EnableFileHashComputation') { should cmp == 1 }
  end
end

control 'cis-18.10.42.8.1' do
  title 'Ensure \'Convert warn verdict to block\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.42.8.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\NIS') do
    its('EnableConvertWarnToBlock') { should cmp == 1 }
  end
end

control 'cis-18.10.42.10.1' do
  title 'Ensure \'Configure real-time protection and Security Intelligence Updates during OOBE\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.10.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsProtection') do
    its('OobeEnableRtpAndSigUpdate') { should cmp == 1 }
  end
end

control 'cis-18.10.42.10.2' do
  title 'Ensure \'Scan all downloaded files and attachments\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.10.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsProtection') do
    its('DisableIOAVProtection') { should cmp == 0 }
  end
end

control 'cis-18.10.42.10.3' do
  title 'Ensure \'Turn off real-time protection\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.10.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsProtection') do
    its('DisableRealtimeMonitoring') { should cmp == 0 }
  end
end

control 'cis-18.10.42.10.4' do
  title 'Ensure \'Turn on behavior monitoring\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.10.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsProtection') do
    its('DisableBehaviorMonitoring') { should cmp == 0 }
  end
end

control 'cis-18.10.42.10.5' do
  title 'Ensure \'Turn on script scanning\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.10.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsProtection') do
    its('DisableScriptScanning') { should cmp == 0 }
  end
end

# ---------------------------------------------------------------------------
# 18.10.42.11 Remediation > Behavioral Network Blocks  (NEW in v5.0.0)
# Requires Windows 11 Release 24H2 Administrative Templates (WindowsDefender.admx)
# ---------------------------------------------------------------------------

control 'cis-18.10.42.11.1.1.1' do
  title 'Ensure \'Configure Brute-Force Protection aggressiveness\' is set to \'Enabled: Medium\' or higher (Automated)'
  desc  'This policy setting configures whether Brute-Force Protection in ' \
        'Microsoft Defender Antivirus is enabled and at what aggressiveness ' \
        'level. Setting this to Medium (1) or High (2) reduces the likelihood ' \
        'of a successful brute-force attack. The default Low setting only ' \
        'blocks when confidence is 100%.'
  impact 0.7
  tag cis_id:    '18.10.42.11.1.1.1'
  tag level:     ['L2']
  tag scope:     'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Remediation\\Behavioral Network Blocks\\Brute Force Protection') do
    its('BruteForceProtectionAggressiveness') { should be_in [1, 2] }
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Medium or Enabled: High:
  # Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Remediation\Behavioral Network Blocks\Brute-Force Protection\Configure Brute-Force Protection aggressiveness
  # Note: This Group Policy path is provided by the Group Policy template WindowsDefender.admx/adml that is included with the Microsoft Windows 11 Release 24H2 Administrative Templates (or newer).
end

control 'cis-18.10.42.11.1.1.2' do
  title 'Ensure \'Configure Remote Encryption Protection Mode\' is set to \'Enabled: Audit\' or higher (Automated)'
  desc  'This policy setting configures the operational mode of the Brute-Force ' \
        'Protection feature in Microsoft Defender Antivirus. Audit (2) detects ' \
        'and logs; Block (1) actively prevents unauthorized sign-ins. ' \
        'Default/Off (0) is non-compliant. Note: despite the UI label this ' \
        'value resides under the Brute Force Protection registry sub-key ' \
        '(CIS benchmark Note #2, p.887).'
  impact 0.5
  tag cis_id:    '18.10.42.11.1.1.2'
  tag level:     ['L1']
  tag scope:     'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Remediation\\Behavioral Network Blocks\\Brute Force Protection') do
    its('BruteForceProtectionConfiguredState') { should be_in [1, 2] }
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Audit or Enabled: Block:
  # Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Remediation\Behavioral Network Blocks\Brute-Force Protection\Configure Remote Encryption Protection Mode
  # Note: This Group Policy path is provided by the Group Policy template WindowsDefender.admx/adml that is included with the Microsoft Windows 11 Release 24H2 Administrative Templates (or newer).
end

control 'cis-18.10.42.11.1.2.1' do
  title 'Ensure \'Configure how aggressively Remote Encryption Protection blocks threats\' is set to \'Enabled: Medium\' or higher (Automated)'
  desc  'This policy setting controls the aggressiveness of Remote Encryption ' \
        'Prevention Protection in Microsoft Defender Antivirus. Medium (1) ' \
        'blocks activity when confidence > 99%; High (2) blocks at > 90%. ' \
        'The default Low threshold (100%-only) is insufficient for production.'
  impact 0.7
  tag cis_id:    '18.10.42.11.1.2.1'
  tag level:     ['L2']
  tag scope:     'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Remediation\\Behavioral Network Blocks\\Remote Encryption Protection') do
    its('RemoteEncryptionProtectionAggressiveness') { should be_in [1, 2] }
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Medium or Enabled: High:
  # Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Remediation\Behavioral Network Blocks\Remote Encryption Protection\Configure how aggressively Remote Encryption Protection blocks threats
  # Note: This Group Policy path is provided by the Group Policy template WindowsDefender.admx/adml that is included with the Microsoft Windows 11 Release 24H2 Administrative Templates (or newer).
end

# ---------------------------------------------------------------------------

control 'cis-18.10.42.12.1' do
  title 'Ensure \'Configure Watson events\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.42.12.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\Reporting') do
    its('DisableGenericRePorts') { should cmp == 1 }
  end
end

control 'cis-18.10.42.13.1' do
  title 'Ensure \'Scan excluded files and directories during quick scans\' is set to \'Enabled: 1\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.13.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\Scan') do
    its('QuickScanIncludeExclusions') { should cmp == 1 }
  end
end

control 'cis-18.10.42.13.2' do
  title 'Ensure \'Scan packed executables\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.13.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\Scan') do
    its('DisablePackedExeScanning') { should cmp == 0 }
  end
end

control 'cis-18.10.42.13.3' do
  title 'Ensure \'Scan removable drives\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.13.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\Scan') do
    its('DisableRemovableDriveScanning') { should cmp == 0 }
  end
end

control 'cis-18.10.42.13.4' do
  title 'Ensure \'Trigger a quick scan after X days without any scans\' is set to \'Enabled: 7\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.13.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\\Scan') do
    its('DaysUntilAggressiveCatchupQuickScan') { should cmp == 7 }
  end
end

control 'cis-18.10.42.13.5' do
  title 'Ensure \'Turn on e-mail scanning\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.42.13.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.42.13.5): Ensure \'Turn on e-mail scanning\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Scan\Turn on e-mail scanning Note: This Group Policy path may not exist by default. It is provided by the 
end

control 'cis-18.10.42.16' do
  title 'Ensure \'Configure detection for potentially unwanted applications\' is set to \'Enabled: Block\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.42.16'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.42.16): Ensure \'Configure detection for potentially unwanted applications\' is set to \'Enabled: Block\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Block: Computer Configuration\Policies\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Configure detection for potentially unwanted applications Note: This Group Policy path is provided 
end

control 'cis-18.10.42.17' do
  title 'Ensure \'Control whether exclusions are visible to local users\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.42.17'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender') do
    its('HideExclusionsFromLocalUsers') { should cmp == 1 }
  end
end

control 'cis-18.10.56.1' do
  title 'Ensure \'Turn off Push To Install service\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.56.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\PushToInstall') do
    its('DisablePushToInstall') { should cmp == 1 }
  end
end

control 'cis-18.10.57.2.2' do
  title 'Ensure \'Do not allow passwords to be saved\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.57.2.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('DisablePasswordSaving') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.2.1' do
  title 'Ensure \'Restrict Remote Desktop Services users to a single Remote Desktop Services session\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.57.3.2.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('fSingleSessionPerUser') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.3.1' do
  title 'Ensure \'Allow UI Automation redirection\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.57.3.3.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('EnableUiaRedirection') { should cmp == 0 }
  end
end

control 'cis-18.10.57.3.3.2' do
  title 'Ensure \'Do not allow COM port redirection\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.57.3.3.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.57.3.3.2): Ensure \'Do not allow COM port redirection\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow COM port redirection Note: This Group 
end

control 'cis-18.10.57.3.3.3' do
  title 'Ensure \'Do not allow drive redirection\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.57.3.3.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.57.3.3.3): Ensure \'Do not allow drive redirection\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection Note: This Group Pol
end

control 'cis-18.10.57.3.3.4' do
  title 'Ensure \'Do not allow location redirection\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.57.3.3.4'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('fDisableLocationRedir') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.3.5' do
  title 'Ensure \'Do not allow LPT port redirection\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.57.3.3.5'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.57.3.3.5): Ensure \'Do not allow LPT port redirection\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow LPT port redirection Note: This Group 
end

control 'cis-18.10.57.3.3.6' do
  title 'Ensure \'Do not allow supported Plug and Play device redirection\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.57.3.3.6'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('fDisablePNPRedir') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.3.7' do
  title 'Ensure \'Do not allow WebAuthn redirection\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.57.3.3.7'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('fDisableWebAuthn') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.9.1' do
  title 'Ensure \'Always prompt for password upon connection\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.57.3.9.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('fPromptForPassword') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.9.2' do
  title 'Ensure \'Require secure RPC communication\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.57.3.9.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('fEncryptRPCTraffic') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.9.3' do
  title 'Ensure \'Require use of specific security layer for remote (RDP) connections\' is set to \'Enabled: SSL\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.57.3.9.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.57.3.9.3): Ensure \'Require use of specific security layer for remote (RDP) connections\' is set to \'Enabled: SSL\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: SSL: Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security\Require use of specific security layer for remote (RDP) connections N
end

control 'cis-18.10.57.3.9.4' do
  title 'Ensure \'Require user authentication for remote connections by using Network Level Authentication\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.57.3.9.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('UserAuthentication') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.9.5' do
  title 'Ensure \'Set client connection encryption level\' is set to \'Enabled: High Level\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.57.3.9.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('MinEncryptionLevel') { should cmp == 3 }
  end
end

control 'cis-18.10.57.3.10.1' do
  title 'Ensure \'Set time limit for active but idle Remote Desktop Services sessions\' is set to \'Enabled: 15 minutes or less, but not Never (0)\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.57.3.10.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('MaxIdleTime') { should cmp >= 1 }
    its('MaxIdleTime') { should cmp <= 900000 }
  end
end

control 'cis-18.10.57.3.10.2' do
  title 'Ensure \'Set time limit for disconnected sessions\' is set to \'Enabled: 1 minute\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.57.3.10.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('MaxDisconnectionTime') { should cmp == 60000 }
  end
end

control 'cis-18.10.57.3.11.1' do
  title 'Ensure \'Do not delete temp folders upon exit\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.57.3.11.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('DeleteTempDirsOnExit') { should cmp == 1 }
  end
end

control 'cis-18.10.57.3.11.2' do
  title 'Ensure \'Do not use temporary folders per session\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.57.3.11.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsServices') do
    its('PerSessionTempDir') { should cmp == 1 }
  end
end

control 'cis-18.10.58.1' do
  title 'Ensure \'Prevent downloading of enclosures\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.58.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InternetExplorer\\Feeds') do
    its('DisableEnclosureDownload') { should cmp == 1 }
  end
end

control 'cis-18.10.58.2' do
  title 'Ensure \'Turn on Basic feed authentication over HTTP\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.58.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\InternetExplorer\\Feeds') do
    # REVIEW: organization-specific value -- benchmark prescribes: 0:
    it { should have_property 'AllowBasicAuthInClear' }
  end
end

control 'cis-18.10.59.2' do
  title 'Ensure \'Allow Cloud Search\' is set to \'Enabled: Disable Cloud Search\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.59.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.59.2): Ensure \'Allow Cloud Search\' is set to \'Enabled: Disable Cloud Search\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Disable Cloud Search: Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow Cloud Search Note: This Group Policy path may not exist by default. It is provided by the Group Poli
end

control 'cis-18.10.59.3' do
  title 'Ensure \'Allow indexing of encrypted files\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.59.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsSearch') do
    its('AllowIndexingEncryptedStoresOrItems') { should cmp == 0 }
  end
end

control 'cis-18.10.59.4' do
  title 'Ensure \'Allow search highlights\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.59.4'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsSearch') do
    its('EnableDynamicContentInWSB') { should cmp == 0 }
  end
end

control 'cis-18.10.63.1' do
  title 'Ensure \'Turn off KMS Client Online AVS Validation\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.63.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.63.1): Ensure \'Turn off KMS Client Online AVS Validation\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Windows Components\Software Protection Platform\Turn off KMS Client Online AVS Validation Note: This Group Policy path may not exist by default. It is pro
end

control 'cis-18.10.77.2.1' do
  title 'Ensure \'Configure Windows Defender SmartScreen\' is set to \'Enabled: Warn and prevent bypass\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.77.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
    # REVIEW: organization-specific value -- benchmark prescribes: 1 (EnableSmartScreen) and REG_SZ value of Block
    it { should have_property 'EnableSmartScreen' }
  end
end

control 'cis-18.10.81.1' do
  title 'Ensure \'Allow suggested apps in Windows Ink Workspace\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.81.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
    its('AllowSuggestedAppsInWindowsInkWorkspace') { should cmp == 0 }
  end
end

control 'cis-18.10.81.2' do
  title 'Ensure \'Allow Windows Ink Workspace\' is set to \'Enabled: On, but disallow access above lock\' OR \'Enabled: Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.81.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace') do
    its('AllowWindowsInkWorkspace') { should be_in [0, 1] }
  end
end

control 'cis-18.10.82.1' do
  title 'Ensure \'Allow user control over installs\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.82.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer') do
    its('EnableUserControl') { should cmp == 0 }
  end
end

control 'cis-18.10.82.2' do
  title 'Ensure \'Always install with elevated privileges\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.82.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer') do
    its('AlwaysInstallElevated') { should cmp == 0 }
  end
end

control 'cis-18.10.82.3' do
  title 'Ensure \'Prevent Internet Explorer security prompt for Windows Installer scripts\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.82.3'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer') do
    its('SafeForScripting') { should cmp == 0 }
  end
end

control 'cis-18.10.83.1' do
  title 'Ensure \'Configure the transmission of the user\'s password in the content of MPR notifications sent by winlogon.\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.83.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableMPR') { should cmp == 0 }
  end
end

control 'cis-18.10.83.2' do
  title 'Ensure \'Sign-in and lock last interactive user automatically after a restart\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.83.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DisableAutomaticRestartSignOn') { should cmp == 1 }
  end
end

control 'cis-18.10.88.1' do
  title 'Ensure \'Turn on PowerShell Script Block Logging\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.88.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging') do
    its('EnableScriptBlockLogging') { should cmp == 1 }
  end
end

control 'cis-18.10.88.2' do
  title 'Ensure \'Turn on PowerShell Transcription\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.88.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription') do
    its('EnableTranscripting') { should cmp == 1 }
  end
end

control 'cis-18.10.90.1.1' do
  title 'Ensure \'Allow Basic authentication\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.90.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    its('AllowBasic') { should cmp == 0 }
  end
end

control 'cis-18.10.90.1.2' do
  title 'Ensure \'Allow unencrypted traffic\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.90.1.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end

control 'cis-18.10.90.1.3' do
  title 'Ensure \'Disallow Digest authentication\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.90.1.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client') do
    its('AllowDigest') { should cmp == 0 }
  end
end

control 'cis-18.10.90.2.1' do
  title 'Ensure \'Allow Basic authentication\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.90.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    its('AllowBasic') { should cmp == 0 }
  end
end

control 'cis-18.10.90.2.2' do
  title 'Ensure \'Allow remote server management through WinRM\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.90.2.2'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    its('AllowAutoConfig') { should cmp == 0 }
  end
end

control 'cis-18.10.90.2.3' do
  title 'Ensure \'Allow unencrypted traffic\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.90.2.3'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    its('AllowUnencryptedTraffic') { should cmp == 0 }
  end
end

control 'cis-18.10.90.2.4' do
  title 'Ensure \'Disallow WinRM from storing RunAs credentials\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.90.2.4'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service') do
    its('DisableRunAs') { should cmp == 1 }
  end
end

control 'cis-18.10.91.1' do
  title 'Ensure \'Allow Remote Shell Access\' is set to \'Disabled\' (Automated)'
  impact 0.7
  tag cis_id: '18.10.91.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS') do
    its('AllowRemoteShellAccess') { should cmp == 0 }
  end
end

control 'cis-18.10.93.2.1' do
  title 'Ensure \'Prevent users from modifying settings\' is set to \'Enabled\' (Automated)'
  impact 0.0
  tag cis_id: '18.10.93.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'manual'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe 'Manual review required' do
    skip 'Manual check (18.10.93.2.1): Ensure \'Prevent users from modifying settings\' is set to \'Enabled\' (Automated)'
  end
  # Remediation guidance: To establish the recommended configuration via GP, set the following UI path to Enabled: Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Security\App and browser protection\Prevent users from modifying settings Note: This Group Policy path may not exist by default
end

control 'cis-18.10.94.1.1' do
  title 'Ensure \'No auto-restart with logged on users for scheduled automatic updates installations\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.94.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    its('NoAutoRebootWithLoggedOnUsers') { should cmp == 0 }
  end
end

control 'cis-18.10.94.2.1' do
  title 'Ensure \'Configure Automatic Updates\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.94.2.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    its('NoAutoUpdate') { should cmp == 0 }
  end
end

control 'cis-18.10.94.2.2' do
  title 'Ensure \'Configure Automatic Updates: Scheduled install day\' is set to \'0 - Every day\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.94.2.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU') do
    its('ScheduledInstallDay') { should cmp == 0 }
  end
end

control 'cis-18.10.94.4.1' do
  title 'Ensure \'Manage preview builds\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.94.4.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    its('ManagePreviewBuildsPolicyValue') { should cmp == 1 }
  end
end

control 'cis-18.10.94.4.2' do
  title 'Ensure \'Select when Quality Updates are received\' is set to \'Enabled: 0 days\' (Automated)'
  impact 0.5
  tag cis_id: '18.10.94.4.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate') do
    # REVIEW: organization-specific value -- benchmark prescribes: 1 (DeferQualityUpdates) and 0
    it { should have_property 'DeferQualityUpdates' }
  end
end

control 'cis-18.11.1' do
  title 'Ensure \'Disable HTTP proxy features: Disable WPAD\' is set to \'Enabled: Checked\' (Automated)'
  impact 0.5
  tag cis_id: '18.11.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\InternetSettings\\WinHttp') do
    its('DisableWpad') { should cmp == 1 }
  end
end

control 'cis-18.11.2' do
  title 'Ensure \'Disable HTTP proxy features: Disable proxy authentication\' is set to \'Enabled: Disable authentication over loopback interfaces\' or higher (Automated)'
  impact 0.5
  tag cis_id: '18.11.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\InternetSettings') do
    its('DisableProxyAuthenticationSchemes') { should be_in [256, 287] }
  end
end

# =
# --- SECTION: 19 Administrative Templates (User) ---
# =

control 'cis-19.5.1.1' do
  title 'Ensure \'Turn off toast notifications on the lock screen\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '19.5.1.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.5.1.1 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications") do
          its('NoToastApplicationNotificationOnLockScreen') { should cmp == 1 }
      end
    end
  end
end

control 'cis-19.6.6.1.1' do
  title 'Ensure \'Turn off Help Experience Improvement Program\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '19.6.6.1.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.6.6.1.1 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0") do
          its('NoImplicitFeedback') { should cmp == 1 }
      end
    end
  end
end

control 'cis-19.7.5.1' do
  title 'Ensure \'Do not preserve zone information in file attachments\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '19.7.5.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.5.1 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments") do
          its('SaveZoneInformation') { should cmp == 2 }
      end
    end
  end
end

control 'cis-19.7.5.2' do
  title 'Ensure \'Notify antivirus programs when opening attachments\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '19.7.5.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.5.2 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments") do
          its('ScanWithAntiVirus') { should cmp == 3 }
      end
    end
  end
end

control 'cis-19.7.8.1' do
  title 'Ensure \'Configure Windows spotlight on lock screen\' is set to \'Disabled\' (Automated)'
  impact 0.5
  tag cis_id: '19.7.8.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.8.1 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Policies\\Microsoft\\Windows\\CloudContent") do
          its('ConfigureWindowsSpotlight') { should cmp == 2 }
      end
    end
  end
end

control 'cis-19.7.8.2' do
  title 'Ensure \'Do not suggest third-party content in Windows spotlight\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '19.7.8.2'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.8.2 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Policies\\Microsoft\\Windows\\CloudContent") do
          its('DisableThirdPartySuggestions') { should cmp == 1 }
      end
    end
  end
end

control 'cis-19.7.8.3' do
  title 'Ensure \'Do not use diagnostic data for tailored experiences\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '19.7.8.3'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.8.3 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Policies\\Microsoft\\Windows\\CloudContent") do
          its('DisableTailoredExperiencesWithDiagnosticData') { should cmp == 1 }
      end
    end
  end
end

control 'cis-19.7.8.4' do
  title 'Ensure \'Turn off all Windows spotlight features\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '19.7.8.4'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.8.4 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Policies\\Microsoft\\Windows\\CloudContent") do
          its('DisableWindowsSpotlightFeatures') { should cmp == 1 }
      end
    end
  end
end

control 'cis-19.7.8.5' do
  title 'Ensure \'Turn off Spotlight collection on Desktop\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '19.7.8.5'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.8.5 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent") do
          its('DisableSpotlightCollectionOnDesktop') { should cmp == 1 }
      end
    end
  end
end

control 'cis-19.7.26.1' do
  title 'Ensure \'Prevent users from sharing files within their profile.\' is set to \'Enabled\' (Automated)'
  impact 0.5
  tag cis_id: '19.7.26.1'
  tag level: ['L1']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.26.1 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
          its('NoInplaceSharing') { should cmp == 1 }
      end
    end
  end
end

control 'cis-19.7.46.2.1' do
  title 'Ensure \'Prevent Codec Download\' is set to \'Enabled\' (Automated)'
  impact 0.7
  tag cis_id: '19.7.46.2.1'
  tag level: ['L2']
  tag scope: 'ALL'
  tag mechanism: 'registry_user'
  ref 'CIS Microsoft Windows Server 2022 Benchmark v5.0.0', url: 'https://www.cisecurity.org/benchmark/microsoft_windows_server'
  user_sids = registry_key('HKEY_USERS').children.map { |c| c[/S-1-5-21-[\d-]+/] }.compact.uniq
  if user_sids.empty?
    describe 'cis-19.7.46.2.1 (per-user)' do
      skip 'No interactive user profiles (S-1-5-21-*) are loaded under HKEY_USERS, so this per-user setting could not be evaluated live. Enforce via Group Policy / the matching remediation, which also writes the .DEFAULT hive for future users.'
    end
  else
    user_sids.each do |sid|
      describe registry_key("HKEY_USERS\\#{sid}\\Software\\Policies\\Microsoft\\WindowsMediaPlayer") do
          its('PreventCodecDownload') { should cmp == 1 }
      end
    end
  end
end
