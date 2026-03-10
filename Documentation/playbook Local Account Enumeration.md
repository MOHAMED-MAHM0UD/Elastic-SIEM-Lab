```
┌───────────────────────────────────────────┐
│         START: ALERT TRIGGERED            │
│   "Local Account Enumeration Detected"    │
└───────────────────────────────────────────┘
                     │
                     ▼
─────────────────────────────────────────────
1. RETRIEVE ALERT DETAILS
─────────────────────────────────────────────
• Process name  
• Command line  
• User performing action  
• Hostname  
• Parent process  
• Logon type (local/remote)

                     │
                     ▼
─────────────────────────────────────────────
2. VALIDATE ENUMERATION
─────────────────────────────────────────────
Check if actual enumeration commands ran:

• `net user`, `net localgroup`  
• `Get-LocalUser`, `Get-LocalGroupMember`  
• `wmic useraccount`  
• Recon tools (e.g., Seatbelt)

Is the activity real?
YES → Continue  
NO → Close alert

                     │
                     ▼
─────────────────────────────────────────────
3. IDENTIFY WHO RAN IT
─────────────────────────────────────────────
Evaluate:

• Admin or normal user?  
• Business task or unusual?  
• Remote login?  
• After-hours?

Is the user authorized?
YES → Continue  
NO → Mark as Suspicious

                     │
                     ▼
─────────────────────────────────────────────
4. CHECK FOR SUSPICIOUS INDICATORS
─────────────────────────────────────────────
Look for:

• Enumeration from non-admin user  
• Executed from odd process (Office, temp folder)  
• Multiple recon commands  
• Enumeration after remote access  
• High-value system (DC, server)

Any suspicious indicators?
YES → High suspicion  
NO → Continue

                     │
                     ▼
─────────────────────────────────────────────
5. SEARCH FOR FOLLOW-UP ACTIVITY (±1 Hour)
─────────────────────────────────────────────
Look for:

• Failed login attempts  
• Privilege escalation  
• New admin account creation  
• Lateral movement  
• LSASS access

Signs of malicious behavior?
YES → Treat as malicious  
NO → Continue

                     │
                     ▼
─────────────────────────────────────────────
6. FINAL CLASSIFICATION
─────────────────────────────────────────────
Decide:

• BENIGN → Expected admin activity  
• MALICIOUS → Recon phase of attack

                     │
                     ▼
─────────────────────────────────────────────
7A. RESPONSE: BENIGN
─────────────────────────────────────────────
• Confirm with IT  
• Document case  
• Close alert

─────────────────────────────────────────────
7B. RESPONSE: MALICIOUS
─────────────────────────────────────────────
• Disable account if needed  
• Contain host  
• Collect logs (EDR, Sysmon, Security logs)  
• Check other hosts for same activity  
• Remediate (patch, remove tools, reset passwords)

                     │
                     ▼
		┌─────────────────────────────┐
		│        CASE CLOSED          │
		└─────────────────────────────┘

```