
```
┌───────────────────────────────────────────────────────────────┐
│                     START: ALERT TRIGGERED                    │
│               "User Account Creation" Detected                │
└───────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
────────────────────────────────────────────────────────────────────
                 1. RETRIEVE RAW EVENT DETAILS
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
          ┌──────────────────────────────────────────────┐
          │ Extract key fields:                          │
          │ • New User (Name/SID)                        │
          │ • Creator Account                            │
          │ • Hostname / Role (DC, server, workstation)  │
          │ • Process & Command Line                     │
          │ • Source IP / Logon context                  │
          └──────────────────────────────────────────────┘
                                 │
                                 ▼
────────────────────────────────────────────────────────────────────
                 2. VALIDATE EVENT IS GENUINE
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
         ┌─────────────────────────────────────────────      
         │ Check for:                                        |
         │ • Windows Event ID 4720                           |   
         │ • Elastic EDR telemetry showing account creation  |   
         └─────────────────────────────────────────────      
                                 │
                                 ▼
                          Is Event Valid?
                      ┌───────────────┬───────────────┐
                      │               │               │
                      ▼               │               ▼
                YES (Continue)        │        NO → Close Alert
                                      │        (False trigger)
                                      ▼
────────────────────────────────────────────────────────────────────
                    3. IDENTIFY CREATOR ACCOUNT
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
     ┌──────────────────────────────────────────────────────────┐
     │ Evaluate the creator:                                    │
     │ • Known admin?                                           │
     │ • Automation/service account?                            │
     │ • Logged on locally/remotely?                            │
     │ • After-hours activity?                                  │
     └──────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                      Is Creator Authorized?
                 ┌───────────────┬────────────────┐
                 │               │                │
                 ▼               │                ▼
           YES (Go to Step 4)    │         NO → HIGH SUSPICION
                                 ▼
────────────────────────────────────────────────────────────────────
                3. EVALUATE NEWLY CREATED ACCOUNT
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
     ┌──────────────────────────────────────────────────────────┐
     │ Examine characteristics:                                 │
     │ • Username typical or suspicious?                        │
     │ • Created on sensitive system?                           │
     │ • Created outside business hours?                        │
     │ • Service-style? Hidden-style?                           │
     └──────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                     Any Suspicious Indicators?
              ┌──────────────┬──────────────────────────┐
              │              │                          │
              ▼              │                          ▼
            YES → Flag as Suspicious                    NO
                                 │                      │
                                 ▼                      ▼
────────────────────────────────────────────────────────────────────
           5. CHECK FOR PRIVILEGE ESCALATION (CRITICAL)
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ Search for group modifications:                              │
  │ • 4728 (global group)                                        │
  │ • 4732 (local group)                                         │
  │ • 4756 (universal group)                                     │
  │                                                              │
  │ Focus: Was the new account added to Administrators / Domain  │
  │ Admins / RDP access groups?                                  │
  └──────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                       Privilege Group Add?
               ┌──────────────┬────────────────┐
               │              │                │
               ▼              │                ▼
         YES → CRITICAL       │          NO → Continue
               │              │
               ▼              ▼
────────────────────────────────────────────────────────────────────
       6. CORRELATE NEARBY SUSPICIOUS BEHAVIOR (±1 HOUR)
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
      ┌─────────────────────────────────────────────────────────┐
      │ Check for:                                              │
      │ • Failed logons / brute forcing                         │
      │ • Unexpected remote access                              │
      │ • PowerShell / cmd.exe spawning system changes          │
      │ • Credential theft patterns (LSASS access)              │
      └─────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                       Any Linked Suspicious Activity?
          ┌───────────────────┬────────────────────┐
          │                   │                    │
          ▼                   │                    ▼
    YES → High Likelihood     │             NO → Continue
          of Maliciousness    │
                              ▼
────────────────────────────────────────────────────────────────────
                         7. FINAL CLASSIFICATION
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
       ┌──────────────────────────────────────────────────────────┐
       │ Evaluate outcome based on:                               │
       │ • Creator legitimacy                                     │
       │ • Username analysis                                      │
       │ • Privilege group changes                                │
       │ • Lateral suspicious activity                            │
       │ • Time and host risk                                     │
       └──────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                      ┌──────────────┬──────────────┐
                      │              │              │
                      ▼              │              ▼
              BENIGN ACTIVITY        │        MALICIOUS ACTIVITY
                      │              │              │
────────────────────────────────────────────────────────────────────
                 8A. RESPONSE: BENIGN ACTIVITY
────────────────────────────────────────────────────────────────────
                      │
                      ▼
     ┌──────────────────────────────────────────────────────────┐
     │ • Validate business justification                         │
     │ • Document approval / ticket reference                    │
     │ • Apply rule exceptions if applicable                     │
     │ • Close case                                              │
     └──────────────────────────────────────────────────────────┘

────────────────────────────────────────────────────────────────────
                8B. RESPONSE: MALICIOUS ACTIVITY
────────────────────────────────────────────────────────────────────
                                 │
                                 ▼
     ┌──────────────────────────────────────────────────────────┐
     │ CONTAINMENT:                                              │
     │ • Disable/delete unauthorized account                     │
     │ • Reset creator’s password                                │
     │ • Isolate compromised host(s) if needed                   │
     │                                                           │
     │ EVIDENCE COLLECTION:                                      │
     │ • Security logs,Sysmon logs, network logs , DNS logs      │
     │ • Authentication patterns                                 │
     │ • Persistence mechanisms(Register ,schdeual task,back door│
     │                                                           │
     │ ENVIRONMENT-WIDE ((SCOPING)):                             │
     │ • Search for similar accounts                             │
     │ • Check admin group integrity                             │
     │                                                           │
     │ REMEDIATION:                                              │
     │ • Close unauthorized access paths                         │
     │ • Patch or harden affected systems                        │
     └──────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                          ┌─────────────────┐
                          │   CASE CLOSED   │
                          └─────────────────┘

```