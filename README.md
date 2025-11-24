# 🛡️ Splunk AD Log Analyzer  

A complete cybersecurity SIEM project focused on analyzing **Windows Active Directory Security Logs** (Event ID 4624 & 4625) to detect brute-force attacks, password spray attempts, lateral movement, and abnormal authentication patterns inside an enterprise environment.

This lab uses Splunk to ingest, analyze, visualize, and investigate AD authentication logs generated from real-world-like datasets. 

---

## 🎯 Objective  
To build a **Splunk-based analysis workflow** that helps in understanding normal vs suspicious AD authentication behavior and possible brute-force attempts.

---

## 🧩 Lab Setup  
- **Tool:** Splunk cloud  
- **Dataset:** `AD_logs` 
- **Input:** `Upload CSV`  

---

## ⚙️ Task 1: Searching AD Events  

### 🕵️ Retrieve all AD logs  
```spl
index=ad_logs
| stats count by EventID  AccountName
```

---

## 📊 Task 2: Identify High Volume of Failed Logons  
```spl
source="AD_LOGS.csv" index="main" sourcetype="csv" EventID=4625
| stats count by SourceIP
| where count >= 10
```

---

## ⚠️ Task 3: Investigate Accounts Being Attacked   
```spl
source="AD_LOGS.csv" index="main" sourcetype="csv" EventID=4625 
| stats count by AccountName SourceIP
| sort - count
```

---

## 👨‍💻 Task 4: Examine Status / SubStatus Codes   
```spl
source="AD_LOGS.csv" index="main" sourcetype="csv" EventID=4625 
| stats count by Status SubStatus
| sort -count
```
---

## 👨‍💻 Task 5: Look for Failure → Success pattern   
```spl
source="AD_LOGS.csv" index="main" sourcetype="csv" SourceIP = 10.10.20.55
| streamstats count(eval(EventID=4625)) as failed_attempts by AccountName
| where EventID=4624 AND failed_attempts >= 1
```
---

## 👨‍💻 Task 6: Analyze CallerProcessName    
```spl
source="AD_LOGS.csv" index="main" sourcetype="csv" 
| stats count by AccountName SourceIP CallerProcessName
| sort -count
```
---

## 👨‍💻 Task 7: Check Logon Types 
```spl
source="AD_LOGS.csv" index="main" sourcetype="csv" 
| stats count by AccountName SourceIP LogonType
| sort -count
```
---

## 👨‍💻 Trigger an alert 
### Trigger an alert when the same AccountName generates five or more failed authentication attempts (EventID 4625) within the monitored dataset. This helps identify potential brute-force activity or repeated unauthorized login attempts on a specific user account.
```spl
source="AD_LOGS.csv" index="main" sourcetype="csv" EventID="4625" 
| stats count by AccountName
| where count >= 5
```

---

## 🖼 Dashboard Screenshots  

<img width="1920" height="1020" alt="png" src="https://github.com/sudarsan143/Splunk-AD-Log-Analyzer/blob/352c7e2a8cb32852d2105e677a2f3947e68dead4/Identify%20High%20Volume%20of%20Failed%20Logons.png" />
<img width="1920" height="1020" alt="png" src="https://github.com/sudarsan143/Splunk-AD-Log-Analyzer/blob/ebdb0a0fbb57fd80113ab2cabbd05f7252007d78/Investigate%20Accounts%20Being%20Attacked.png" />
<img width="1920" height="1020" alt="png" src="https://github.com/sudarsan143/Splunk-AD-Log-Analyzer/blob/ebdb0a0fbb57fd80113ab2cabbd05f7252007d78/Examine%20Status%20%20SubStatus%20Codes.png" />
<img width="1920" height="1020" alt="png" src="https://github.com/sudarsan143/Splunk-AD-Log-Analyzer/blob/ebdb0a0fbb57fd80113ab2cabbd05f7252007d78/Look%20for%20Failure%20%E2%86%92%20Success%20pattern.png" />
<img width="1920" height="1020" alt="png" src="https://github.com/sudarsan143/Splunk-AD-Log-Analyzer/blob/ebdb0a0fbb57fd80113ab2cabbd05f7252007d78/Analyze%20CallerProcessName.png" />
<img width="1920" height="1020" alt="png" src="https://github.com/sudarsan143/Splunk-AD-Log-Analyzer/blob/ebdb0a0fbb57fd80113ab2cabbd05f7252007d78/Check%20Logon%20Types.png" />
<img width="1920" height="1020" alt="png" src="https://github.com/sudarsan143/Splunk-AD-Log-Analyzer/blob/ebdb0a0fbb57fd80113ab2cabbd05f7252007d78/Trigger%20an%20alert.png" />


---

---

## 🏁 Conclusion  
This project helped me:  
- Analyze Active Directory authentication logs using Splunk
- Detect brute-force attempts and login anomalies
- Investigate suspicious accounts, IPs, and logon patterns
- Build beginner-friendly SIEM use cases and detection logic
- Strengthen my SOC investigation skills for real-world AD attacks 

---

## 🔖 Tags  
`#Splunk` `#CyberSecurity` `#SOC` `#SIEM` `#ADLogs` `#ThreatDetection` `#BlueTeam` `#HandsOnLearning`
