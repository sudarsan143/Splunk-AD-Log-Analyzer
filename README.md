# 🛡️ Splunk AD Log Analyzer  

A complete cybersecurity SIEM project focused on analyzing **Windows Active Directory Security Logs** (Event ID 4624 & 4625) to detect brute-force attacks, password spray attempts, lateral movement, and abnormal authentication patterns inside an enterprise environment.

This lab uses Splunk to ingest, analyze, visualize, and investigate AD authentication logs generated from real-world-like datasets. 

---

## 🎯 Objective  
To build a **Splunk-based analysis workflow** that helps in understanding normal vs suspicious AD authentication behavior and possible brute-force attempts.

---

## 🧩 Lab Setup  
- **Tool:** Splunk cloud  
- **Dataset:** `AD_LOGS`  
- **Sourcetype:** `syslog`  

---

## ⚙️ Task 1: Searching AD Events  

### 🕵️ Retrieve all AD logs  
```spl
index=ad_logs
| stats count by EventID Outcome AccountName
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

<img width="1920" height="1020" alt="Screenshot 2025-11-02 190203" src="https://github.com/user-attachments/assets/ba81c651-1472-4ff1-bab6-bfa8367c4f7d" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 191955" src="https://github.com/user-attachments/assets/e216212d-a081-4452-9430-6ce938701d9e" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192012" src="https://github.com/user-attachments/assets/639649db-6170-4c6a-a507-e6066b167975" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192335" src="https://github.com/user-attachments/assets/347b8921-b440-4ccc-8ddb-99fb863bb3fb" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192437" src="https://github.com/user-attachments/assets/046b42c0-652b-4614-8f7d-2fbe40ce447d" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192537" src="https://github.com/user-attachments/assets/2ec40af9-2604-4711-a342-5da6e8812c94" />
<img width="1920" height="1020" alt="Screenshot 2025-11-02 192757" src="https://github.com/user-attachments/assets/8c0f1c1c-95e3-4ffa-8770-90c65a27e481" />


---

## 🙌 Acknowledgment  
Special thanks to [Rajneesh Gupta](https://github.com/0xrajneesh/) for the dataset and guidance.

---

## 🏁 Conclusion  
This project helped me:  
- Explore SSH monitoring through Splunk  
- Detect anomalies and failed login spikes  
- Investigate attacker IPs and visualize trends  

---

## 🔖 Tags  
`#Splunk` `#CyberSecurity` `#SOC` `#SIEM` `#SSHLogs` `#ThreatDetection` `#BlueTeam` `#HandsOnLearning`
