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

## 🖼 Dashboard Screenshots  

<img width="1920" height="1020" alt="Screenshot 2025-11-02 190203" src="https://github.com/user-attachments/assets/ba81c651-1472-4ff1-bab6-bfa8367c4f7d" />


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
