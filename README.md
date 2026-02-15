
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/NormanRomney/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "Rep369" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-02-14T16:10:49.9902132Z`. These events began at `2026-02-14T15:34:16.297653Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "sales-center-1"
| where InitiatingProcessAccountName == "rep369"
| where FileName contains "tor"
| where Timestamp >= datetime(2/14/2026, 3:34:16.297 PM)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1285" height="535" alt="Screenshot 2026-02-14 at 8 36 45 PM" src="https://github.com/user-attachments/assets/ae828755-86f5-4204-a6e6-f43821fa2238" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.5.exe". Based on the logs returned, at `2026-02-14T15:40:38.8234812Z`, an employee on the "sales-center-1" device ran the file `tor-browser-windows-x86_64-portable-15.0.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "sales-center-1"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe"
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1380" height="342" alt="Screenshot 2026-02-14 at 8 45 11 PM" src="https://github.com/user-attachments/assets/41c57dd9-2a12-4c03-b4ae-f5a37cbf100a" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-02-14T15:41:17.0149666Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sales-center-1"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1491" height="508" alt="Screenshot 2026-02-14 at 8 51 21 PM" src="https://github.com/user-attachments/assets/305753fe-4338-46cd-8a74-81aebe8bf89a" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-02-14T15:41:31.7268198Z`, an employee on the "sales-center-1" device successfully established a connection to the remote IP address `83.148.245.77` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\rep369\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `9150`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "sales-center-1"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001",  "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
<img width="1383" height="470" alt="Screenshot 2026-02-14 at 9 03 23 PM" src="https://github.com/user-attachments/assets/ce3da821-7b7a-4f85-aa9b-824a804934ed" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-14T15:34:16.297653Z`
- **Event:** The user "rep369" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Rep369\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-14T15:40:38.8234812Z`
- **Event:** The user "rep369" executed the file `tor-browser-windows-x86_64-portable-15.0.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
- **File Path:** `C:\Users\Rep369\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-14T15:41:17.0149666Z`
- **Event:** User "rep369" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Rep369\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-14T15:41:31.7268198Z`
- **Event:** A network connection to IP `83.148.245.77` on port `9001` by user "rep369" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\rep369\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-14T15:41:51.0453209Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "rep369" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
