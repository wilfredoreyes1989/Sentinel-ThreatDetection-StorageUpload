# Sentinel-ThreatDetection-StorageUpload

This project simulates a suspicious file upload to Azure Blob Storage and demonstrates how Microsoft Sentinel can detect and alert on potential threats using KQL-based analytics rules.

---

## Project Goal

Create a realistic scenario where a `.exe` file is uploaded to an Azure Storage container, and Microsoft Sentinel detects the upload using diagnostic logs.

---

## Tools Used

- Azure Blob Storage
- Microsoft Sentinel
- Log Analytics Workspace
- PowerShell (Az module)
- Kusto Query Language (KQL)
- Visual Studio / GitHub

---

## Steps Performed

1. Created a `.exe`-named file called `internal-malware-test.exe`
2. Uploaded the file via PowerShell using authenticated Azure Storage context
3. Configured Microsoft Defender for Storage
4. Connected diagnostic logs to a Log Analytics Workspace
5. Enabled Microsoft Sentinel and linked it to the workspace
6. Built a custom scheduled analytics rule to detect file uploads with `.exe` in the name
7. Queried `StorageBlobLogs` to validate ingestion and detection

---

## Screenshots

| Description                         | File |
|-------------------------------------|------|
| PowerShell file upload confirmation | Images/01_PowerShell_Upload_Success.png |
| Log query result in Sentinel        | Images/02_Sentinel_Log_Query_NoIdentity.png |

---

## KQL Detection Query

Stored in: `KQL/BlobUploadLogQuery.kql`

```kql
StorageBlobLogs
| where OperationName == "PutBlob"
| where Uri contains "internal-malware-test"
| sort by TimeGenerated desc
| project TimeGenerated, Uri, CallerIpAddress, AuthenticationType, StatusCode
