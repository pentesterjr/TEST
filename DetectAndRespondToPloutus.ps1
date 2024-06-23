# Filename: DetectAndRespondToPloutus.ps1

# Define known IoCs for Ploutus ATM Malware
$maliciousProcesses = @("Ploutus.exe", "MaliciousProcessName.exe")
$maliciousFiles = @("C:\Windows\System32\ploutus.dll", "C:\ProgramData\malware.exe")
$maliciousRegistryKeys = @("HKLM:\SOFTWARE\MaliciousKey", "HKCU:\Software\MaliciousKey")

# Function to stop malicious processes
function Stop-MaliciousProcesses {
    foreach ($processName in $maliciousProcesses) {
        try {
            $process = Get-Process -Name $processName -ErrorAction Stop
            Write-Output "Stopping malicious process: $processName"
            Stop-Process -Name $processName -Force
            Log-DetectionResponse "Stopped malicious process: $processName"
        } catch {
            Log-DetectionResponse "Error stopping process $processName: $_"
        }
    }
}

# Function to remove malicious files
function Remove-MaliciousFiles {
    foreach ($filePath in $maliciousFiles) {
        try {
            if (Test-Path $filePath) {
                Write-Output "Removing malicious file: $filePath"
                Remove-Item $filePath -Force
                Log-DetectionResponse "Removed malicious file: $filePath"
            }
        } catch {
            Log-DetectionResponse "Error removing file $filePath: $_"
        }
    }
}

# Function to remove malicious registry keys
function Remove-MaliciousRegistryKeys {
    foreach ($regKey in $maliciousRegistryKeys) {
        try {
            if (Test-Path $regKey) {
                Write-Output "Removing malicious registry key: $regKey"
                Remove-Item $regKey -Recurse -Force
                Log-DetectionResponse "Removed malicious registry key: $regKey"
            }
        } catch {
            Log-DetectionResponse "Error removing registry key $regKey: $_"
        }
    }
}

# Function to log the detection and response actions
function Log-DetectionResponse {
    $logFilePath = "C:\ATM_Security\PloutusDetectionLog.txt"
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $message = $timeStamp + " - " + $args[0]
    Add-Content -Path $logFilePath -Value $message
}

# Function to send notifications (example with email)
function Send-Notification {
    param (
        [string]$subject,
        [string]$body
    )
    # Example email notification (configure SMTP settings as required)
    $smtpServer = "smtp.example.com"
    $smtpFrom = "alert@example.com"
    $smtpTo = "admin@example.com"
    $message = New-Object system.net.mail.mailmessage
    $message.from = $smtpFrom
    $message.To.add($smtpTo)
    $message.Subject = $subject
    $message.Body = $body
    $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
    $smtp.Send($message)
}

# Main function to detect and respond to Ploutus malware
function Detect-And-Respond {
    Write-Output "Starting detection and response for Ploutus ATM Malware"
    Log-DetectionResponse "Starting detection and response for Ploutus ATM Malware"

    # Check for malicious processes
    foreach ($processName in $maliciousProcesses) {
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($process) {
            Log-DetectionResponse "Malicious process detected: $processName"
            Stop-MaliciousProcesses
            Send-Notification "Malicious Process Detected" "Process $processName detected and stopped."
        }
    }

    # Check for malicious files
    foreach ($filePath in $maliciousFiles) {
        if (Test-Path $filePath) {
            Log-DetectionResponse "Malicious file detected: $filePath"
            Remove-MaliciousFiles
            Send-Notification "Malicious File Detected" "File $filePath detected and removed."
        }
    }

    # Check for malicious registry keys
    foreach ($regKey in $maliciousRegistryKeys) {
        if (Test-Path $regKey) {
            Log-DetectionResponse "Malicious registry key detected: $regKey"
            Remove-MaliciousRegistryKeys
            Send-Notification "Malicious Registry Key Detected" "Registry key $regKey detected and removed."
        }
    }

    Write-Output "Detection and response process completed"
    Log-DetectionResponse "Detection and response process completed"
}

# Execute the detection and response function
Detect-And-Respond
