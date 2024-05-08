
$sourcePC = "K-31152"
# Creating filter criteria for events
$filterHash = @{LogName = "Security"; Id = 4625; StartTime = (Get-Date).AddDays(-1)}

# Getting lockout events from the source computer
$lockoutEvents = Get-WinEvent -ComputerName $sourcePC -FilterHashTable $filterHash -MaxEvents 1 -ErrorAction 0

# Building output based on advanced properties
$lockoutEvents | Select @{Name = "LockedUserName"; Expression = {$_.Properties[5].Value}}, `
                        @{Name = "LogonType"; Expression = {$_.Properties[10].Value}}, `
                        @{Name = "LogonProcessName"; Expression = {$_.Properties[11].Value}}, `
                        @{Name = "ProcessName"; Expression = {$_.Properties[18].Value}}