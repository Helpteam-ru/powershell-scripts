# Getting the PDC emulator DC
$pdc = (Get-ADDomain).PDCEmulator

# Creating filter criteria for events
$filterHash = @{LogName = "Security"; Id = 4740; StartTime = (Get-Date).AddDays(-1)}

# Getting lockout events from the PDC emulator
$lockoutEvents = Get-WinEvent -ComputerName $pdc -FilterHashTable $filterHash -ErrorAction SilentlyContinue

# Building output based on advanced properties
$lockoutEvents | Select @{Name = "LockedUser"; Expression = {$_.Properties[0].Value}}, `
                        @{Name = "SourceComputer"; Expression = {$_.Properties[1].Value}}, `
                        @{Name = "DomainController"; Expression = {$_.Properties[4].Value}}, TimeCreated