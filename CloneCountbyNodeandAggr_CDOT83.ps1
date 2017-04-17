Import-Module Graphite-Powershell
Import-Module DataONTAP
$password = ConvertTo-SecureString "netapp123" -AsPlainText -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "wfa",$password
connect-nccontroller trcl1va2cm.mhint -Credential $cred
$global:CurrentNcController.TimeoutMsec = 7200000

Add-Type -TypeDefinition @"
	public enum Syslog_Facility
	{
		kern,
		user,
		mail,
		daemon,
		auth,
		syslog,
		lpr,
		news,
		uucp,
		clock,
		authpriv,
		ftp,
		ntp,
		logaudit,
		logalert,
		cron, 
		local0,
		local1,
		local2,
		local3,
		local4,
		local5,
		local6,
		local7,
	}
"@

Add-Type -TypeDefinition @"
	public enum Syslog_Severity
	{
		Emergency,
		Alert,
		Critical,
		Error,
		Warning,
		Notice,
		Informational,
		Debug
	}
"@

function Send-SyslogMessage
{
<#
.SYNOPSIS
Sends a SYSLOG message to a server running the SYSLOG daemon

.DESCRIPTION
Sends a message to a SYSLOG server as defined in RFC 5424. A SYSLOG message contains not only raw message text,
but also a severity level and application/system within the host that has generated the message.

.PARAMETER Server
Destination SYSLOG server that message is to be sent to

.PARAMETER Message
Our message

.PARAMETER Severity
Severity level as defined in SYSLOG specification, must be of ENUM type Syslog_Severity

.PARAMETER Facility
Facility of message as defined in SYSLOG specification, must be of ENUM type Syslog_Facility

.PARAMETER Hostname
Hostname of machine the mssage is about, if not specified, local hostname will be used

.PARAMETER Timestamp
Timestamp, myst be of format, "yyyy:MM:dd:-HH:mm:ss zzz", if not specified, current date & time will be used

.PARAMETER UDPPort
SYSLOG UDP port to send message to

.INPUTS
Nothing can be piped directly into this function

.OUTPUTS
Nothing is output

.EXAMPLE
Send-SyslogMessage mySyslogserver "The server is down!" Emergency Mail
Sends a syslog message to mysyslogserver, saying "server is down", severity emergency and facility is mail

.NOTES
NAME: Send-SyslogMessage

#>
[CMDLetBinding()]
Param
(
	[Parameter(mandatory=$true)] [String] $Server,
	[Parameter(mandatory=$true)] [String] $Message,
	[Parameter(mandatory=$true)] [Syslog_Severity] $Severity,
	[Parameter(mandatory=$true)] [Syslog_Facility] $Facility,
	[String] $Hostname,
	[String] $Timestamp,
	[int] $UDPPort = 514
)

# Create a UDP Client Object
$UDPCLient = New-Object System.Net.Sockets.UdpClient
$UDPCLient.Connect($Server, $UDPPort)

# Evaluate the facility and severity based on the enum types
$Facility_Number = $Facility.value__
$Severity_Number = $Severity.value__
Write-Verbose "Syslog Facility, $Facility_Number, Severity is $Severity_Number"

# Calculate the priority
$Priority = ($Facility_Number * 8) + $Severity_Number
Write-Verbose "Priority is $Priority"

# If no hostname parameter specified, then set it
if (($Hostname -eq "") -or ($Hostname -eq $null))
{
	$Hostname = Hostname
}

# I the hostname hasn't been specified, then we will use the current date and time
if (($Timestamp -eq "") -or ($Timestamp -eq $null))
{
	$Timestamp = Get-Date -Format "MMM dd hh:mm:ss"
}

# Assemble the full syslog formatted message
$FullSyslogMessage = "<{0}>{1} {2}" -f $Priority, $Timestamp, $Message

# create an ASCII Encoding object
$Encoding = [System.Text.Encoding]::ASCII

# Convert into byte array representation
$ByteSyslogMessage = $Encoding.GetBytes($FullSyslogMessage)

# If the message is too long, shorten it
if ($ByteSyslogMessage.Length -gt 1024)
{
    $ByteSyslogMessage = $ByteSyslogMessage.SubString(0, 1024)
}

# Send the Message
$UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length)

}

$ClusterName = Get-NcCluster
$ActualClusterName = $ClusterName.ClusterName


Send-SyslogMessage fgprd-oncommand-elasticlog-app001.mhint "[$ActualClusterName-1a:clone.Count:info]: Starting clone count collection!" Informational syslog


$volumes = Get-NcVol  | ?{ $_.VolumeCloneAttributes.CloneChildCountSpecified -eq $true} 

        foreach($vol in $volumes)
          {
                    $Cluster = $clustername.ClusterName  
                    $Node = $vol.VolumeIdAttributes.Node
                    $Volume = $vol.Name
                    $Aggr = $vol.Aggregate
                    $Clonecount = $vol.VolumeCloneAttributes.CloneChildCount                                
                    Send-GraphiteMetric -CarbonServer '10.10.0.168' -CarbonServerPort 2003 -MetricPath  "Clones.VA2.$Cluster.Node.$Node.Aggr.$Aggr.$Volume.count" -MetricValue $Clonecount -DateTime (get-date)
                                     
  }
Send-SyslogMessage fgprd-oncommand-elasticlog-app001.mhint "[$ActualClusterName-1a:clone.Count:info]: Stopping clone count collection!" Informational syslog