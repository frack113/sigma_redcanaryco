write-host "  _________________________  " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host " )) Frack113 tests script (( " -ForegroundColor red
write-host "((                         ))" -ForegroundColor red
write-host "  -------------------------  " -ForegroundColor red
write-host " for the best of my knowledge "

write-host "Import module"
Import-Module .\Export-WinEvents
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psm1

write-host " Open csv"
$csv = Import-Csv -Path .\Full_tests.csv -Delimiter ';'

$list_channel = ('Application','Security','System','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')

foreach ($info in $csv)
{
	$technique = $info.technique
	$nmr = $info.nmr_test
	$valid = $info.sigma
	$name =  $info.name
	if ($info.os -like '*windows*'){
        if ($info.executor -ne 'manual'){ 
		    if ($valid -eq 'False') {
			    write-host "Test $name - $technique test : $nmr" 
			    write-host "Disable Realtime Monitoring" 
			    Set-MpPreference -DisableRealtimeMonitoring 1
			    write-host "Make environnement" 
			    Invoke-AtomicTest $technique -TestNumbers $nmr -Cleanup -NoExecutionLog 
			    Invoke-AtomicTest $technique -TestNumbers $nmr -GetPrereqs -TimeoutSeconds 120 -NoExecutionLog
			    $list_channel | Clear-WinEvents -Verbose
			    Start-Sleep -s 10

			    write-host "Start Aurora" 
			    Start-Process C:\aurora\aurora-agent-64.exe -WorkingDirectory C:\aurora -ArgumentList "-c agent-config-standard.yml","--minimum-level low","--json","-l c:\Tests\$($technique)_test_$($nmr)_aurora.json"
			    Start-Sleep -s 30

			    write-host "Start test" 
			    Invoke-AtomicTest $technique -TestNumbers $nmr -TimeoutSeconds 120 -NoExecutionLog
			    Start-Sleep -s 10

			    write-host "Stop Aurora" 
			    Stop-Process -name aurora-agent-64

			    Start-Sleep -s 10
			    foreach ($channel in $list_channel){
                        $name = $channel.replace("/","_")
				Export-WinEvents -TimeBucket 'Last 5 Minutes' -OutputPath "c:\Tests\$($technique)_test_$($nmr)_channel_$name.json" -Channel $channel
 			    }
		
			    write-host "Cleanup" 
			    Invoke-AtomicTest $technique -TestNumbers $nmr -Cleanup -NoExecutionLog
			    Start-Sleep -s 10

		    } Else { write-host "$name / $technique test: $nmr / OK" -ForegroundColor green }
		} Else { write-host "$name / $technique test: $nmr / manual test :)" -ForegroundColor DarkRed }
	} Else { write-host "$name / $technique test: $nmr / not windows :)" -ForegroundColor DarkRed }
}
write-host "Good Hunt..." -ForegroundColor green