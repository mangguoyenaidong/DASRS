param(
    [string]$Target = "127.0.0.1",
    [int]$Port = 80,
    [string]$Path = "/",
    [int]$Repeat = 3,
    [int]$DelayMs = 800
)

$baseUrl = "http://$Target`:$Port$Path"
$payloads = @(
    "?cmd=cat+/etc/passwd",
    "?q=union+select+1,2,3",
    "?file=../../../../etc/passwd"
)

Write-Host "DASRS demo traffic sender"
Write-Host "Target: $baseUrl"
Write-Host "Repeat: $Repeat"
Write-Host ""

for ($i = 0; $i -lt $Repeat; $i++) {
    foreach ($suffix in $payloads) {
        $url = "$baseUrl$suffix"
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] GET $url"
        try {
            $response = Invoke-WebRequest -Uri $url -Method GET -TimeoutSec 5 -UseBasicParsing
            Write-Host "  -> HTTP $($response.StatusCode)"
        } catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                Write-Host "  -> HTTP $([int]$_.Exception.Response.StatusCode.value__)"
            } else {
                Write-Host "  -> Request failed: $($_.Exception.Message)"
            }
        }
        Start-Sleep -Milliseconds $DelayMs
    }
}

Write-Host ""
Write-Host "Done. Now check:"
Write-Host "1. Suricata eve.json"
Write-Host "2. DASRS alert list"
Write-Host "3. Alert audit modal for Traffic Context and AI analysis"

