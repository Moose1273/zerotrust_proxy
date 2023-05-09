# ==========================================================================
# GLOBAL VARIABLES
# ==========================================================================
$global:cvssv2_basescore_sum = 0
function Invoke-Vulmap {

    [CmdletBinding()]
    Param(
        [ValidateSet('Default', 'CollectInventory')]
        [string] $Mode = 'Default',
        [switch] $OnlyExploitableVulns,
        [string] $DownloadExploit,
        [switch] $DownloadAllExploits,
        [switch] $SaveInventoryFile,
        [switch] $ReadInventoryFile,
        [string] $InventoryOutFile = 'windows/win_inventory_res.json',
        [string] $InventoryInFile = 'windows/win_inventory_res.json',
        [string] $Proxy
    )

    $ErrorActionPreference = 'Stop'
    $registry_paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    $vulMapScannerUri = 'https://vulmon.com/scannerapi_vv211'
    $exploitDownloadUri = 'https://vulmon.com/downloadexploit?qid='
    $userAgentString = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0'

    $TrustAllCertsPolicyCode = @'
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
                }
        }
'@

    if ($Proxy) {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            Write-Error -Message 'Proxy support is not available for PowerShell Core, please use Windows PowerShell (powershell.exe) instead of PowerShell Core (pwsh.exe) if you need to use a proxy.'
        }
        else {
            # Ignores ssl-errors which is required for proxies:
            Write-Verbose "Loading code to circumvent proxy ssl errors."
            Add-Type -TypeDefinition $TrustAllCertsPolicyCode
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    function Get-ProductList () {
        Write-Verbose "Reading installed software from registry."
        @(
            foreach ($registry_path in $registry_paths) {
                $subkeys = Get-ChildItem -Path $registry_path -ErrorAction SilentlyContinue

                if ($subkeys) {
                    ForEach ($key in $subkeys) {
                        $DisplayName = $key.getValue('DisplayName')

                        if ($null -notlike $DisplayName) {
                            $DisplayVersion = $key.GetValue('DisplayVersion')

                            [PSCustomObject]@{
                                PSTypeName      = 'System.Software.Inventory'
                                DisplayName     = $DisplayName.Trim()
                                DisplayVersion  = $DisplayVersion
                                NameVersionPair = $DisplayName.Trim() + $DisplayVersion
                            }
                        }
                    }
                }
            }
        ) | Sort-Object NameVersionPair -Unique
    }

    function Get-Exploit ($ExploitID) {
        Write-Verbose "Downloading exploit '$ExploitID'."
        $webRequestSplat = @{
            Uri       = $exploitDownloadUri + $ExploitID
            UserAgent = $userAgentString
        }

        if ($Proxy) {
            $webRequestSplat.Proxy = $Proxy
        }

        $request = Invoke-WebRequest @webRequestSplat

        $fileName = ($request.Headers.'Content-Disposition' -split '=')[1].Substring(1)
        $null = New-Item -Path $fileName -ItemType File -Value $request -Force

        Write-Verbose "Saved exploit '$ExploitID' to file '$fileName'."
    }

    function Get-JsonRequestBatches ($inventory) {
        $numberOfBatches = [math]::Ceiling(@($inventory).count / 100)

        for ($i = 0; $i -lt $numberOfBatches; $i++) {
            Write-Verbose "Submitting software to vulmon.com api, batch '$i' of '$numberOfBatches'."
            $productList = $inventory |
                Select-Object -First 100 |
                ForEach-Object {
                    [pscustomobject]@{
                        product = $_.DisplayName
                        version = if ($_.DisplayVersion) { $_.DisplayVersion } else { '' }
                    }
                }

            $inventory = $inventory | Select-Object -Skip 100

            $json_request_data = [ordered]@{
                os           = (Get-CimInstance Win32_OperatingSystem -Verbose:$false).Caption
                product_list = @($productList)
            } | ConvertTo-Json

            $webRequestSplat = @{
                Uri    = $vulMapScannerUri
                Method = 'POST'
                Body   = @{ querydata = $json_request_data }
            }

            if ($Proxy) {
                $webRequestSplat.Proxy = $Proxy
            }

            (Invoke-WebRequest @webRequestSplat).Content | ConvertFrom-Json
        }
    }

    function Resolve-RequestResponses ($responses) {
        $count=0
        $cvssv2_basescore_sum = 0
        foreach ($response in $responses) {
            foreach ($vuln in ($response | Select-Object -ExpandProperty results -ErrorAction SilentlyContinue)) {
                Write-Verbose "Parsing results from vulmon.com api."
                $interests = $vuln |
                    Select-Object -Property query_string -ExpandProperty vulnerabilities |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Product                = $_.query_string
                            'CVE ID'               = $_.cveid
                            'Risk Score'           = $_.cvssv2_basescore
                            'Vulnerability Detail' = $_.url
                            ExploitID              = if ($null -ne $_.exploits) { 'EDB' + ($_.exploits[0].url).Split('{=}')[2] } else { $null }
                            'Exploit Title'        = if ($null -ne $_.exploits) { $_.exploits[0].title } else { $null }
                        }
                        # 评分系统
                        if($_.cvssv2_basescore -gt 7 -and $_.cvssv2_basescore -lt 10){
                            $global:cvssv2_basescore_sum += 4
                        }elseif($_.cvssv2_basescore -gt 4 -and $_.cvssv2_basescore -lt 7){
                            $global:cvssv2_basescore_sum += 3
                        }elseif($_.cvssv2_basescore -gt 2 -and $_.cvssv2_basescore -lt 4){
                            $global:cvssv2_basescore_sum += 2
                        }elseif($_.cvssv2_basescore -gt 0 -and $_.cvssv2_basescore -lt 2 ){
                            $global:cvssv2_basescore_sum += 1
                        }else {
                            $global:cvssv2_basescore_sum += 0
                        }
                        #$global:cvssv2_basescore_sum += $_.cvssv2_basescore
                    }

                if ($OnlyExploitableVulns -Or $DownloadAllExploits) {
                    $interests = $interests | Where-Object { $null -ne $_.exploits }
                }

                $count += $interests.Count
                Write-Verbose "Found '$count' vulnerabilities so far."
                $interests
            }
        }
    }

    function Invoke-VulnerabilityScan ($inventory_json) {
        Write-Host 'Vulnerability scanning started...'
        $inventory = ConvertFrom-Json $inventory_json
        
        # Write-Host $inventory_json

        $responses = Get-JsonRequestBatches $inventory

        # Write-Host $responses

        $vulmon_api_status_message = $responses[-1] | Select-Object -ExpandProperty status_message

        $vuln_list = Resolve-RequestResponses $responses

        if ($DownloadAllExploits) {
            foreach ($exp in $vuln_list) {
                $exploit_id = $exp.ExploitID
                Get-Exploit $exploit_id
            }
        }

        Write-Host "Checked $(@($inventory).count) items" -ForegroundColor Green

        if ($null -like $vuln_list) {
            Write-Host "Vulmon.com Api returned message: $vulmon_api_status_message" -ForegroundColor DarkCyan
        }
        else {
            Write-Host "$($vuln_list.Count) vulnerabilities found!" -ForegroundColor Red
            $vuln_list | Format-Table -AutoSize
            $global:cvssv2_basescore_sum = $global:cvssv2_basescore_sum/$vuln_list.Count
        }
    }

    function Get-Inventory {
        if ($ReadInventoryFile) {
            # read from file
            Write-Host "Reading software inventory from $InventoryInFile..."
            $inventory_json = Get-Content -Encoding UTF8 -Path $InventoryInFile | Out-String
        }
        else {
            Write-Host 'Collecting software inventory...'
            $inventory = Get-ProductList
            $inventory_json = ConvertTo-Json $inventory
        }

        Write-Host 'Software inventory collected'
        return $inventory_json
    }



    <#-----------------------------------------------------------[Execution]------------------------------------------------------------#>
    Write-Host 'collecting software inventory started...'

    $inventory_json = Get-Inventory

    if (! $inventory_json) {
        Write-Warning 'No installed software detected.'
        break
    }

    if ($Mode -eq 'Default') {
        Invoke-VulnerabilityScan $inventory_json | Out-Default # Out-Default forces PowerShell to ouput this object before 'Done.', as intended.
        $win_inventory_res = "{""cvssv2_basescore_sum"":$global:cvssv2_basescore_sum,""inventory"":$inventory_json}"
        Write-Host "Saving software inventory result to $InventoryOutFile..."
        $win_inventory_res | Out-File -Encoding UTF8 -FilePath $InventoryOutFile
        #echo $win_inventory_res > $InventoryOutFile
    }

    Write-Host 'Done.'
}
systeminfo > windows/systeminfo.txt 
Invoke-Vulmap
Write-Host "Press any key to continue..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")