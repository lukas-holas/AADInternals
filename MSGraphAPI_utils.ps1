# This script contains utility functions for MSGraph API at https://graph.microsoft.com

function Call-MSGraphAPI
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
        [String]$API,
        [Parameter(Mandatory=$False)]
        [String]$ApiVersion="beta",
        [Parameter(Mandatory=$False)]
        [String]$Method="GET",
        [Parameter(Mandatory=$False)]
        $Body,
        [Parameter(Mandatory=$False)]
        $Headers,
        [Parameter(Mandatory=$False)]
        [String]$QueryString,
        [Parameter(Mandatory=$False)]
        [int]$MaxResults=1000,
        # Throttling / retry controls
        [Parameter(Mandatory=$False)]
        [int]$MaxRetries=6,
        [Parameter(Mandatory=$False)]
        [int]$RetryBaseDelaySeconds=2,
        [Parameter(Mandatory=$False)]
        [int]$RetryMaxDelaySeconds=60
    )
    Process
    {
        if($Headers -eq $null)
        {
            $Headers=@{}
        }
        $Headers["Authorization"] = "Bearer $AccessToken"

        if([string]::IsNullOrEmpty($Headers["User-Agent"]))
        {
            $Headers["User-Agent"] = Get-UserAgent
        }

        # Create the url
        $url = "https://graph.microsoft.com/$($ApiVersion)/$($API)?$(if(![String]::IsNullOrEmpty($QueryString)){"&$QueryString"})"
        Write-Verbose "Calling Graph API: $url"

        # Helper: invoke request with throttling-aware retries
        $invokeWithRetry = {
            param([string]$targetUrl)
            $attempt = 0
            while ($true) {
                try {
                    return Invoke-RestMethod -UseBasicParsing -Uri $targetUrl -ContentType "application/json" -Method $Method -Body $Body -Headers $Headers
                }
                catch {
                    $webEx = $_.Exception
                    $resp = $webEx.Response
                    $status = $null
                    if ($resp -and ($resp -is [System.Net.HttpWebResponse])) { $status = [int]$resp.StatusCode }

                    $isThrottle = ($status -eq 429 -or $status -eq 503)
                    $isTransient = $isThrottle -or $status -eq 500 -or $status -eq 502 -or $status -eq 504

                    # Determine retry delay
                    $delayMs = $null
                    $delaySource = $null
                    if ($isTransient -and $resp -and $resp.Headers) {
                        $headersLocal = $resp.Headers
                        $retryAfterHeader = $headersLocal['Retry-After']
                        $retryAfterMsHeader = $headersLocal['x-ms-retry-after-ms']
                        $retryAfterSecHeader = $headersLocal['x-ms-retry-after']
                        $retryAfterSeconds = $null
                        if ($retryAfterHeader) {
                            # Retry-After can be seconds or HTTP-date
                            $sec = 0
                            if ([int]::TryParse($retryAfterHeader, [ref]$sec)) { $retryAfterSeconds = $sec }
                            else {
                                $dt = $null
                                if ([datetime]::TryParse($retryAfterHeader, [ref]$dt)) {
                                    $delta = [int][Math]::Ceiling(($dt.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalSeconds)
                                    if ($delta -gt 0) { $retryAfterSeconds = $delta }
                                }
                            }
                            $delaySource = 'Retry-After'
                        }
                        elseif ($retryAfterMsHeader) {
                            $msVal = 0
                            if ([int]::TryParse($retryAfterMsHeader, [ref]$msVal)) {
                                $delayMs = [Math]::Max(0,$msVal)
                            }
                            $delaySource = 'x-ms-retry-after-ms'
                        }
                        elseif ($retryAfterSecHeader) {
                            $sec2 = 0
                            if ([int]::TryParse($retryAfterSecHeader, [ref]$sec2)) { $retryAfterSeconds = $sec2 }
                            $delaySource = 'x-ms-retry-after'
                        }
                        if ($delayMs -eq $null -and $retryAfterSeconds -ne $null) {
                            $delayMs = [int]([Math]::Max(0,$retryAfterSeconds) * 1000)
                        }
                    }

                    if ($isTransient -and $attempt -lt $MaxRetries) {
                        if ($delayMs -eq $null) {
                            $backoff = [Math]::Min($RetryMaxDelaySeconds, [Math]::Pow(2, $attempt) * $RetryBaseDelaySeconds)
                            $jitterMs = Get-Random -Minimum 100 -Maximum 400
                            $delayMs = [int]([Math]::Round(($backoff * 1000) + $jitterMs))
                            if (-not $delaySource) { $delaySource = 'exponential backoff' }
                        }
                        $delayInfo = "{0} ms ({1})" -f $delayMs, $delaySource
                        if ($status -eq 429) {
                            Write-Verbose ("Graph throttling (429). Retrying in {0}. Attempt {1}/{2}." -f $delayInfo, ($attempt+1), $MaxRetries)
                        } elseif ($status -eq 503) {
                            Write-Verbose ("Graph service unavailable (503). Retrying in {0}. Attempt {1}/{2}." -f $delayInfo, ($attempt+1), $MaxRetries)
                        } else {
                            Write-Verbose ("Transient Graph error {0}. Retrying in {1}. Attempt {2}/{3}." -f $status, $delayInfo, ($attempt+1), $MaxRetries)
                        }
                        Start-Sleep -Milliseconds $delayMs
                        $attempt++
                        continue
                    }

                    # Build informative error message
                    $errorMessage = $webEx.Message
                    try {
                        if ($resp) {
                            $streamMsg = Get-ErrorStreamMessage -errorStream $resp.GetResponseStream()
                            if ($streamMsg) {
                                $errorResponse = $streamMsg | ConvertFrom-Json
                                if ($errorResponse.error.message) { $errorMessage = $errorResponse.error.message }
                            }
                        }
                    } catch {}

                    throw $errorMessage
                }
            }
        }

        # Call the API (initial request)
        $response = & $invokeWithRetry $url

        # Check if we have more items to fetch
        if($response.psobject.properties.name -match '@odata.nextLink')
        {
            $items=$response.value.count

            # Loop until finished or MaxResults reached
            while(($url = $response.'@odata.nextLink') -and $items -lt $MaxResults)
            {
                # Return
                $response.value
                
                $response = & $invokeWithRetry $url
                $items+=$response.value.count
            }

            # Return
            $response.value
            
        }
        else
        {

            # Return
            if($response.psobject.properties.name -match "Value")
            {
                return $response.value 
            }
            else
            {
                return $response
            }
        }

    }
}

# Download a file from an url in an object attribute
# Jun 30st 2022
function DownloadFile
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline)]
        [Object]$Data,
        [Parameter(Mandatory = $False)]
        [String]$Directory = "",
        [Parameter(Mandatory = $False)]
        [String]$FileNameAttribute = "name",
        [Parameter(Mandatory = $False)]
        [String]$DownloadUrlAttribute = "@microsoft.graph.downloadUrl"
    )
    Process
    {
        $Data | Where-Object { $($_.$DownloadUrlAttribute) } | ForEach-Object { 
            Write-Host "Filename : $($_.$FileNameAttribute)"
            Start-BitsTransfer -Asynchronous -Source $($_.$DownloadUrlAttribute) -Destination "$Directory\$($_.$FileNameAttribute)" 
        }
    }
}

