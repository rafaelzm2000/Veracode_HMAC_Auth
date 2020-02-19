﻿[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-RandomHex {
    param(
        [int] $Bits = 256
    )
    $bytes = new-object 'System.Byte[]' ($Bits/8)
    (new-object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
    (new-object System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary @(,$bytes)).ToString()
}

<# Returns a Byte array from a Hex String #>
Function GetByteArray {

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true)]
        [String] $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)

    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }

    $Bytes   
}

<# Returns nonce as a byte array#>
Function GetNonce {

    $nonce = Get-RandomHex -Bits 128 
    $nonceByteArray = GetByteArray $nonce

    $nonceByteArray
}

Function ComputeHash ($CHData, $CHKey) {
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $CHKey

    $Result = $hmac.ComputeHash($CHData)

    $Result

}

<# Construct Signature #>
Function CalculateDataSignature($apiKeyBytes, $nonceBytes, $dateStamp, $dataCDS) {

    $requestVersion = "vcode_request_version_1"
    $requestVersionBytes = [Text.Encoding]::UTF8.GetBytes($requestVersion)
    [byte[]] $kNonce = ComputeHash $nonceBytes $apiKeyBytes
    [byte[]] $kDate = ComputeHash  $dateStamp $kNonce
    [byte[]] $kSignature = ComputeHash $requestVersionBytes $kDate

    $dataSignature = ComputeHash $dataCDS $kSignature 

    $dataSignature

}

Function CalculateAuthorizationHeader($IdCA, $apiKeyCA, $urlBaseCA, $urlPathCA, $MethodCA, $urlQueryParams)	{
    
    try {

        if (-not ([string]::IsNullOrEmpty($urlQueryParams)))
		{
			$urlPathCA += '?' + ($urlQueryParams);
		}
              
        $dataCA = "id={0}&host={1}&url={2}&method={3}" -f $IdCA, $urlBaseCA, $urlPathCA, $MethodCA
        $dataCABytes = [Text.Encoding]::UTF8.GetBytes($dataCA)
		$dateStamp = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
        [byte[]] $dateStampbytes = [Text.Encoding]::UTF8.GetBytes($dateStamp)
        [byte[]] $nonceBytesCA = GetNonce
        $nonceHex = [System.BitConverter]::ToString($nonceBytesCA) -replace '-'
        [byte[]] $apiKeyBytes = GetByteArray $apiKeyCA
        [byte[]] $dataSignatureCA = CalculateDataSignature $apiKeyBytes $nonceBytesCA $dateStampbytes $dataCABytes
        $dateSignatureHex = [System.BitConverter]::ToString($dataSignatureCA) -replace '-'
		$authorizationParam = "id={0},ts={1},nonce={2},sig={3}" -f $IdCA, $dateStamp, $nonceHex, $dateSignatureHex 

        $AuthorizationScheme = "VERACODE-HMAC-SHA-256" + " " + $authorizationParam
        
        $AuthorizationScheme
        
   }
    catch {
	
	    $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Host $ErrorMessage
        Write-Host $FailedItem
        Break
    }
    
}

<# The script uses environment variables to hide your API ID and Key. 
 # You will need to set up two environment variables called Veracode_API_ID and Veracode_API_Key.
 # You may use your credentials as plain text. However, that is not recommended. 
#>         
$id = $env:Veracode_API_ID
$key = $env:Veracode_API_Key

$authorizationScheme = 'VERACODE-HMAC-SHA-256'
$requestVersion = "vcode_request_version_1"
$method = 'GET'
$urlBase = "analysiscenter.veracode.com"
$urlPath = "/api/5.0/getbuildlist.do"
<# $urlQueryParams Usage
 # If you only one parameter, do not add the '?' The code will handle it. Example: $urlQueryParams = 'app_id=420049'
 # If you have more then one parameter, ingore the first '?' but add it between each parameter. 
 # Example: $urlQueryParams = 'app_id=12345?sandbox_id=12345?version=scanname'
#>
$urlQueryParams = 'app_id=420049'

if (-not ([string]::IsNullOrEmpty($urlQueryParams)))
{
    $url = 'https://' + $urlBase + $urlPath + '?' + $urlQueryParams

}else {

    $url = 'https://' + $urlBase + $urlPath 
}

<# Construct Header #>
$authorization = CalculateAuthorizationHeader $id $key $urlBase $urlPath $method $urlQueryParams
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization",$authorization)
$headers.Add("Content-Type",'application/json')

<# Make Request #>
Try{

    $response = Invoke-WebRequest -Uri $url -Headers $headers -Method Get 

    <# Print status and body of response #>
    $status = $response.StatusCode
    $body = $response.Content

    Write-Host "Request Status Code:$status"
    Write-Host "Response:$body"
}
catch {
	
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Host $ErrorMessage
    Write-Host $FailedItem
    Break
}






