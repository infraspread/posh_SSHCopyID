function sshcopyid {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $sshuser,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $sshhost,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $sshpublicKeyPath,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]
        $AdminAuthorizedKeys
    )

    # check if ssh command exists
    if (!(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Error "ssh command not found. Please install OpenSSH client." -ForegroundColor "Red" -BackgroundColor "Black"
        return
    }


    if (Test-Path $sshpublicKeyPath) {
        $publicKey = Get-Content $sshpublicKeypath
        Write-Host "Public Key from file $sshpublicKeyPath is: $publicKey" -ForegroundColor "Green" -BackgroundColor "Black"
    }
    else {
        Write-Error "The public key file $sshpublicKeyPath does not exist." -ForegroundColor "Red" -BackgroundColor "Black"
    }   

    if ($AdminAuthorizedKeys) {
        $authorizedKeysPath = "C:\ProgramData\ssh\administrators_authorized_keys"
    }
    else {
        $authorizedKeysPath = "%Userprofile%\.ssh\authorized_keys"
    }

    # establish SSH session
    $session = New-PSSession -HostName $sshhost -UserName $sshuser -SSHTransport

   # check if public key already exists in authorized_keys file and add it if it doesn't exist
   $result = Invoke-Command -Session $session -ScriptBlock {
    param($publicKey, $authorizedKeysPath)
    $authorizedKeys = Get-Content $authorizedKeysPath -Raw
    if ($authorizedKeys -match [regex]::Escape($publicKey)) {
        Write-Warning "Public key already exists in $authorizedKeysPath on $env:COMPUTERNAME."
    } else {
        Write-Host "Adding public key to $authorizedKeysPath on $env:COMPUTERNAME."
        Add-Content $authorizedKeysPath $publicKey
    }
} -ArgumentList $publicKey, $authorizedKeysPath

if ($result) {
    Write-Error "Failed to add public key to $authorizedKeysPath on $sshhost : $result" -ForegroundColor "Red" -BackgroundColor "Black"
}

# close SSH session
Remove-PSSession $session
}

<#
    # check if public key already exists in authorized_keys file
    $result = ssh $sshuser'@'$sshhost "type $authorizedKeysPath | findstr /c:""$publicKey""" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Warning "Public key already exists in $authorizedKeysPath on $sshhost."
        return
    }


    if ($AdminAuthorizedKeys) {
        Write-Host "Adding public key from $sshpublicKeyPath to admin_authorized_keys"
        $result = ssh $sshuser'@'$sshhost "cmd.exe /c echo $publicKey >> $authorizedKeysPath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to add public key to $authorizedKeysPath : $result" -ForegroundColor "Red" -BackgroundColor "Black"
            return
        }
    } else {
        write-host "Adding public key from $sshpublicKeyPath to $authorizedKeysPath"
        ssh $sshuser'@'$sshhost "echo $publicKey >> $authorizedKeysPath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to add public key to $authorizedKeysPath : $result" -ForegroundColor "Red" -BackgroundColor "Black"
            return
        }
    }

    # check if public key already exists in authorized_keys file and add it if it doesn't exist
    ssh $sshuser'@'$sshhost "cmd /c type $authorizedKeysPath | findstr /c:""$publicKey""" > $null || "cmd /c echo $publicKey >> $authorizedKeysPath" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Warning "Public key already exists in $authorizedKeysPath on $sshhost."
    } else {
        Write-Host "Adding public key from $sshpublicKeyPath to $authorizedKeysPath"
        Write-Error "Failed to add public key to $authorizedKeysPath $result"
        return
    }
    #>


<#
when running above function, you will get the following output in the target file:
ECHO is on.
ECHO is on.
Microsoft Windows [Version 10.0.20348.1906]
(c) Microsoft Corporation. All rights reserved.

infraspread\administrator@DC C:\Users\Administrator>ECHO is on.
ECHO is on.
#>
