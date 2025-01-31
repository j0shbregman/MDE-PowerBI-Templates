<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>



#These are the paths where the links are going to be 
$link_paths = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\", "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\")

$start_apps = (Get-StartApps)

$start_apps_map = @{ }

foreach ($start_app in $start_apps) {

    #Write-Host $start_app.Name $start_app.AppId
    $start_apps_map.Add($start_app.AppId,$start_app.Name)

}


$programs = @{
    "Adobe Acrobat"                = "Acrobat.exe"
    "[Adobe Photoshop]"            = "photoshop.exe"
    "[Adobe Illustrator]"          = "illustrator.exe"
    "Adobe Creative Cloud"         = "Creative Cloud.exe"
    "Adobe Substance 3D Painter"   = "Adobe Substance 3D Painter.exe"
    "Firefox Private Browsing"     = "private_browsing.exe"
    "Firefox"                      = "firefox.exe"
    "Google Chrome"                = "chrome.exe"
    "Microsoft Edge"               = "msedge.exe"
    "Notepad++"                    = "notepad++.exe"
    "Parallels Client"             = "APPServerClient.exe"
    "Remote Desktop"               = "msrdcw.exe"
    "TeamViewer"                   = "TeamViewer.exe"
    "[Royal TS]"                   = "royalts.exe"
    "Elgato StreamDeck"            = "StreamDeck.exe"
    "[Visual Studio]"              = "devenv.exe"
    "Visual Studio Code"           = "code.exe"
    "Camtasia Studio"              = "CamtasiaStudio.exe"
    "Camtasia Recorder"            = "CamtasiaRecorder.exe"
    "Jabra Direct"                 = "jabra-direct.exe"
    "7-Zip File Manager"           = "7zFM.exe"
    "Access"                       = "MSACCESS.EXE"
    "Excel"                        = "EXCEL.EXE"
    "OneDrive"                     = "onedrive.exe"
    "OneNote"                      = "ONENOTE.EXE"
    "Outlook"                      = "OUTLOOK.EXE"
    "PowerPoint"                   = "POWERPNT.EXE"
    "Project"                      = "WINPROJ.EXE"
    "Publisher"                    = "MSPUB.EXE"
    "Visio"                        = "VISIO.EXE"
    "Word"                         = "WINWORD.exe"
    "[PowerShell 7]"               = "pwsh.exe"
    "SQL Server Management Studio" = "ssms.exe"
    "Azure Data Studio"            = "azuredatastudio.exe"
    "Zoom"                         = "zoom.exe"
    "Internet Explorer"            = "IEXPLORE.EXE"
    "Skype for Business"           = "Skype.exe"
    "VLC Player"                   = "vlc.exe"
    "Cisco Jabber"                 = "CiscoJabber.exe"
    "Microsoft Teams"              = "msteams.exe"
    "PuTTY"                        = "putty.exe"
    "wordpad"                      = "WORDPAD.EXE"
    "[AutoCAD]"                    = "acad.exe"
    "[CORSAIR iCUE Software]"      = "iCue.exe"
    "[Steam]"                      = "steam.exe"
    "Paint"                        = "mspaint.exe"
}





function GetLinkData($path, $link) {
    
    $filepath = $path+$link

    $Folder = Split-Path -Parent -Path $FilePath
    $File = Split-Path -Leaf -Path $FilePath
    $Shell = New-Object -COMObject Shell.Application
    $ShellFolder = $Shell.NameSpace($Folder)
    $ShellFile = $ShellFolder.ParseName($File)

    
    $app_id = $ShellFile.ExtendedProperty("System.AppUserModel.ID")
    $toast_activator_CLSID = $ShellFile.ExtendedProperty("System.AppUserModel.ToastActivatorCLSID")
    $package_app_id = $ShellFile.ExtendedProperty("System.AppUserModel.PinMigration.PackagedAppId")

    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($filepath)
    

    $target_path = $Shortcut.TargetPath

    if ($null -ne $target_path -and $target_path -ne "") {

        $target_paths = $target_path -split '\\'
        $last_target_path = $target_paths[$target_paths.Count-1]

    }

    if ($null -ne $app_id -and $start_apps_map.Contains(($app_id))) {
        $app_name = $start_apps_map[$app_id]
    } else {
        $app_name = "?"
    }

    $link_paths = $link -split '\\'
    $last_link_path = $link_paths[$link_paths.Count-1]


    $pos_of_period = $last_link_path.IndexOf(".")
    $last_link_name = $last_link_path.Substring(0,$pos_of_period)
    
    if ($null -ne $app_id -or $null -ne $toast_activator_CLSID -or $null -ne $package_app_id) {

        if ($app_name -ne $last_link_name) {
            Write-Host "Warning: The name of the app ($app_name) and the link ($last_link_name.lnk) don't match." -ForegroundColor Yellow
        }


        if ($link_paths.Count -gt 1) {
            $sub_menu = $link_paths[0]
        } else {
            $sub_menu = ""
        }
        
        #Check if the name of the app or the .exe is in the $programs list
        if ($programs.Contains($last_link_name)) {

            $comment = ""
            #remove the item from programs

            $program = $programs[$last_link_name]

            $program_data = "`t""$last_link_name""        =      ""$program""`n"

            $programs.Remove($last_link_name)


        } elseif ($programs.ContainsValue($last_target_path)) {
            
            #Find the key for multi-versions
            $multi_version_key = $programs.Keys.Where({ $programs[$PSItem] -eq $last_target_path; }, [System.Management.Automation.WhereOperatorSelectionMode]::First);
            $program_data = "`t""$multi_version_key""        =      ""$last_target_path""`n"

            if ($programs.Contains("$multi_version_key")) {
                $programs.Remove("$multi_version_key")
            } else {
                Write-Host "Error:  `$programs doesn't contain $multi_version_key" -ForegroundColor Red
            }
            


        } else {

            Write-Host "Warning: No entry or duplicate entry for $last_link_name or $last_target_path in `$programs." -ForegroundColor Yellow
            if ($null -ne $target_path -and $target_path -ne "") {

                $program_data="`t#""$last_link_name""      =   ""$last_target_path""`n"  

            }
            $comment = "#"
        }

        if ($null -ne $toast_activator_CLSID ) {
            #remove the {}
            $toast_activator_CLSID = $toast_activator_CLSID.trim('{}') 
            $toast_activator_CLSID = "[System.guid]::New(""$toast_activator_CLSID"")"
        } else {
            $toast_activator_CLSID = """"""
        }

        $tiles_data = "`t$comment""$last_link_name"" = @{AppUserModelID=""$app_id"";ToastActivatorCLSID=$toast_activator_CLSID;PackagedAppId=""$package_app_id""}`n"
            

        return $tiles_data, $program_data
        
    }
    

}



$tile_output = ""
$program_output = ""


$tile_output = "`$programsTiles=@{`n"
$program_output = "`$programs=@{`n"

foreach ($path in $link_paths) {

    
    $links = (Get-ChildItem -Path $path -Recurse -Name -Include "*.lnk")
    foreach ($link in $links) {
        $tile_data,$program_data=GetLinkData $path $link
        $tile_output+= $tile_data
        $program_output+=$program_data
    }

}
$tile_output += "}"


$programs.GetEnumerator() | ForEach-Object {

    $key = $_.Key
    $value = $_.Value
    Write-Host "Warning: No link found for $key.  Please re-run this script on a machine that has this application installed correctly." -ForegroundColor Yellow
    $program_output += "`t""$key""        =      ""$value""`n"
}
$program_output +="}"


Write-Host "Entries that are commented out were found on the machine, but not in the `$programs variable on line 42 of this script." -ForegroundColor Green
Write-Host "Use the following data in the AddShortcutsv6.ps1 for `$programsTiles" -ForegroundColor Green

Write-Host "$tile_output"

Write-Host "Use the following data in the AddShortcutsv6.ps1 for `$programs" -ForegroundColor Green

Write-Host "$program_output"