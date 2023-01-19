# Block Win32 API calls from Office macro ASR Recovery Scripts

This repo contains sample Powershell scripts commands and instructions to recover shortcuts (.lnk) from the False Positive (FP) on Attack Surface Reduction rules (ASR Rules) - “Block Win32 API calls from Office macro” rule turned on in **block mode**. 

Please start out by reading the blog here https://aka.ms/ASRFPRecovery

And then going thru the Frequently Asked Questions (FAQ) here https://aka.ms/ASR_shortcuts_deletion_FAQ 

This repo contains information about the following scripts:
* AddShortcuts.ps1 - Powershell script that attempts to restore impacted shortcuts based on imformation retrieved from VSS and registry
* MpTaskBarRecover.exe - Executable that attempts to restore taskbar links and libraries based on information retrieved from the registry
* ASROfficeWin32IsSystemImpacted.ps1 - Powershell script that checks based on available logs and events if a machine has been impacted by this issue

## AddShortcuts.ps1

```
AddShortcuts.ps1 [-Telemetry $false|$true ][ -ForceRepair ][ -VssRecovery ][ -Verbose 0|1|2|3 ]

Telemetry:                          Enable or disables having telemetry logging, default: true
ForceRepair:                        Repair is done irrespective of machine being considered affected or not, default: true
VssRecovery:                        Use VSS recovery to restore lnk files, default: true
MpTaskBarRecoverUtilDownload:        Download the MpTaskBarRecovery.exe from the Microsoft Download Center, default: true
                                    When this is false, the script assumes that MpTaskBarRecover.exe resides in the current working                                           directory 
SkipBinaryValidation:                Skips validating the authenticity of MpTaskBarRecover.exe whether download or locally, default: false                                    
Verbose:          Level of logging, default 1 
                      0: No stdout and no log file
                      1: Only stdout (default)
                      2: both stdout and log file output
                      3: detailed stdout along with log file output
```

### Fixes links to software installed based on app path
The script iterates through ``` SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths ``` for both HKLM and HKU hives and looks for applications defined in the script.  For those applications, a version is retrieved from the registry, and a shortcut is created in the appropriate Start Menu.  This will run for all applications defined and is the registry, so customers may see new items added to the Start Menu.

#### Adding additional applications
The script can be modified to include additional applications by adding entry to the ```$programs``` variable.  

```
$programs = @{
    "Adobe Acrobat"                = "Acrobat.exe"
    "[Adobe Photoshop]"            = "photoshop.exe"
    "[Adobe Illustrator]"          = "illustrator.exe"
    ...
```

**Important:** ```$programs``` table is a key=value pair, with [] are used to denote programs that have version year info, like [Visual Studio]  For such entries with [], we will lookup file description in file version info and use that, if it doesnt exists, we will fallback using generic name.

### VSS Recovery (Optional)
If the script discovers VSS (shadow copy), then the shadow copies are mounted, and the following paths/extensions are restored if the files exist

| Path | Extensions |
| ---- | ------     |
| \Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\ | .lnk |
| \ProgramData\Microsoft\Windows\Start Menu\ | .lnk |
| $($profiledir)\AppData\Roaming\Microsoft\Windows\ | .lnk |
| $($profiledir)\AppData\Roaming\Microsoft\Internet Explorer\ | .lnk |
| $($profiledir)\AppData\Roaming\Microsoft\Office\ | .lnk |
| $($profiledir)\Favorites\ | .url |
| $($profiledir)\Desktop\ | .url |
| $($profiledir)\Desktop\ | .lnk |

### Best effort to trigger run once of MpTaskBarRecovery.exe 

The ```MpTaskBarRecover.exe``` is added as a RunOnce to every user.  There is a best effort attempt to trigger RunOnce immediately for logged in users by impersonating their tokens.  This is only expected to work if the script is run from local SYSTEM account, and may work from an elevated administrator context depending on the local security policy.  Even if triggering the RunOnce is unsuccessful, then the .exe will run in the next time the user logs in.  Non logged on users will still have to log in to have the MpTaskBarRecover.exe run.

The MpTaskBarRecover.exe is either downloaded from the Microsoft Download Center or copied locally from the current working directory to the Windows directory.  Before copying the file to the Windows directory the script validates the authenticity of the binary, unless the Skip.... is enabled.

### Saving Results (Optional) 
(CELA)

### Release History

| Version | Date    | Details | Link |
| ------- | ------- | ----------- | ------|
|  v4     | 01/18/2023 | <li>Attempts to trigger RunOnce for every user on a **best effort** basis</li><li>```-ForceRepair`` is on by default</li><li>Minor bug fixes</li> | ? |
|  v3     | 01/17/2023 |<li>Improved VSS recovery to restore .lnk files into Startup, Desktop, and Quick Launch.</li><li>Updated VSS recovery logic to look for shadow copies before '2023-01-13T06:04:45.000Z' on using the -ForceRepair option.</li><li>Enhanced support for localization - fixed bug where ACL didn't work outside of EN-US</li><li>Updated tool messages for better clarity & detail</li><li>Runs in User Context</li>   | https://aka.ms/ASRAddShortcuts |
|  v2     | 01/16/2023 | <li>Volume Shadow Copy (VSS) Recovery is attempted by Default</li><li>Improvements to also recover Favorite URLs to Favorites & Desktop</li><li>Handling for Server SKU to skip the run as there was no impact</li><li>Better handling on non-english language systems</li>| https://aka.ms/ASRAddShortcutsv2 |
|  v1.1   | 01/15/2023 | <li>Added Volume Shadow Copy (VSS) Recovery switch</li><li>Added telemetry</li> |  https://aka.ms/ASRAddShortcutsV1.1 |
|  v1.0   | 01/14/2023 | <li>Recover shortcut in the “Start menu” from a static list</li> |  https://aka.ms/ASRAddShortcutsV1 |

### Notes
**#1:**  This script works best with Powershell 5.x.  The script has encountered issues with some versions of Powershell 7.x.  If you encounter an issue with Powershell 7.x, please consider running this script with Powershell 5.x.


### Frequently Asked Questions (FAQ)
**Q:** I'm missing shortcuts after running AddShortcuts.ps1\
**A:** The app shortcuts that will be recovered by default are listed in Q17 here https://aka.ms/ASR_shortcuts_deletion_FAQ\
If you want to add additional shortcuts, you are able to by adding the shortcut name w/o the .lnk and adding the .exe in line 65 in the RecoverRules.ps1 here https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_scripts/AddShortcuts.ps1

## MpTaskBarRecover.exe
Tool to try recovering taskbar shortcuts (.lnk)

### Usage
```
CMD (non-admin)\
MpTaskBarRecover.exe [-v] [--notelemetry] [--force] [--forcerepair] [-?]

-v             verbose\
--notelemetry  To disable telemetry reporting.\
--forcerepair  Force repair shortcuts that are not pointing to right pinned targets.\
--force        Force to rerun the tool on the same device.\
-?             Display usage without running the tool.
```
### Release History
| Version |Date | Details | Microsoft Download Center Link |
|-----    |-----|------   |-----                           |
|   v2    | 01/17/2022 | <li>If you are using System Center Config Manager or Group Policy Object Editor or third-party tools then deploy both files and run the command “powershell -ep bypass -file .\AddShortcuts.ps1 -MpTaskBarRecoverUtilLocal” as Administrator.</li><li>The changes will come into effect after users logout and login to their accounts.</li><li>The MPRecoverTaskbar.exe can be run multiple times on end-user machines if necessary.  If end-users are missing taskbar icons after completing this process, then try running it a second time from %windir%\MPRecoverTaskbar.exe in the user context.</li>|https://aka.ms/ASRTaskBarRepairTool|
|   v1   |  01/16/2022 | <li>Needs to run in user context (non-admin)</li> | ?  |

### Notes
**#1:**Logs will be saved to ```%temp%\MpRecoverTaskBar-xxxx_x_x_x_x_x*.log``` 

## ASROfficeWin32IsSystemImpacted.ps1
Script to detect impact on a machine using security intelligence update (SIU aka signature, definitions) versions installed and time range, and *any* events logged in.  

### Release History
Version | Date    | Details | Link |
| ------- | ------- | ----------- | ------|
| v1      |  01/16/2023 | Initial Release | https://aka.ms/ASRTestImpact |


### Notes
**#1:**  The logic depends on Windows Event entries that contain the 3 impacted SIU versions. But those events get rotated especially as days pass, so you'll may see 'Machine was not impacted by ASR rule', 'Machine didnt get affected' respectively for the scripts. ForceRepair parameter is for that purpose.


# Deployment options
Here are a couple of deployment tools that you'll are able to use to push out the Powershell script (AddShortcuts.ps1) and/or .exe's (MpTaskBarRecover.exe).
* Intune (MEM, MDM) http://aka.ms/RestoreShortcuts-Intune
* System Center Configuration Manager (SCCM, MEMCM) https://aka.ms/RestoreShortcuts-SCCM

# How to check if your Windows 10 or Windows 11 are still running the impacted SIU:
In Advanced Hunting, you are able to run the following Advanced Hunting (AH) query to see if any of your devices require an updated version of the SIU: 
https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_AdvancedHunting/Check_what_machines_have_the_bad_signatures

Once you confirm that the devices have an updated SIU, you can move the ASR Rules - “Block Win32 API calls from Office macro” rule to **block mode**.

# Suggestions and Feedback

We maintain a backlog of suggested sample Powershell scripts in the project issues page. Feel free to comment, rate, or provide suggestions. We value your feedback. Let us know if you run into any problems or share your suggestions by adding an entry into the issues section.

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
