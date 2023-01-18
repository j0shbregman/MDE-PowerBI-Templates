# About

This repo contains sample Powershell scripts commands and instructions to recover shortcuts (.lnk) from the False Positive (FP) on Attack Surface Reduction rules (ASR Rules) - “Block Win32 API calls from Office macro” rule turned on in **block mode**. 

Please start out by reading the blog here https://aka.ms/ASRFPRecovery

And then going thru the Frequently Asked Questions (FAQ) here https://aka.ms/ASR_shortcuts_deletion_FAQ 


## ASROfficeWin32IsSystemImpacted.ps1
Script to detect impact on a machine using security intelligence update (SIU aka signature, definitions) versions installed and time range, and *any* events logged in.  

### Notes
**#1:**  The logic depends on Windows Event entries that contain the 3 impacted SIU versions. But those events get rotated especially as days pass, so you'll may see 'Machine was not impacted by ASR rule', 'Machine didnt get affected' respectively for the scripts. ForceRepair parameter is for that purpose.

### Release History
Version | Date    | Details | Link |
| ------- | ------- | ----------- | ------|
| v1      |  01/16/2023 | Initial Release | https://aka.ms/ASRTestImpact |

## AddShortcuts.ps1

This script requires Powershell 5.x and not Powershell 7.x\

### Release History

| Version | Date    | Details | Link |
| ------- | ------- | ----------- | ------|
|  v3     | 01/17/2023 |<li>Improved VSS recovery to restore .lnk files into Startup, Desktop, and Quick Launch.</li><li>Updated VSS recovery logic to look for shadow copies before '2023-01-13T06:04:45.000Z' on using the -ForceRepair option.</li><li>Enhanced support for localization - fixed bug where ACL didn't work outside of EN-US</li><li>Updated tool messages for better clarity & detail</li><li>Runs in User Context</li>   | https://aka.ms/ASRAddShortcuts |
|  v2     | 01/16/2023 | <li>Volume Shadow Copy (VSS) Recovery is attempted by Default</li><li>Improvements to also recover Favorite URLs to Favorites & Desktop</li><li>Handling for Server SKU to skip the run as there was no impact</li><li>Better handling on non-english language systems</li>| https://aka.ms/ASRAddShortcutsv2 |
|  v1.1   | 01/15/2023 | <li>Added Volume Shadow Copy (VSS) Recovery switch</li><li>Added telemetry</li> |  https://aka.ms/ASRAddShortcutsV1.1 |
|  v1.0   | 01/14/2023 | <li>Recover shortcut in the “Start menu” from a static list</li> |  https://aka.ms/ASRAddShortcutsV1 |

### Notes
**#1:**  The logic depends on Windows Event entries that contain the 3 impacted SIU versions. But those events get rotated especially as days pass, so you'll may see 'Machine was not impacted by ASR rule', 'Machine didnt get affected' respectively for the scripts. Force parameter is for that purpose.\
**# 2:**  When running the AddShortcuts.ps1, you should consider passing the -force parameter.

### Frequently Asked Questions (FAQ)
**Q:** I'm missing shortcuts after running AddShortcuts.ps1\
**A:** The app shortcuts that will be recovered by default are listed in Q17 here https://aka.ms/ASR_shortcuts_deletion_FAQ\
If you want to add additional shortcuts, you are able to by adding the shortcut name w/o the .lnk and adding the .exe in line 65 in the RecoverRules.ps1 here https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_scripts/AddShortcuts.ps1


## MpTaskBarRecover.exe
Tool to try recovering taskbar shortcuts (.lnk)

Usage of the tool:\
CMD (non-admin)\
MpTaskBarRecover.exe [-v] [--notelemetry] [--force] [--forcerepair] [-?]

-v             verbose\
--notelemetry  To disable telemetry reporting.\
--forcerepair  Force repair shortcuts that are not pointing to right pinned targets.\
--force        Force to rerun the tool on the same device.\
-?             Display usage without running the tool.

Note: Logs will be saved to %temp%\MpRecoverTaskBar-xxxx_x_x_x_x_x*.log

<table>
<tr>
<td> Version</td> <td> Details </td> <td> Microsoft Download Center link  </td>
</tr>
<tr>
<td> v2 </td>
<td>


```
* 01/17/2022
* If you are using System Center Config Manager or Group Policy Object Editor or third-party tools then deploy both files and run the command “powershell -ep bypass -file .\AddShortcuts.ps1 -MpTaskBarRecoverUtilLocal” as Administrator.
* If you are using Intune or no management tool then deploy AddShortcuts.ps1 and run the command “powershell –ep bypass –file .\AddShortcuts.ps1 -MpTaskBarRecoverUtilDownload” as Administrator.  This will automatically download MPTaskBarRecover.exe from the Microsoft download center onto the user’s machine and run the script. Detailed Instructions on how to deploy the script using Microsoft Intune are here. 
* The changes will come into effect after users logout and login to their accounts.
* The MPRecoverTaskbar.exe can be run multiple times on end-user machines if necessary.  If end-users are missing taskbar icons after completing this process, then try running it a second time from %windir%\MPRecoverTaskbar.exe in the user context.
```


</td>

<td>

```
https://aka.ms/ASRTaskBarRepairTool

```

</td>
</tr>

<tr>
<td> v1  </td>
<td>


```
* 01/16/2022
* Needs to run in user context (non-admin) 
```


</td>

</td>

<td>

```
<Replaced with the new version>
```

</td>


</tr>
</table>

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
