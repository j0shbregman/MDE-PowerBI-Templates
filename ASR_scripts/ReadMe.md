# About

This repo contains sample Powershell scripts commands and instructions to recover shortcuts (.lnk) from the False Positive (FP) on Attack Surface Reduction rules (ASR Rules) - “Block Win32 API calls from Office macro” rule turned on in **block mode**. 

Please start out by reading the blog here https://aka.ms/ASRFPRecovery

And then going thru the Frequently Asked Questions (FAQ) here https://aka.ms/ASR_shortcuts_deletion_FAQ 

## ASROfficeWin32IsSystemImpacted.ps1
    Script to detect impact on a machine using security intelligence update (aka signature, definitions) versions installed and time range, and *any* events logged in.  https://aka.ms/ASRTestImpact

## RecoverRules.ps1

This script requires Powershell 5.x and not Powershell 7.x

<table>
<tr>
<td> Version</td> <td> Details </td> <td> Github link </td>
</tr>
<tr>
<td> v3 </td>
<td>


```
* 01/17/2022
* Improved VSS recovery to restore .lnk files into Startup, Desktop, and Quick Launch.
* Updated VSS recovery logic to look for shadow copies before '2023-01-13T06:04:45.000Z' on using the -ForceRepair option.
* Enhanced support for localization - fixed bug where ACL didn't work outside of EN-US
* Updated tool messages for better clarity & detail
* Runs in User Context.
```


</td>

<td>

```
https://aka.ms/ASRAddShortcuts

```

</td>
</tr>

<tr>
<td> v2  </td>
<td>


```
* 01/16/2022
* Volume Shadow Copy (VSS) Recovery is attempted by Default 
* Improvements to also recover Favorite URLs to Favorites & Desktop
* Handling for Server SKU to skip the run as there was no impact
* Better handling on non-english language systems
* + items from v1.1 & v1.0
```


</td>

</td>

<td>

```
https://aka.ms/ASRAddShortcutsv2
```

</td>

</tr>
<tr>
<td> v1.1  </td>
<td>


```
* 01/15/2022
* Volume Shadow Copy (VSS) Recovery switch
* Tool telemetry
* + items from v1
```

</td>

</td>

<td>

```
https://aka.ms/ASRAddShortcutsV1.1
```

</td>
</tr>
<tr>
<td> v1 </td>
<td>


```
* 01/14/2022
* Recover shortcut in the “Start menu” from a static list
* Note: You are able to append their Line of business applications (LoB apps)
```


</td>
<td>

```
https://aka.ms/ASRAddShortcutsV1
```

</td>
</tr>
</table>

## MpTaskBarRecover.exe
Tool to try recovering taskbar shortcuts (.lnk)

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
