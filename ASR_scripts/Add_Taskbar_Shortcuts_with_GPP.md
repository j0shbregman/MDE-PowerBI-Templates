# Step-by-step guide to run MpTaskBarRecover.exe via Group Policy Preferences (GPP) on Windows 10/11

### *Before proceeding:* You only need to follow these steps if your Windows 10 or Windows 11 are not able to download https://aka.ms/ASRTaskBarRepairTool directly from the Microsoft Download Center (MSFTDlC).  Since https://aka.ms/ASRAddShortcuts automatically tries to download ASRTaskBarRepairTool from the MSFTDlC.
<br />

You can use a Scheduled Task group policy preference that launches at logon for user level.

<br />

This guide visually demonstrates steps described in Microsoft public documentation [Group Policy Preferences](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581922(v=ws.11))

<br />

## Step to deploy MpTaskBarRecover.exe as a "User configuration" (not as "Computer Configuration")
##### 1. On a machine that has "Group Policy Management" a part of [Remote Server Administration Tools (RSAT)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools)


##### 2. Expand Group Policy Management > Forest: "your domain name e.g. contoso.com"  > Domains > "your domain name e.g. contoso.com" > Group Policy Objects

![Info](.ImagesGPO/GPO18.png)\
Right-click on "Group Policy Objects"\
Click on New

##### 3. In New GPO
![Info](.ImagesGPO/GPO19.png)\
Under "Name: Recover Taskbar"\
Click on OK

##### 4. Double-click on "Recover Taskbar"
Click on "Details" tab\
![Info](.ImagesGPO/GPO25.png)\
Write down the "Unique ID" e.g. DFF97E65-7139-401B-9D27-13FC975BE08D\
![Info](.ImagesGPO/GPO26.png)\
Note:  In this example is in \\dc\SYSVOL\contoso.com\Policies\DFF97E65-7139-401B-9D27-13FC975BE08D\User\
Note 2: The DFF97E65-7139-401B-9D27-13FC975BE08D will be different for your environment.\
Note 3: You will need the unique GUID above for step 11.

##### 5. Download https://aka.ms/ASRTaskBarRepairTool to c:\temp
Download the latest version of the .exe from https://aka.ms/ASRTaskBarRepairTool to your drive.  In this example, we are using c:\temp\

![Info](.ImagesGPO/GPO27.png)

Right-click on MpTaskBarRecover\
Click on Properties

![Info](.ImagesGPO/GPO28.png)

 In the "General tab" (default)\
Next to "Security: This file came from another computer and might be blocked to help protect\ this computer."\
Check the box for "Unblock".\
Click on "Apply"\
Click on "OK"

##### 6. Right-click on "Recover Taskbar" GPO
![Info](.ImagesGPO/GPO20.png)\
Click on "Edit"

##### 7. Open "User Configuration" > "Preferences" > "Control Panel Settings" > "Scheduled Tasks"
![Info](.ImagesGPO/GPO21.png)\
Right-click "Scheduled Tasks"\
Click on "New"\
Select "Immediate Task (At least Windows 7)"

##### 8. In the "General" tab (default)

![Info](.ImagesGPO/GPO22.png)\
Action: Update\
Name: "<"Enter the name of the scheduled task", in this example, we will use "Recover Taskbar"\
Next to "When running the task, use the following user account:" %LogonDomain%\%LogonUser% (default) \
Select the radio button "Run only when user is logged on" \
Do not check the box for "Run with highest privileges"\
In "Configure:" select "Windows 7, Windows Server 2008 R2"

##### 9. In the "Triggers" tab
![Info](.ImagesGPO/GPO29.png)\
Click on "New..."

Begin the task: At log on\
Settings - Any user\
Delay task for: 1 minute\
Stop task if it runs longer than: 30 minutes\
Activate:\
Check the box for Expire: 1/31/2023 11:59:59 PM\
Check the box "Enabled"\
Click on "OK"

Note: The expiration is optional

##### 10. In the "Actions" tab

![Info](.ImagesGPO/GPO30.png)\
Click on New...

### *Copy c:\temp\MpTaskBarRecover.exe to \\dc\SYSVOL\contoso.com\Policies\DFF97E65-7139-401B-9D27-13FC975BE08D\User*
Note: The GUID here will be different for your environment.  Review Step 5 above.
>

![Info](.ImagesGPO/GPO31.png)\
Click on "Browse..."\
Note: \\dc\SYSVOL\contoso.com\Policies\DFF97E65-7139-401B-9D27-13FC975BE08D\User\
Note: The GUID here will be different for your environment.  Review Step 5 above.

![Info](.ImagesGPO/GPO32.png)\
In the Open dialog box, next to "File name:" Make sure that MpTaskbarRecover is present\
Click on "Open"

![Info](.ImagesGPO/GPO33.png)\
Click on "OK"

##### 11. In the "Conditions" tab
Leave it "default"

##### 12. In the "Settings" tab
Leave it "default"

##### 13. In the "Common" tab
Leave it "default"

Click on "Apply"\
Click on "OK"

You should see the following:\
![Info](.ImagesGPO/GPO34.png)

Close the "Group Polcy Management Editor"

##### 14. Go to the OU that you want to deploy this new GPO.

![Info](.ImagesGPO/GPO35.png)\
Right-click on the OU "e.g. Workstation"\
Click on "Link an Existing GPO"\


![Info](.ImagesGPO/GPO37.png)\
Under "Look in this domain:" Select your domain (e.g. contoso.com)\
Under "Group Policy object:" select the policy (e.g. "Recover Taskbar")

![Info](.ImagesGPO/GPO38.png)
Under the "Linked Group Policy Objects", you should see the new policy.\

##### 15. On a Windows 10 or Windows 11 client, login with a end-user account (running as a domain user, not as LocalAdmin)

Open up Task Scheduler\
Double click on "Task Scheduler Library"\
Under name, you should be able to see "Recover Tasbar"
>

e.g.\
![Info](.ImagesGPO/GPO39.png)
