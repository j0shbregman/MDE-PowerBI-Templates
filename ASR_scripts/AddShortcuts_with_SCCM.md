Follow the below steps to create a package in ConfigMgr to recover start menu and taskbar shortcuts.

1.  Download both [**AddShortcuts.ps1**](https://github.com/microsoft/MDE-PowerBI-Templates/blob/master/ASR_scripts/AddShortcuts.ps1) and [**MpRecoverTaskBar.exe**](https://aka.ms/ASRTaskBarRepairTool) to a folder.
2.  Open ConfigMgr console. Click on **Software Library** workspace and navigate to **Application Management** \> **Packages.**
3.  Click on the **Create Package** button to start creating the package using package wizard.
4.  In the **Specify information about the package** page, enter a name for the package. Other fields are optional.

    Check the **This Package contains source files** check box and provide the folder location where you saved all the files. It should be a network location.

    Click **Next**.

    ![Graphical user interface, text, application, email Description automatically generated](Images/ASRFPRecovery_with_SCCM01.png)

5.  In the **Program Type** window, Select **Standard Program** and click Next.
6.  In the **Standard Program** windows, update the fields as below. For the ![Graphical user interface, text, application, email Description automatically generated](Images/ASRFPRecovery_with_SCCM02.png)

    Use the below command line:

    **powershell -ExecutionPolicy bypass -file AddShortcutsV3.ps1 -MpTaskBarRecoverUtilLocal**

7.  In the **Requirements** window, leave all fields as default and click Next.
8.  Confirm the settings in the **Summary** window and click Next.
9.  Click on the Close button once the package creation is completed successfully.
