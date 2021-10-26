# TestSigned
Powershell script to test for unsigned service DLLs on Windows10+ clients and Servers

DLLs relating to running services should be signed by a trusted organisation but sometimes unsigned services execute without signing (especially some legacy netsvcs services etc.)

During any incident investigation it is important to identify whether any unknown/unrecognised unsigned DLLs are running and this script iterates through all running services and checks for a signed cert for each - listing the unsigned ones.
For best use, collect a trusted baseline of unsigned services and compare the output of the tool.

Note that you may need to change your Powershell ExecutionPolicy to allow an externally defined scipt to run by using the code:

```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
```
Please do not make changes to the ExectionPolicy unless you understand the implications, see https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.1

Example use:
```
PS> . .\test-signed.ps1
PS> Test-Signed
```

The script will present a progress bar as each running service is inspected and will then report on unsigned DLLs, e.g.
```
Test-Signed V1.0
D Scholefield Nov 2019
---------------------------------------------
Number of signed services:  196 (of which unique 46)
Number of unsigned services: 0 (of which unique 0)
Service .exe's that have no valid signature or unauthorised:
        none
Service .DLL's that have no valid signature or DLL path cannot be found:
Total of 19
        NetworkService:nlasvc (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:Nwsapagent (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:LogonHours (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:PCAudit (details: no key:[HKLM key not found defining this service DLL])
        LocalServiceNetworkRestricted:LmHosts (details: no key:[HKLM key not found defining this service DLL])
        LocalService:nsi (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:uploadmgr (details: no key:[HKLM key not found defining this service DLL])
        NetworkService:dosvc (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:Nla (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:Irmon (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:Ntmssvc (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:WmdmPmSp (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:helpsvc (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:Ias (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:SRService (details: no key:[HKLM key not found defining this service DLL])
        LocalServiceAndNoImpersonation:BthHFSrv (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:NWCWorkstation (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:FastUserSwitchingCompatibility (details: no key:[HKLM key not found defining this service DLL])
        netsvcs:Wmi (details: no key:[HKLM key not found defining this service DLL])
```


