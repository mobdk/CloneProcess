# CloneProcess
Clone running process with ZwCreateProcess (syscall)

Compile as https://github.com/mobdk/compilecs and insert entrypoint
Executing: rundll32 CloneProcess.dll,#1 or rundll32 CloneProcess.dll,DllMain

Tested on 64 bit Windows 10 build 2004 19041.572 

Cloning non admin process works also, if one like to clone svchost.exe with arguments fx: svchost.exe -k PrintWorkflow -s PrintWorkflowUserSvc

int ProcId = FindTheRightPID("svchost.exe", "PrintWorkflow", "PrintWorkflowUserSvc", ""); FindTheRightPID will return the correct PID

Cloning admin process like lsass.exe fx: int ProcId = FindTheRightPID("lsass.exe", "", "", ""); rundll32 CloneProcess.dll,#1 must be
running as admin.



