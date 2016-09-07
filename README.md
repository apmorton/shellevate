# shellevate
Shell Based RunAs With UAC Compatibility

shellevate is an extended version of [ShellRunas](https://technet.microsoft.com/en-us/sysinternals/shellrunas.aspx)
that adds support for optionally elevating the process via a UAC prompt. 
Most importantly, it does this elevation _after_ switching user contexts.
This means you don't have to run shellevate itself as admin, and the user you start as does not need to be an admin.

shellevate can also force a program which would normally request a UAC prompt to run without one.

# Examples
- `shellevate /asinvoker /netonly mmc` - run MMC without a UAC prompt, under the given credentials only for network connections,
and suppress the UAC prompt mmc normally requires
- `shellevate /elevate mmc` - run MMC under the given credentials, and force MMC to be elevated to admin rights
- `shellevate /shell C:\document.txt` - open `C:\document.txt` under the given credentials using the default associated application

#Icon Credit
[nl2bricons @ thenounproject.com](https://thenounproject.com/nl2bricons/collection/terminal-cmd/?oq=shell&cidx=2&i=472620)
