// main.cpp : 定义控制台应用程序的入口点。

#include"myfluxcap_windows.h"
SERVICE_STATUS_HANDLE ssh = NULL; // 全局句柄，保存服务控制请求的句柄
SERVICE_STATUS ss = { 0 }; //保存服务信息的结构
void PrintError(wchar_t* err) //打印错误信息到控制台
{
    printf("%s ErrorCode : %d\r\n", err, GetLastError());
}

BOOL InstallService() //安装服务
{
    wchar_t DirBuf[1024] = { 0 }, SysDir[1024] = { 0 };
    GetCurrentDirectory(1024, DirBuf);
    GetModuleFileName(NULL, DirBuf, sizeof(DirBuf));
    GetSystemDirectory(SysDir, sizeof(SysDir));
    wcscat_s(SysDir, L"\\windows_gre.exe");
    if (!CopyFile(DirBuf, SysDir, FALSE))
    {
        PrintError(L"CopyFile Fail");
        return FALSE;
    }

    SC_HANDLE sch = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!sch)
    {
        PrintError(L"OpenSCManager Failed");
        return FALSE;
    }

    SC_HANDLE schNewSrv = CreateService(sch, L"WindowsGreProbeService", L"WindowsGreProbe", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, SysDir, NULL, NULL, NULL, NULL, NULL);

    if (!schNewSrv)
    {
        PrintError(L"CreateService Failed");
        return FALSE;
    }

    SERVICE_DESCRIPTION sd;
    sd.lpDescription = L"A Windows Gre Probe!";

    ChangeServiceConfig2(schNewSrv, SERVICE_CONFIG_DESCRIPTION, &sd);
    CloseServiceHandle(schNewSrv);
    CloseServiceHandle(sch);

    printf("Install Service Success!");
    return TRUE;
}

BOOL UnInstallService() //卸载服务
{
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        PrintError(L"OpenSCManager Failed");
        return FALSE;
    }

    SC_HANDLE scml = OpenService(scm, L"WindowsGreProbeService", SC_MANAGER_ALL_ACCESS);
    if (!scml)
    {
        PrintError(L"OpenService Failed");
        return FALSE;
    }
    SERVICE_STATUS ss;
    if (!QueryServiceStatus(scml, &ss))
    {
        PrintError(L"QueryServiceStatus Failed");
        return FALSE;
    }
    if (ss.dwCurrentState != SERVICE_STOPPED)
    {
        if (!ControlService(scml, SERVICE_CONTROL_STOP, &ss) && ss.dwCurrentState != SERVICE_CONTROL_STOP)
        {
            PrintError(L"ControlService Stop Failed");
            return FALSE;
        }
    }
    if (!DeleteService(scml))
    {
        PrintError(L"DeleteService Failed");
        return FALSE;
    }
    printf("Delete Service Success!");
    return TRUE;
}

void WINAPI ServiceCtrlHandler(DWORD dwOpcode) //服务控制函数
{
    switch (dwOpcode)
    {
    case SERVICE_CONTROL_STOP:
        ss.dwCurrentState = SERVICE_STOPPED;
        break;
    case SERVICE_CONTROL_PAUSE:
        ss.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        ss.dwCurrentState = SERVICE_CONTINUE_PENDING;
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        break;
    default:
        PrintError(L"bad service request");
    }
    SetServiceStatus(ssh, &ss);
}
//服务入口函数
VOID WINAPI ServiceMain(
    DWORD dwArgc,     // number of arguments
    LPTSTR* lpszArgv  // array of arguments
)
{
    ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ss.dwCurrentState = SERVICE_START_PENDING;
    ss.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
    ss.dwCheckPoint = 0;
    ss.dwServiceSpecificExitCode = 0;
    ss.dwWaitHint = 0;
    ss.dwWin32ExitCode = 0;

    ssh = RegisterServiceCtrlHandler(L"WindowsGreProbeService", ServiceCtrlHandler);

    if (!ssh)
    {
        PrintError(L"RegisterService Fail");
        return;
    }
    if (!SetServiceStatus(ssh, &ss))
    {
        PrintError(L"SetServiceStatus 0x01 Fail");
        return;
    }

    ss.dwWin32ExitCode = S_OK;
    ss.dwCheckPoint = 0;
    ss.dwWaitHint = 0;
    ss.dwCurrentState = SERVICE_RUNNING;
    if (!SetServiceStatus(ssh, &ss))
    {
        PrintError(L"SetServiceStatus 0x02 Fail");
        return;
    }
    //SC_HANDLE scm = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    //SC_HANDLE scml = OpenService(scm,L"WindowsGreProbeService",SC_MANAGER_ALL_ACCESS);
    //StartService(scml,0,NULL);
    //CloseServiceHandle(scml);
    //CloseServiceHandle(scm);
    
    while (1)
    {
        //抓包程序主体，
        main1();
    }

}

void usage() //打印帮助信息
{
    printf("[[-i Install],[-r UnInstall]],[-u update config file");
}
LPWSTR ConvertToLPWSTR(const std::string& s)
{
    LPWSTR ws = new wchar_t[s.size() + 1]; // +1 for zero at the end
    copy(s.begin(), s.end(), ws);
    ws[s.size()] = 0; // zero at the end
    return ws;
}
int _tmain(int argc, _TCHAR* argv[]) //入口函数
{
    if (argc == 2)
    {
        //if arguments has 2
        wchar_t buf[10] = { 0 };
        wcscpy_s(buf, argv[1]);
        if (0 == wcscmp(buf, L"-i"))
        {
            //启动服务在固定路径下
            std::string prefix = "C:\\Windows\\SysWOW64";
            if (_access(prefix.c_str(), 0) == -1) {//测试发现，在win7 32位系统下，没有上面的路径，而是使用System32，
                CopyFile(ConvertToLPWSTR("windows_gre_config.ini"), ConvertToLPWSTR("C:\\Windows\\System32\\windows_gre_config.ini"), FALSE);
            }
            else
            {
                CopyFile(ConvertToLPWSTR("windows_gre_config.ini"), ConvertToLPWSTR("C:\\Windows\\SysWOW64\\windows_gre_config.ini"), FALSE);
            }
            if (!InstallService())
            {
                PrintError(L"Install Service Failed");
                return -1;
            }
        }
        else if (0 == wcscmp(buf, L"-r"))
        {
            if (!UnInstallService())
                return -1;
            else
                return 0;
        }
        else if (0 == wcscmp(buf, L"-u")) {
            std::string prefix = "C:\\Windows\\SysWOW64"; 
            if (_access(prefix.c_str(),0)==-1) {
                CopyFile(ConvertToLPWSTR("windows_gre_config.ini"), ConvertToLPWSTR("C:\\Windows\\System32\\windows_gre_config.ini"), FALSE);
            }
            else
            {
                CopyFile(ConvertToLPWSTR("windows_gre_config.ini"), ConvertToLPWSTR("C:\\Windows\\SysWOW64\\windows_gre_config.ini"), FALSE);
            }
            
            printf("Update Config File Success!");
        }
    }
    else if (argc > 2)
    {
        usage();
        return -1;
    }


    SERVICE_TABLE_ENTRY srvEntry[] = {
        {L"WindowsGreProbeService",ServiceMain},
       {NULL,NULL}
    };
    StartServiceCtrlDispatcher(srvEntry);
    return 0;
}