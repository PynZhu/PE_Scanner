/**
 * @file DangerousAPIs.cpp
 * @brief Dangerous API database implementation
 * @date 2026-06-17
 */

#include "../../Include/Rules/DangerousAPIs.h"
#include "../../Include/Core/Logger.h"

namespace PE {

CDangerousAPIs::CDangerousAPIs()
{
    Initialize();
}

CDangerousAPIs& CDangerousAPIs::GetInstance()
{
    static CDangerousAPIs instance;
    return instance;
}

void CDangerousAPIs::Initialize()
{
    LOG_DEBUG("CDangerousAPIs: Initializing dangerous API database");

    // ========================================================================
    // Remote Thread Injection APIs
    // ========================================================================
    m_apis.push_back({"VirtualAllocEx",       EApiCategory::RemoteThreadInjection, ERiskLevel::High,    "Allocates memory in a remote process"});
    m_apis.push_back({"VirtualProtectEx",     EApiCategory::RemoteThreadInjection, ERiskLevel::High,    "Changes memory protection in a remote process"});
    m_apis.push_back({"WriteProcessMemory",   EApiCategory::RemoteThreadInjection, ERiskLevel::High,    "Writes data to a remote process memory"});
    m_apis.push_back({"CreateRemoteThread",   EApiCategory::RemoteThreadInjection, ERiskLevel::Critical, "Creates a thread in a remote process"});
    m_apis.push_back({"NtCreateThreadEx",     EApiCategory::RemoteThreadInjection, ERiskLevel::Critical, "NT API for creating remote threads"});
    m_apis.push_back({"QueueUserAPC",         EApiCategory::RemoteThreadInjection, ERiskLevel::High,    "Queues an APC to a thread for code execution"});
    m_apis.push_back({"NtQueueApcThread",     EApiCategory::RemoteThreadInjection, ERiskLevel::High,    "NT API for queuing APC to a thread"});
    m_apis.push_back({"SetThreadContext",     EApiCategory::RemoteThreadInjection, ERiskLevel::High,    "Modifies thread context for code injection"});
    m_apis.push_back({"ResumeThread",         EApiCategory::RemoteThreadInjection, ERiskLevel::Medium,  "Resumes a suspended thread"});

    // ========================================================================
    // Process Operation APIs
    // ========================================================================
    m_apis.push_back({"CreateProcess",        EApiCategory::ProcessOperation, ERiskLevel::Medium, "Creates a new process"});
    m_apis.push_back({"CreateProcessAsUser",  EApiCategory::ProcessOperation, ERiskLevel::Medium, "Creates a process as a different user"});
    m_apis.push_back({"ShellExecute",         EApiCategory::ProcessOperation, ERiskLevel::Medium, "Executes a shell command"});
    m_apis.push_back({"ShellExecuteEx",       EApiCategory::ProcessOperation, ERiskLevel::Medium, "Executes a shell command (extended)"});
    m_apis.push_back({"WinExec",              EApiCategory::ProcessOperation, ERiskLevel::Medium, "Executes a program"});
    m_apis.push_back({"system",               EApiCategory::ProcessOperation, ERiskLevel::Medium, "Executes a system command"});
    m_apis.push_back({"popen",                EApiCategory::ProcessOperation, ERiskLevel::Medium, "Pipes output from a command"});

    // ========================================================================
    // Memory Operation APIs
    // ========================================================================
    m_apis.push_back({"ReadProcessMemory",    EApiCategory::MemoryOperation, ERiskLevel::Medium, "Reads memory from a remote process"});
    m_apis.push_back({"VirtualProtect",       EApiCategory::MemoryOperation, ERiskLevel::Medium, "Changes memory protection"});
    m_apis.push_back({"VirtualAlloc",         EApiCategory::MemoryOperation, ERiskLevel::Low,    "Allocates virtual memory"});
    m_apis.push_back({"HeapCreate",           EApiCategory::MemoryOperation, ERiskLevel::Low,    "Creates a heap"});
    m_apis.push_back({"NtUnmapViewOfSection", EApiCategory::MemoryOperation, ERiskLevel::High,   "Unmaps a view of a section (process hollowing)"});
    m_apis.push_back({"NtMapViewOfSection",   EApiCategory::MemoryOperation, ERiskLevel::High,   "Maps a view of a section"});

    // ========================================================================
    // Network Operation APIs
    // ========================================================================
    m_apis.push_back({"InternetOpen",         EApiCategory::NetworkOperation, ERiskLevel::Low,    "Opens an internet connection"});
    m_apis.push_back({"InternetOpenUrl",      EApiCategory::NetworkOperation, ERiskLevel::Medium, "Opens a URL for reading"});
    m_apis.push_back({"InternetConnect",      EApiCategory::NetworkOperation, ERiskLevel::Medium, "Connects to an internet resource"});
    m_apis.push_back({"HttpOpenRequest",      EApiCategory::NetworkOperation, ERiskLevel::Medium, "Opens an HTTP request"});
    m_apis.push_back({"HttpSendRequest",      EApiCategory::NetworkOperation, ERiskLevel::Medium, "Sends an HTTP request"});
    m_apis.push_back({"URLDownloadToFile",    EApiCategory::NetworkOperation, ERiskLevel::High,   "Downloads a file from a URL"});
    m_apis.push_back({"URLDownloadToCacheFile", EApiCategory::NetworkOperation, ERiskLevel::High, "Downloads to cache file"});
    m_apis.push_back({"WinHttpOpen",          EApiCategory::NetworkOperation, ERiskLevel::Low,    "Opens a WinHTTP session"});
    m_apis.push_back({"WinHttpConnect",       EApiCategory::NetworkOperation, ERiskLevel::Medium, "Connects via WinHTTP"});
    m_apis.push_back({"WinHttpOpenRequest",   EApiCategory::NetworkOperation, ERiskLevel::Medium, "Opens a WinHTTP request"});
    m_apis.push_back({"WinHttpSendRequest",   EApiCategory::NetworkOperation, ERiskLevel::Medium, "Sends a WinHTTP request"});
    m_apis.push_back({"socket",               EApiCategory::NetworkOperation, ERiskLevel::Low,    "Creates a socket"});
    m_apis.push_back({"connect",              EApiCategory::NetworkOperation, ERiskLevel::Low,    "Connects to a remote host"});
    m_apis.push_back({"send",                 EApiCategory::NetworkOperation, ERiskLevel::Low,    "Sends data over a socket"});
    m_apis.push_back({"recv",                 EApiCategory::NetworkOperation, ERiskLevel::Low,    "Receives data from a socket"});
    m_apis.push_back({"WSAStartup",           EApiCategory::NetworkOperation, ERiskLevel::Low,    "Initializes Winsock"});

    // ========================================================================
    // Registry Operation APIs
    // ========================================================================
    m_apis.push_back({"RegCreateKey",         EApiCategory::RegistryOperation, ERiskLevel::Medium, "Creates a registry key"});
    m_apis.push_back({"RegCreateKeyEx",       EApiCategory::RegistryOperation, ERiskLevel::Medium, "Creates a registry key (extended)"});
    m_apis.push_back({"RegSetValue",          EApiCategory::RegistryOperation, ERiskLevel::Medium, "Sets a registry value"});
    m_apis.push_back({"RegSetValueEx",        EApiCategory::RegistryOperation, ERiskLevel::Medium, "Sets a registry value (extended)"});
    m_apis.push_back({"RegDeleteKey",         EApiCategory::RegistryOperation, ERiskLevel::Medium, "Deletes a registry key"});
    m_apis.push_back({"RegDeleteValue",       EApiCategory::RegistryOperation, ERiskLevel::Medium, "Deletes a registry value"});

    // ========================================================================
    // Service Operation APIs
    // ========================================================================
    m_apis.push_back({"CreateService",        EApiCategory::ServiceOperation, ERiskLevel::High,   "Creates a Windows service"});
    m_apis.push_back({"StartService",         EApiCategory::ServiceOperation, ERiskLevel::High,   "Starts a Windows service"});
    m_apis.push_back({"OpenSCManager",        EApiCategory::ServiceOperation, ERiskLevel::Medium, "Opens the service control manager"});
    m_apis.push_back({"OpenService",          EApiCategory::ServiceOperation, ERiskLevel::Medium, "Opens a handle to a service"});
    m_apis.push_back({"ControlService",       EApiCategory::ServiceOperation, ERiskLevel::Medium, "Controls a service"});
    m_apis.push_back({"DeleteService",        EApiCategory::ServiceOperation, ERiskLevel::High,   "Deletes a Windows service"});

    // ========================================================================
    // Shellcode Execution APIs
    // ========================================================================
    m_apis.push_back({"EnumWindows",          EApiCategory::ShellcodeExecution, ERiskLevel::High,   "Can be used for shellcode execution via callbacks"});
    m_apis.push_back({"EnumDesktopWindows",   EApiCategory::ShellcodeExecution, ERiskLevel::High,   "Can be used for shellcode execution via callbacks"});
    m_apis.push_back({"EnumChildWindows",     EApiCategory::ShellcodeExecution, ERiskLevel::High,   "Can be used for shellcode execution via callbacks"});
    m_apis.push_back({"SetWindowsHookEx",     EApiCategory::ShellcodeExecution, ERiskLevel::High,   "Sets a Windows hook for code injection"});
    m_apis.push_back({"CreateThread",         EApiCategory::ShellcodeExecution, ERiskLevel::Medium, "Creates a thread"});
    m_apis.push_back({"RtlCreateUserThread",  EApiCategory::ShellcodeExecution, ERiskLevel::High,   "Creates a user-mode thread"});

    // ========================================================================
    // Anti-Debug APIs
    // ========================================================================
    m_apis.push_back({"IsDebuggerPresent",    EApiCategory::AntiDebug, ERiskLevel::Low,    "Checks if a debugger is attached"});
    m_apis.push_back({"CheckRemoteDebuggerPresent", EApiCategory::AntiDebug, ERiskLevel::Low,    "Checks for remote debugger"});
    m_apis.push_back({"NtQueryInformationProcess",  EApiCategory::AntiDebug, ERiskLevel::Low,    "Queries process information (debug port check)"});
    m_apis.push_back({"OutputDebugString",    EApiCategory::AntiDebug, ERiskLevel::Low,    "Outputs debug string (can detect debugger)"});

    LOG_INFO_F("CDangerousAPIs: Loaded %zu dangerous APIs", m_apis.size());
}

const DangerousApiInfo* CDangerousAPIs::FindApi(const std::string& apiName) const
{
    for (const auto& api : m_apis)
    {
        if (api.apiName == apiName)
        {
            return &api;
        }
    }
    return nullptr;
}

std::vector<DangerousApiInfo> CDangerousAPIs::GetApisByCategory(EApiCategory category) const
{
    std::vector<DangerousApiInfo> result;
    for (const auto& api : m_apis)
    {
        if (api.category == category)
        {
            result.push_back(api);
        }
    }
    return result;
}

const std::vector<DangerousApiInfo>& CDangerousAPIs::GetAllApis() const
{
    return m_apis;
}

std::string CDangerousAPIs::CategoryToString(EApiCategory category)
{
    switch (category)
    {
        case EApiCategory::RemoteThreadInjection: return "Remote Thread Injection";
        case EApiCategory::ProcessOperation:       return "Process Operation";
        case EApiCategory::MemoryOperation:        return "Memory Operation";
        case EApiCategory::NetworkOperation:       return "Network Operation";
        case EApiCategory::RegistryOperation:      return "Registry Operation";
        case EApiCategory::ServiceOperation:       return "Service Operation";
        case EApiCategory::ShellcodeExecution:     return "Shellcode Execution";
        case EApiCategory::AntiDebug:              return "Anti-Debug";
        default:                                   return "Unknown";
    }
}

} // namespace PE
