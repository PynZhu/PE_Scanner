/**
 * @file ScriptManager.cpp
 * @brief Duktape script manager implementation
 * @date 2026-06-17
 */

#include "../../Include/Signatures/ScriptManager.h"
#include "../../Include/Core/RiskLevel.h"
#include "../../Include/Utils/EntropyCalculator.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <chrono>

namespace fs = std::filesystem;

namespace PE {

// ============================================================================
// Context data passed to JS callbacks
// ============================================================================

struct ScriptContextData
{
    const PEInfo*   peInfo;
    const uint8_t*  fileData;
    size_t          fileSize;
};

// ============================================================================
// Forward declarations for Duktape function callbacks
// ============================================================================

static ScriptContextData* GetCtxData(duk_context* ctx);

static duk_ret_t js_pe_getEntryPoint(duk_context* ctx);
static duk_ret_t js_pe_getImageBase(duk_context* ctx);
static duk_ret_t js_pe_getFileSize(duk_context* ctx);
static duk_ret_t js_pe_getSectionCount(duk_context* ctx);
static duk_ret_t js_pe_getSection(duk_context* ctx);
static duk_ret_t js_pe_getImport(duk_context* ctx);
static duk_ret_t js_pe_readBytes(duk_context* ctx);
static duk_ret_t js_pe_getPEInfo(duk_context* ctx);
static duk_ret_t js_console_log(duk_context* ctx);
static duk_ret_t js_console_warn(duk_context* ctx);
static duk_ret_t js_console_error(duk_context* ctx);

// ============================================================================
// Constructor / Destructor
// ============================================================================

CScriptManager::CScriptManager()
    : m_ctx(nullptr)
    , m_pFileData(nullptr)
    , m_fileSize(0)
    , m_initialized(false)
{
    LOG_DEBUG("CScriptManager: Created");
}

CScriptManager::~CScriptManager()
{
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool CScriptManager::Initialize()
{
    if (m_initialized)
    {
        LOG_DEBUG("CScriptManager: Already initialized");
        return true;
    }

    // Create Duktape heap (context)
    m_ctx = duk_create_heap_default();
    if (m_ctx == nullptr)
    {
        m_lastError = "Failed to create Duktape heap";
        LOG_ERROR("CScriptManager: Failed to create Duktape heap");
        return false;
    }

    // Register 'pe' object
    if (!RegisterPEObj())
    {
        Shutdown();
        return false;
    }

    // Register 'console' object
    if (!RegisterConsoleObj())
    {
        Shutdown();
        return false;
    }

    m_initialized = true;
    LOG_INFO("CScriptManager: Duktape initialized successfully");
    return true;
}

void CScriptManager::Shutdown()
{
    if (m_ctx != nullptr)
    {
        duk_destroy_heap(m_ctx);
        m_ctx = nullptr;
    }

    m_scripts.clear();
    m_initialized = false;
    LOG_DEBUG("CScriptManager: Shutdown complete");
}

// ============================================================================
// PE Data
// ============================================================================

void CScriptManager::SetPEData(const uint8_t* pFileData, size_t fileSize,
                                const PEInfo& peInfo)
{
    m_pFileData = pFileData;
    m_fileSize  = fileSize;
    m_peInfo    = peInfo;

    // Store context data for JS callbacks using Duktape heap stash
    if (m_ctx != nullptr)
    {
        ScriptContextData* ctxData = new ScriptContextData();
        ctxData->peInfo   = &m_peInfo;
        ctxData->fileData = m_pFileData;
        ctxData->fileSize = m_fileSize;

        // Store pointer in heap stash so callbacks can retrieve it
        duk_push_heap_stash(m_ctx);
        duk_push_pointer(m_ctx, ctxData);
        duk_put_prop_string(m_ctx, -2, "\xFF" "ctxData");
        duk_pop(m_ctx);
    }
}

// ============================================================================
// Script Loading
// ============================================================================

int CScriptManager::LoadScriptsFromDirectory(const std::string& directory)
{
    if (!m_initialized)
    {
        m_lastError = "ScriptManager not initialized";
        LOG_ERROR("CScriptManager: LoadScriptsFromDirectory failed - not initialized");
        return -1;
    }

    if (!fs::exists(directory) || !fs::is_directory(directory))
    {
        m_lastError = "Directory does not exist: " + directory;
        LOG_ERROR_F("CScriptManager: Directory '%s' does not exist", directory.c_str());
        return -1;
    }

    int count = 0;
    try
    {
        for (const auto& entry : fs::recursive_directory_iterator(directory))
        {
            if (entry.is_regular_file())
            {
                std::string path = entry.path().string();
                if (path.size() >= 3 &&
                    path.substr(path.size() - 3) == ".js")
                {
                    if (LoadScript(path))
                    {
                        ++count;
                    }
                }
            }
        }
    }
    catch (const fs::filesystem_error& e)
    {
        m_lastError = "Filesystem error: " + std::string(e.what());
        LOG_ERROR_F("CScriptManager: Filesystem error: %s", e.what());
        return -1;
    }

    LOG_INFO_F("CScriptManager: Loaded %d scripts from '%s'", count, directory.c_str());
    return count;
}

bool CScriptManager::LoadScript(const std::string& filePath)
{
    if (!m_initialized)
    {
        m_lastError = "ScriptManager not initialized";
        return false;
    }

    std::string content = ReadFile(filePath);
    if (content.empty())
    {
        m_lastError = "Failed to read script file: " + filePath;
        LOG_ERROR_F("CScriptManager: Failed to read '%s'", filePath.c_str());
        return false;
    }

    // Extract filename from path
    std::string name = filePath;
    size_t pos = name.find_last_of("/\\");
    if (pos != std::string::npos)
    {
        name = name.substr(pos + 1);
    }

    ScriptFile script;
    script.name     = name;
    script.content  = content;
    script.filePath = filePath;
    m_scripts.push_back(script);

    LOG_DEBUG_F("CScriptManager: Loaded script '%s'", name.c_str());
    return true;
}

// ============================================================================
// Script Execution
// ============================================================================

std::vector<ScriptResult> CScriptManager::ExecuteAll()
{
    std::vector<ScriptResult> results;

    if (!m_initialized)
    {
        LOG_ERROR("CScriptManager: ExecuteAll failed - not initialized");
        return results;
    }

    for (const auto& script : m_scripts)
    {
        ScriptResult result = ExecuteScript(script.name);
        results.push_back(result);
    }

    return results;
}

ScriptResult CScriptManager::ExecuteScript(const std::string& scriptName)
{
    ScriptResult result;
    result.success = false;

    if (!m_initialized)
    {
        result.errorMessage = "ScriptManager not initialized";
        return result;
    }

    // Find the script
    auto it = std::find_if(m_scripts.begin(), m_scripts.end(),
        [&scriptName](const ScriptFile& s) { return s.name == scriptName; });

    if (it == m_scripts.end())
    {
        result.errorMessage = "Script not found: " + scriptName;
        return result;
    }

    result.scriptName = scriptName;

    // Evaluate the script using duk_peval_string (protected eval)
    if (duk_peval_string(m_ctx, it->content.c_str()) != 0)
    {
        // Error occurred during eval
        const char* errorStr = duk_safe_to_string(m_ctx, -1);
        result.errorMessage = errorStr ? errorStr : "Unknown script error";
        duk_pop(m_ctx);

        LOG_ERROR_F("CScriptManager: Script '%s' threw exception: %s",
                    scriptName.c_str(), result.errorMessage.c_str());
        return result;
    }
    duk_pop(m_ctx); // Pop eval result

    // Check if the script defined a 'run' function and call it
    duk_get_global_string(m_ctx, "run");

    if (duk_is_function(m_ctx, -1))
    {
        // Call the run function with no arguments
        if (duk_pcall(m_ctx, 0) != 0)
        {
            // Error occurred during run() call
            const char* errorStr = duk_safe_to_string(m_ctx, -1);
            result.errorMessage = errorStr ? errorStr : "Unknown error in run()";
            duk_pop(m_ctx);

            LOG_ERROR_F("CScriptManager: Script '%s' run() threw: %s",
                        scriptName.c_str(), result.errorMessage.c_str());
            return result;
        }

        // Parse the return value (should be an object)
        if (duk_is_object(m_ctx, -1))
        {
            // Get description
            duk_get_prop_string(m_ctx, -1, "description");
            if (duk_is_string(m_ctx, -1))
            {
                result.description = duk_to_string(m_ctx, -1);
            }
            duk_pop(m_ctx);

            // Get riskLevel
            duk_get_prop_string(m_ctx, -1, "riskLevel");
            if (duk_is_string(m_ctx, -1))
            {
                std::string risk = duk_to_string(m_ctx, -1);
                if (risk == "critical") result.riskLevel = ERiskLevel::Critical;
                else if (risk == "high") result.riskLevel = ERiskLevel::High;
                else if (risk == "medium") result.riskLevel = ERiskLevel::Medium;
                else if (risk == "low") result.riskLevel = ERiskLevel::Low;
                else result.riskLevel = ERiskLevel::None;
            }
            duk_pop(m_ctx);

            // Get details array
            duk_get_prop_string(m_ctx, -1, "details");
            if (duk_is_array(m_ctx, -1))
            {
                duk_size_t len = duk_get_length(m_ctx, -1);
                for (duk_size_t i = 0; i < len; ++i)
                {
                    duk_get_prop_index(m_ctx, -1, static_cast<duk_uarridx_t>(i));
                    if (duk_is_string(m_ctx, -1))
                    {
                        result.details.push_back(duk_to_string(m_ctx, -1));
                    }
                    duk_pop(m_ctx);
                }
            }
            duk_pop(m_ctx); // Pop details array
        }

        duk_pop(m_ctx); // Pop run() return value
    }
    else
    {
        // No run function - script executed successfully but no structured result
        result.description = "Script executed (no run() function)";
        result.riskLevel = ERiskLevel::None;
        duk_pop(m_ctx); // Pop undefined from duk_get_global_string
    }

    result.success = true;
    LOG_DEBUG_F("CScriptManager: Script '%s' executed successfully", scriptName.c_str());
    return result;
}

// ============================================================================
// JS Object Registration
// ============================================================================

bool CScriptManager::RegisterPEObj()
{
    // Create 'pe' object on the value stack
    duk_push_object(m_ctx);

    // Define methods using duk_put_prop_string with c functions
    duk_push_c_function(m_ctx, js_pe_getEntryPoint, 0);
    duk_put_prop_string(m_ctx, -2, "getEntryPoint");

    duk_push_c_function(m_ctx, js_pe_getImageBase, 0);
    duk_put_prop_string(m_ctx, -2, "getImageBase");

    duk_push_c_function(m_ctx, js_pe_getFileSize, 0);
    duk_put_prop_string(m_ctx, -2, "getFileSize");

    duk_push_c_function(m_ctx, js_pe_getSectionCount, 0);
    duk_put_prop_string(m_ctx, -2, "getSectionCount");

    duk_push_c_function(m_ctx, js_pe_getSection, 1);
    duk_put_prop_string(m_ctx, -2, "getSection");

    duk_push_c_function(m_ctx, js_pe_getImport, 1);
    duk_put_prop_string(m_ctx, -2, "getImport");

    duk_push_c_function(m_ctx, js_pe_readBytes, 2);
    duk_put_prop_string(m_ctx, -2, "readBytes");

    duk_push_c_function(m_ctx, js_pe_getPEInfo, 0);
    duk_put_prop_string(m_ctx, -2, "getPEInfo");

    // Set the 'pe' object as a property of the global object
    duk_put_global_string(m_ctx, "pe");

    LOG_DEBUG("CScriptManager: Registered 'pe' object");
    return true;
}

bool CScriptManager::RegisterConsoleObj()
{
    // Create 'console' object on the value stack
    duk_push_object(m_ctx);

    // Define methods
    duk_push_c_function(m_ctx, js_console_log, DUK_VARARGS);
    duk_put_prop_string(m_ctx, -2, "log");

    duk_push_c_function(m_ctx, js_console_warn, DUK_VARARGS);
    duk_put_prop_string(m_ctx, -2, "warn");

    duk_push_c_function(m_ctx, js_console_error, DUK_VARARGS);
    duk_put_prop_string(m_ctx, -2, "error");

    // Set the 'console' object as a property of the global object
    duk_put_global_string(m_ctx, "console");

    LOG_DEBUG("CScriptManager: Registered 'console' object");
    return true;
}

// ============================================================================
// Utility
// ============================================================================

std::string CScriptManager::ReadFile(const std::string& filePath)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        return "";
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string content;
    content.resize(static_cast<size_t>(size));
    file.read(&content[0], size);

    return content;
}

// ============================================================================
// Duktape Function Callbacks - 'pe' object
// ============================================================================

static ScriptContextData* GetCtxData(duk_context* ctx)
{
    duk_push_heap_stash(ctx);
    duk_get_prop_string(ctx, -1, "\xFF" "ctxData");
    ScriptContextData* data = static_cast<ScriptContextData*>(duk_get_pointer(ctx, -1));
    duk_pop_2(ctx);
    return data;
}

static duk_ret_t js_pe_getEntryPoint(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr || data->peInfo == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_push_uint(ctx, data->peInfo->ntHeaders.optionalHeader.addressOfEntryPoint);
    return 1;
}

static duk_ret_t js_pe_getImageBase(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr || data->peInfo == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_push_uint(ctx, static_cast<uint32_t>(data->peInfo->ntHeaders.optionalHeader.imageBase));
    return 1;
}

static duk_ret_t js_pe_getFileSize(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_push_uint(ctx, static_cast<uint32_t>(data->fileSize));
    return 1;
}

static duk_ret_t js_pe_getSectionCount(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr || data->peInfo == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_push_uint(ctx, static_cast<uint32_t>(data->peInfo->sections.size()));
    return 1;
}

static duk_ret_t js_pe_getSection(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr || data->peInfo == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_int_t index = duk_to_int(ctx, 0);

    if (index < 0 || static_cast<size_t>(index) >= data->peInfo->sections.size())
    {
        duk_push_undefined(ctx);
        return 1;
    }

    const auto& section = data->peInfo->sections[index];

    duk_push_object(ctx);
    duk_push_string(ctx, section.name.c_str());
    duk_put_prop_string(ctx, -2, "name");
    duk_push_uint(ctx, section.virtualAddress);
    duk_put_prop_string(ctx, -2, "virtualAddress");
    duk_push_uint(ctx, section.virtualSize);
    duk_put_prop_string(ctx, -2, "virtualSize");
    duk_push_uint(ctx, section.sizeOfRawData);
    duk_put_prop_string(ctx, -2, "rawSize");
    duk_push_number(ctx, section.entropy);
    duk_put_prop_string(ctx, -2, "entropy");
    duk_push_boolean(ctx, section.isReadable);
    duk_put_prop_string(ctx, -2, "isReadable");
    duk_push_boolean(ctx, section.isWritable);
    duk_put_prop_string(ctx, -2, "isWritable");
    duk_push_boolean(ctx, section.isExecutable);
    duk_put_prop_string(ctx, -2, "isExecutable");

    return 1;
}

static duk_ret_t js_pe_getImport(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr || data->peInfo == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    const char* dllName = duk_to_string(ctx, 0);
    if (dllName == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_push_array(ctx);
    duk_uarridx_t idx = 0;

    for (const auto& dll : data->peInfo->imports)
    {
        // Case-insensitive comparison
        std::string dllLower = dll.dllName;
        std::string searchLower = dllName;
        std::transform(dllLower.begin(), dllLower.end(), dllLower.begin(), ::tolower);
        std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(), ::tolower);

        if (dllLower.find(searchLower) != std::string::npos)
        {
            for (const auto& func : dll.functions)
            {
                duk_push_object(ctx);
                if (func.isOrdinal)
                {
                    duk_push_string(ctx, ("ORDINAL_" + std::to_string(func.ordinal)).c_str());
                    duk_put_prop_string(ctx, -2, "name");
                    duk_push_int(ctx, func.ordinal);
                    duk_put_prop_string(ctx, -2, "ordinal");
                }
                else
                {
                    duk_push_string(ctx, func.name.c_str());
                    duk_put_prop_string(ctx, -2, "name");
                }
                duk_push_boolean(ctx, func.isOrdinal);
                duk_put_prop_string(ctx, -2, "isOrdinal");
                duk_put_prop_index(ctx, -2, idx++);
            }
        }
    }

    return 1;
}

static duk_ret_t js_pe_readBytes(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr || data->fileData == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    duk_uint_t offset = duk_to_uint(ctx, 0);
    duk_uint_t count = duk_to_uint(ctx, 1);

    if (static_cast<size_t>(offset + count) > data->fileSize || count == 0)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    // Push a fixed buffer and then create a buffer object (Uint8Array-like)
    void* buf = duk_push_fixed_buffer(ctx, count);
    memcpy(buf, data->fileData + offset, count);

    // Create a Uint8Array view over the buffer
    duk_push_buffer_object(ctx, -1, 0, count, DUK_BUFOBJ_UINT8ARRAY);

    // Replace the buffer with the typed array view
    duk_replace(ctx, -2);

    return 1;
}

static duk_ret_t js_pe_getPEInfo(duk_context* ctx)
{
    ScriptContextData* data = GetCtxData(ctx);
    if (data == nullptr || data->peInfo == nullptr)
    {
        duk_push_undefined(ctx);
        return 1;
    }

    const PEInfo& pe = *data->peInfo;

    duk_push_object(ctx);

    duk_push_uint(ctx, static_cast<uint32_t>(pe.fileSize));
    duk_put_prop_string(ctx, -2, "fileSize");

    duk_push_boolean(ctx, pe.isPE32Plus);
    duk_put_prop_string(ctx, -2, "isPE32Plus");

    duk_push_uint(ctx, pe.ntHeaders.optionalHeader.addressOfEntryPoint);
    duk_put_prop_string(ctx, -2, "entryPoint");

    duk_push_uint(ctx, static_cast<uint32_t>(pe.ntHeaders.optionalHeader.imageBase));
    duk_put_prop_string(ctx, -2, "imageBase");

    duk_push_uint(ctx, pe.ntHeaders.fileHeader.numberOfSections);
    duk_put_prop_string(ctx, -2, "numberOfSections");

    duk_push_uint(ctx, pe.ntHeaders.optionalHeader.sizeOfImage);
    duk_put_prop_string(ctx, -2, "sizeOfImage");

    duk_push_uint(ctx, pe.ntHeaders.optionalHeader.sizeOfHeaders);
    duk_put_prop_string(ctx, -2, "sizeOfHeaders");

    duk_push_uint(ctx, pe.ntHeaders.optionalHeader.checkSum);
    duk_put_prop_string(ctx, -2, "checksum");

    duk_push_uint(ctx, pe.ntHeaders.optionalHeader.subsystem);
    duk_put_prop_string(ctx, -2, "subsystem");

    return 1;
}

// ============================================================================
// Duktape Function Callbacks - 'console' object
// ============================================================================

static duk_ret_t js_console_log(duk_context* ctx)
{
    duk_idx_t nargs = duk_get_top(ctx);
    for (duk_idx_t i = 0; i < nargs; ++i)
    {
        const char* str = duk_to_string(ctx, i);
        if (str != nullptr)
        {
            LOG_INFO_F("[JS] %s", str);
        }
    }
    return 0;
}

static duk_ret_t js_console_warn(duk_context* ctx)
{
    duk_idx_t nargs = duk_get_top(ctx);
    for (duk_idx_t i = 0; i < nargs; ++i)
    {
        const char* str = duk_to_string(ctx, i);
        if (str != nullptr)
        {
            LOG_WARNING_F("[JS] %s", str);
        }
    }
    return 0;
}

static duk_ret_t js_console_error(duk_context* ctx)
{
    duk_idx_t nargs = duk_get_top(ctx);
    for (duk_idx_t i = 0; i < nargs; ++i)
    {
        const char* str = duk_to_string(ctx, i);
        if (str != nullptr)
        {
            LOG_ERROR_F("[JS] %s", str);
        }
    }
    return 0;
}

} // namespace PE
