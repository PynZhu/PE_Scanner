/**
 * @file ScriptManager.h
 * @brief Duktape script manager for PE security analysis
 * @date 2026-06-17
 *
 * Manages JavaScript-based signature scripts using Duktape.
 * Loads .js files from a directory, executes them in a sandboxed
 * environment, and collects analysis results.
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include "../Core/Types.h"
#include "../Core/Logger.h"

// Duktape header doesn't have extern "C" guards
#ifdef __cplusplus
extern "C" {
#endif
#include <duktape.h>
#ifdef __cplusplus
}
#endif

namespace PE {

/**
 * @brief Result from a single script execution
 */
struct ScriptResult
{
    std::string scriptName;       ///< Script file name
    std::string description;      ///< Result description
    ERiskLevel  riskLevel;        ///< Risk level determined by script
    std::vector<std::string> details; ///< Detailed findings
    bool        success;          ///< Whether script executed successfully
    std::string errorMessage;     ///< Error message if execution failed
};

/**
 * @brief Duktape script manager
 *
 * Initializes a Duktape heap, loads .js signature scripts from
 * a specified directory, and executes them against PE file data.
 * Provides a 'pe' object and 'console' object to JavaScript code.
 */
class CScriptManager
{
public:
    CScriptManager();
    ~CScriptManager();

    // Non-copyable
    CScriptManager(const CScriptManager&) = delete;
    CScriptManager& operator=(const CScriptManager&) = delete;

    /**
     * @brief Initialize the Duktape heap
     * @return true if initialization succeeded
     */
    bool Initialize();

    /**
     * @brief Set the PE file data for scripts to access
     * @param pFileData Pointer to mapped file data
     * @param fileSize Size of the file data
     * @param peInfo Parsed PE information
     */
    void SetPEData(const uint8_t* pFileData, size_t fileSize, const PEInfo& peInfo);

    /**
     * @brief Load all .js scripts from a directory (recursive)
     * @param directory Path to the scripts directory
     * @return Number of scripts loaded, or -1 on error
     */
    int LoadScriptsFromDirectory(const std::string& directory);

    /**
     * @brief Load a single .js script file
     * @param filePath Path to the script file
     * @return true if loaded successfully
     */
    bool LoadScript(const std::string& filePath);

    /**
     * @brief Execute all loaded scripts
     * @return std::vector<ScriptResult> Results from all scripts
     */
    std::vector<ScriptResult> ExecuteAll();

    /**
     * @brief Execute a single script by name
     * @param scriptName Name of the script to execute
     * @return ScriptResult Result of the execution
     */
    ScriptResult ExecuteScript(const std::string& scriptName);

    /**
     * @brief Get the number of loaded scripts
     * @return size_t Script count
     */
    size_t GetScriptCount() const { return m_scripts.size(); }

    /**
     * @brief Check if the manager is initialized
     * @return true if initialized
     */
    bool IsInitialized() const { return m_initialized; }

    /**
     * @brief Get the last error message
     * @return std::string Error description
     */
    std::string GetLastError() const { return m_lastError; }

    /**
     * @brief Shutdown and free all Duktape resources
     */
    void Shutdown();

private:
    /**
     * @brief Register the 'pe' object in the Duktape context
     */
    bool RegisterPEObj();

    /**
     * @brief Register the 'console' object in the Duktape context
     */
    bool RegisterConsoleObj();

    /**
     * @brief Read a file into a string
     * @param filePath Path to the file
     * @return std::string File contents, empty on error
     */
    std::string ReadFile(const std::string& filePath);

    struct ScriptFile
    {
        std::string name;     ///< Script name (filename without path)
        std::string content;  ///< Script source code
        std::string filePath; ///< Full path to the script file
    };

    duk_context*                m_ctx;          ///< Duktape context (heap handle)
    std::vector<ScriptFile>     m_scripts;      ///< Loaded scripts
    const uint8_t*              m_pFileData;    ///< Mapped file data pointer
    size_t                      m_fileSize;     ///< File data size
    PEInfo                      m_peInfo;       ///< Parsed PE information
    bool                        m_initialized;  ///< Initialization flag
    std::string                 m_lastError;    ///< Last error message
};

} // namespace PE
