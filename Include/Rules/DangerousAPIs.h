/**
 * @file DangerousAPIs.h
 * @brief Dangerous API definitions for security analysis
 * @date 2026-06-17
 *
 * Defines known dangerous Windows APIs grouped by category.
 * Used by the rule engine to detect potentially malicious API usage.
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "../Core/RiskLevel.h"

namespace PE {

/**
 * @brief API category enumeration
 */
enum class EApiCategory : uint8_t
{
    RemoteThreadInjection,  ///< Remote thread injection APIs
    ProcessOperation,       ///< Process manipulation APIs
    MemoryOperation,        ///< Memory manipulation APIs
    NetworkOperation,       ///< Network communication APIs
    RegistryOperation,      ///< Registry manipulation APIs
    ServiceOperation,       ///< Windows service APIs
    ShellcodeExecution,     ///< Shellcode execution APIs
    AntiDebug,              ///< Anti-debugging APIs
    Unknown                 ///< Uncategorized
};

/**
 * @brief Dangerous API descriptor
 */
struct DangerousApiInfo
{
    std::string   apiName;       ///< API function name
    EApiCategory  category;      ///< API category
    ERiskLevel    riskLevel;     ///< Base risk level for this API
    std::string   description;   ///< Description of why this API is dangerous
};

/**
 * @brief Dangerous API database
 *
 * Maintains a categorized list of known dangerous Windows APIs.
 * Provides lookup functionality by API name or DLL name.
 */
class CDangerousAPIs
{
public:
    /**
     * @brief Get the singleton instance
     * @return CDangerousAPIs& Reference to the instance
     */
    static CDangerousAPIs& GetInstance();

    /**
     * @brief Check if an API is in the dangerous list
     * @param apiName The API function name to check
     * @return const DangerousApiInfo* Pointer to API info, or nullptr if not found
     */
    const DangerousApiInfo* FindApi(const std::string& apiName) const;

    /**
     * @brief Get all APIs in a specific category
     * @param category The category to filter by
     * @return std::vector<DangerousApiInfo> List of APIs in the category
     */
    std::vector<DangerousApiInfo> GetApisByCategory(EApiCategory category) const;

    /**
     * @brief Get all dangerous APIs
     * @return const std::vector<DangerousApiInfo>& Full list of dangerous APIs
     */
    const std::vector<DangerousApiInfo>& GetAllApis() const;

    /**
     * @brief Get the category name as a string
     * @param category The category enum value
     * @return std::string Human-readable category name
     */
    static std::string CategoryToString(EApiCategory category);

private:
    CDangerousAPIs();
    ~CDangerousAPIs() = default;
    CDangerousAPIs(const CDangerousAPIs&) = delete;
    CDangerousAPIs& operator=(const CDangerousAPIs&) = delete;

    /**
     * @brief Initialize the dangerous API database
     */
    void Initialize();

    std::vector<DangerousApiInfo> m_apis;  ///< Full list of dangerous APIs
};

} // namespace PE
