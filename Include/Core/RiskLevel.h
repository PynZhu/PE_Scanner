/**
 * @file RiskLevel.h
 * @brief Risk level utility functions for security analysis
 * @date 2026-06-17
 *
 * Provides utility functions for working with ERiskLevel enum values.
 * The ERiskLevel enum itself is defined in Types.h.
 */

#pragma once

#include "Types.h"
#include <string>

namespace PE {

/**
 * @brief Convert risk level to human-readable string
 * @param level Risk level value
 * @return std::string String representation (e.g. "High")
 */
inline std::string RiskLevelToString(ERiskLevel level)
{
    switch (level)
    {
        case ERiskLevel::None:     return "None";
        case ERiskLevel::Low:      return "Low";
        case ERiskLevel::Medium:   return "Medium";
        case ERiskLevel::High:     return "High";
        case ERiskLevel::Critical: return "Critical";
        default:                   return "Unknown";
    }
}

/**
 * @brief Convert risk level to display symbol
 * @param level Risk level value
 * @return const char* Symbol string
 */
inline const char* RiskLevelToSymbol(ERiskLevel level)
{
    switch (level)
    {
        case ERiskLevel::None:     return "[SAFE]";
        case ERiskLevel::Low:      return "[LOW]";
        case ERiskLevel::Medium:   return "[MEDIUM]";
        case ERiskLevel::High:     return "[HIGH]";
        case ERiskLevel::Critical: return "[CRITICAL]";
        default:                   return "[UNKNOWN]";
    }
}

} // namespace PE
