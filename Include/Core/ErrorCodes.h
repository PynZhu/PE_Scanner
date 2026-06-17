/**
 * @file ErrorCodes.h
 * @brief PE Static Sentinel error code definitions
 * @date 2026-06-17
 *
 * This file defines all possible error codes and their descriptions.
 * Error codes are organized into categories for quick issue identification.
 */

#pragma once

#include <string>
#include <cstdint>

namespace PE {

// ============================================================================
// Error Code Enumeration
// ============================================================================

/**
 * @brief Error code enumeration
 *
 * Encoding rules:
 * - 0xxx: General errors
 * - 1xxx: File operation errors
 * - 2xxx: Parser errors
 * - 3xxx: Analyzer errors
 * - 9xxx: Internal errors
 */
enum class EErrorCode : uint32_t
{
    // === Success ===
    Success                     = 0,        ///< Operation completed successfully

    // === General Errors (0xxx) ===
    Unknown                     = 1000,     ///< Unknown error
    NotImplemented              = 1001,     ///< Feature not implemented
    InvalidParameter            = 1002,     ///< Invalid parameter
    OutOfMemory                 = 1003,     ///< Out of memory
    InvalidState                = 1004,     ///< Invalid state (e.g., parsing before loading)

    // === File Operation Errors (1xxx) ===
    FileNotFound                = 2000,     ///< File does not exist
    FileAccessDenied            = 2001,     ///< File access denied
    FileTooSmall                = 2002,     ///< File too small to contain a valid PE header
    FileMappingFailed           = 2003,     ///< File mapping failed
    FileOpenFailed              = 2004,     ///< File open failed
    FileCreateMappingFailed     = 2005,     ///< Create file mapping failed
    FileMapViewFailed           = 2006,     ///< Map view of file failed
    FileTooLarge                = 2007,     ///< File too large to map

    // === Parser Errors (2xxx) ===
    ParserInitFailed            = 3000,     ///< Parser initialization failed
    ParserInvalidDosMagic       = 3001,     ///< Invalid DOS magic (not MZ)
    ParserInvalidELfanew        = 3002,     ///< Invalid e_lfanew value (out of bounds or unaligned)
    ParserInvalidPESignature    = 3003,     ///< Invalid PE signature (not PE\0\0)
    ParserInvalidFileHeader     = 3004,     ///< File header parsing failed
    ParserInvalidOptionalHeader = 3005,     ///< Optional header parsing failed
    ParserInvalidMagic          = 3006,     ///< Invalid optional header magic (not PE32 or PE32+)
    ParserUnsupportedArch       = 3007,     ///< Unsupported architecture

    // === Analyzer Errors (3xxx) ===
    AnalyzerInitFailed          = 4000,     ///< Analyzer initialization failed
    AnalyzerMissingParser       = 4001,     ///< Missing required parser dependency
    AnalyzerExecutionFailed     = 4002,     ///< Analyzer execution failed
    AnalysisFailed              = 4003,     ///< Analysis process failed

    // === Internal Errors (9xxx) ===
    InternalError               = 9000,     ///< Internal error
    InvalidCodePath             = 9001,     ///< Code path that should not be reached
};

// ============================================================================
// Error Code Utility Functions
// ============================================================================

/**
 * @brief Get the description string for an error code
 * @param errorCode The error code
 * @return Error description string (English)
 */
inline std::string GetErrorDescription(EErrorCode errorCode)
{
    switch (errorCode)
    {
        case EErrorCode::Success:
            return "Operation completed successfully";

        case EErrorCode::Unknown:
            return "Unknown error";
        case EErrorCode::NotImplemented:
            return "Feature not implemented";
        case EErrorCode::InvalidParameter:
            return "Invalid parameter";
        case EErrorCode::OutOfMemory:
            return "Out of memory";
        case EErrorCode::InvalidState:
            return "Invalid state";

        case EErrorCode::FileNotFound:
            return "File not found";
        case EErrorCode::FileAccessDenied:
            return "File access denied";
        case EErrorCode::FileTooSmall:
            return "File too small to contain a valid PE header";
        case EErrorCode::FileMappingFailed:
            return "File mapping failed";
        case EErrorCode::FileOpenFailed:
            return "File open failed";
        case EErrorCode::FileCreateMappingFailed:
            return "Create file mapping failed";
        case EErrorCode::FileMapViewFailed:
            return "Map view of file failed";
        case EErrorCode::FileTooLarge:
            return "File too large to map";

        case EErrorCode::ParserInitFailed:
            return "Parser initialization failed";
        case EErrorCode::ParserInvalidDosMagic:
            return "Invalid DOS magic (not MZ)";
        case EErrorCode::ParserInvalidELfanew:
            return "Invalid e_lfanew value (out of bounds or unaligned)";
        case EErrorCode::ParserInvalidPESignature:
            return "Invalid PE signature (not PE\\0\\0)";
        case EErrorCode::ParserInvalidFileHeader:
            return "File header parsing failed";
        case EErrorCode::ParserInvalidOptionalHeader:
            return "Optional header parsing failed";
        case EErrorCode::ParserInvalidMagic:
            return "Invalid optional header magic (not PE32 or PE32+)";
        case EErrorCode::ParserUnsupportedArch:
            return "Unsupported architecture";

        case EErrorCode::AnalyzerInitFailed:
            return "Analyzer initialization failed";
        case EErrorCode::AnalyzerMissingParser:
            return "Missing required parser dependency";
        case EErrorCode::AnalyzerExecutionFailed:
            return "Analyzer execution failed";
        case EErrorCode::AnalysisFailed:
            return "Analysis process failed";

        case EErrorCode::InternalError:
            return "Internal error";
        case EErrorCode::InvalidCodePath:
            return "Code path that should not be reached";

        default:
            return "Unknown error code";
    }
}

/**
 * @brief Get the name of an error code (for logging output)
 * @param errorCode The error code
 * @return Error code name string
 */
inline std::string GetErrorCodeName(EErrorCode errorCode)
{
    switch (errorCode)
    {
        case EErrorCode::Success:                   return "Success";
        case EErrorCode::Unknown:                   return "Unknown";
        case EErrorCode::NotImplemented:            return "NotImplemented";
        case EErrorCode::InvalidParameter:          return "InvalidParameter";
        case EErrorCode::OutOfMemory:               return "OutOfMemory";
        case EErrorCode::InvalidState:              return "InvalidState";
        case EErrorCode::FileNotFound:              return "FileNotFound";
        case EErrorCode::FileAccessDenied:          return "FileAccessDenied";
        case EErrorCode::FileTooSmall:              return "FileTooSmall";
        case EErrorCode::FileMappingFailed:         return "FileMappingFailed";
        case EErrorCode::FileOpenFailed:            return "FileOpenFailed";
        case EErrorCode::FileCreateMappingFailed:   return "FileCreateMappingFailed";
        case EErrorCode::FileMapViewFailed:         return "FileMapViewFailed";
        case EErrorCode::FileTooLarge:              return "FileTooLarge";
        case EErrorCode::ParserInitFailed:          return "ParserInitFailed";
        case EErrorCode::ParserInvalidDosMagic:     return "ParserInvalidDosMagic";
        case EErrorCode::ParserInvalidELfanew:      return "ParserInvalidELfanew";
        case EErrorCode::ParserInvalidPESignature:  return "ParserInvalidPESignature";
        case EErrorCode::ParserInvalidFileHeader:   return "ParserInvalidFileHeader";
        case EErrorCode::ParserInvalidOptionalHeader: return "ParserInvalidOptionalHeader";
        case EErrorCode::ParserInvalidMagic:        return "ParserInvalidMagic";
        case EErrorCode::ParserUnsupportedArch:     return "ParserUnsupportedArch";
        case EErrorCode::AnalyzerInitFailed:        return "AnalyzerInitFailed";
        case EErrorCode::AnalyzerMissingParser:     return "AnalyzerMissingParser";
        case EErrorCode::AnalyzerExecutionFailed:   return "AnalyzerExecutionFailed";
        case EErrorCode::AnalysisFailed:            return "AnalysisFailed";
        case EErrorCode::InternalError:             return "InternalError";
        case EErrorCode::InvalidCodePath:           return "InvalidCodePath";
        default:                                    return "UnknownErrorCode";
    }
}

} // namespace PE
