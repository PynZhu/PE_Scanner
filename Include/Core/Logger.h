/**
 * @file Logger.h
 * @brief PE Static Sentinel logging system
 * @date 2026-06-17
 *
 * This file defines the logging system macros and function declarations.
 * The logging system supports multi-level output and automatically includes
 * timestamps and source file location information.
 */

#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <windows.h>

namespace PE {

// ============================================================================
// Log Level Enumeration
// ============================================================================

/**
 * @brief Log level enumeration
 */
enum class ELogLevel : uint8_t
{
    Debug     = 0,  ///< Debug information
    Info      = 1,  ///< General information
    Warning   = 2,  ///< Warning
    Error     = 3,  ///< Error
    Fatal     = 4   ///< Fatal error
};

// ============================================================================
// Logger Class
// ============================================================================

/**
 * @brief Logger class (Singleton)
 *
 * Provides global unified log output functionality.
 * Supports setting log level; logs below the set level will be filtered out.
 */
class CLogger
{
public:
    /**
     * @brief Get the global logger instance
     * @return CLogger& Reference to the logger instance
     */
    static CLogger& GetInstance();

    /**
     * @brief Set the log level
     * @param level Minimum output level
     */
    void SetLevel(ELogLevel level);

    /**
     * @brief Get the current log level
     * @return ELogLevel Current log level
     */
    ELogLevel GetLevel() const;

    /**
     * @brief Output a log message
     * @param level Log level
     * @param file Source file name (automatically passed by macro)
     * @param line Line number (automatically passed by macro)
     * @param message Log message
     */
    void Log(ELogLevel level, const char* file, int line, const std::string& message);

    /**
     * @brief Output a formatted log message
     * @param level Log level
     * @param file Source file name (automatically passed by macro)
     * @param line Line number (automatically passed by macro)
     * @param format Format string
     * @param ... Variable arguments
     */
    void LogFormat(ELogLevel level, const char* file, int line, const char* format, ...);

private:
    CLogger();
    ~CLogger();
    CLogger(const CLogger&) = delete;
    CLogger& operator=(const CLogger&) = delete;

    /**
     * @brief Get the log level prefix string
     * @param level Log level
     * @return Prefix string (e.g. "[ERROR]")
     */
    static const char* LevelToString(ELogLevel level);

    /**
     * @brief Get the current timestamp string
     * @return Formatted timestamp
     */
    static std::string GetTimestamp();

    ELogLevel m_currentLevel;  ///< Current log level
};

} // namespace PE

// ============================================================================
// Log Macros
// ============================================================================

/**
 * @def LOG_DEBUG
 * @brief Output debug log
 */
#define LOG_DEBUG(msg) \
    PE::CLogger::GetInstance().Log(PE::ELogLevel::Debug, __FILE__, __LINE__, msg)

/**
 * @def LOG_INFO
 * @brief Output info log
 */
#define LOG_INFO(msg) \
    PE::CLogger::GetInstance().Log(PE::ELogLevel::Info, __FILE__, __LINE__, msg)

/**
 * @def LOG_WARNING
 * @brief Output warning log
 */
#define LOG_WARNING(msg) \
    PE::CLogger::GetInstance().Log(PE::ELogLevel::Warning, __FILE__, __LINE__, msg)

/**
 * @def LOG_ERROR
 * @brief Output error log
 */
#define LOG_ERROR(msg) \
    PE::CLogger::GetInstance().Log(PE::ELogLevel::Error, __FILE__, __LINE__, msg)

/**
 * @def LOG_FATAL
 * @brief Output fatal error log
 */
#define LOG_FATAL(msg) \
    PE::CLogger::GetInstance().Log(PE::ELogLevel::Fatal, __FILE__, __LINE__, msg)

/**
 * @def LOG_DEBUG_F
 * @brief Output formatted debug log
 */
#define LOG_DEBUG_F(fmt, ...) \
    PE::CLogger::GetInstance().LogFormat(PE::ELogLevel::Debug, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @def LOG_INFO_F
 * @brief Output formatted info log
 */
#define LOG_INFO_F(fmt, ...) \
    PE::CLogger::GetInstance().LogFormat(PE::ELogLevel::Info, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @def LOG_WARNING_F
 * @brief Output formatted warning log
 */
#define LOG_WARNING_F(fmt, ...) \
    PE::CLogger::GetInstance().LogFormat(PE::ELogLevel::Warning, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @def LOG_ERROR_F
 * @brief Output formatted error log
 */
#define LOG_ERROR_F(fmt, ...) \
    PE::CLogger::GetInstance().LogFormat(PE::ELogLevel::Error, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @def LOG_FATAL_F
 * @brief Output formatted fatal error log
 */
#define LOG_FATAL_F(fmt, ...) \
    PE::CLogger::GetInstance().LogFormat(PE::ELogLevel::Fatal, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
