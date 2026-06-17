/**
 * @file Logger.cpp
 * @brief PE Static Sentinel logging system implementation
 * @date 2026-06-17
 */

#include "../../Include/Core/Logger.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <cstdarg>

namespace PE {

// ============================================================================
// CLogger Implementation
// ============================================================================

CLogger::CLogger()
    : m_currentLevel(ELogLevel::Info)
{
}

CLogger::~CLogger()
{
}

CLogger& CLogger::GetInstance()
{
    static CLogger instance;
    return instance;
}

void CLogger::SetLevel(ELogLevel level)
{
    m_currentLevel = level;
}

ELogLevel CLogger::GetLevel() const
{
    return m_currentLevel;
}

void CLogger::Log(ELogLevel level, const char* file, int line, const std::string& message)
{
    // Filter out logs below current level
    if (level < m_currentLevel)
    {
        return;
    }

    // Build log output
    std::ostringstream oss;
    oss << GetTimestamp() << " "
        << LevelToString(level) << " "
        << "[" << file << ":" << line << "] "
        << message;

    // Output to console
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Set color based on log level
    WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // White (default)
    switch (level)
    {
        case ELogLevel::Debug:
            color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Bright green
            break;
        case ELogLevel::Info:
            color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // White
            break;
        case ELogLevel::Warning:
            color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // Yellow
            break;
        case ELogLevel::Error:
            color = FOREGROUND_RED | FOREGROUND_INTENSITY; // Bright red
            break;
        case ELogLevel::Fatal:
            color = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // Bright purple
            break;
    }

    SetConsoleTextAttribute(hConsole, color);
    std::cout << oss.str() << std::endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // Also output to stderr for fatal errors
    if (level >= ELogLevel::Error)
    {
        std::cerr << oss.str() << std::endl;
    }
}

void CLogger::LogFormat(ELogLevel level, const char* file, int line, const char* format, ...)
{
    // Filter out logs below current level
    if (level < m_currentLevel)
    {
        return;
    }

    va_list args;
    va_start(args, format);

    // Calculate required buffer size
    int size = _vscprintf(format, args);
    if (size < 0)
    {
        va_end(args);
        return;
    }

    // Allocate buffer and format
    std::string buffer(size, '\0');
    vsnprintf_s(&buffer[0], size + 1, size, format, args);
    va_end(args);

    Log(level, file, line, buffer);
}

const char* CLogger::LevelToString(ELogLevel level)
{
    switch (level)
    {
        case ELogLevel::Debug:   return "[DEBUG]";
        case ELogLevel::Info:    return "[INFO] ";
        case ELogLevel::Warning: return "[WARN] ";
        case ELogLevel::Error:   return "[ERROR]";
        case ELogLevel::Fatal:   return "[FATAL]";
        default:                 return "[UNKWN]";
    }
}

std::string CLogger::GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm localTime;
    localtime_s(&localTime, &timeT);

    std::ostringstream oss;
    oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

} // namespace PE
