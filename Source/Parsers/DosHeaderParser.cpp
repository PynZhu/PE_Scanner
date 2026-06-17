/**
 * @file DosHeaderParser.cpp
 * @brief DOS header parser implementation
 * @date 2026-06-17
 *
 * Implements IMAGE_DOS_HEADER parsing logic.
 * Validates MZ magic and extracts the e_lfanew field.
 */

#include "../../Include/Parsers/DosHeaderParser.h"
#include "../../Include/Core/Logger.h"
#include <sstream>
#include <iomanip>
#include <windows.h>

namespace PE {

// ============================================================================
// Constants
// ============================================================================

constexpr size_t DOS_HEADER_SIZE = sizeof(IMAGE_DOS_HEADER);  ///< DOS header size (64 bytes)
constexpr Word   MZ_MAGIC = 0x5A4D;                           ///< MZ magic ('MZ')
constexpr DWord  ELFANEW_ALIGNMENT = 4;                        ///< e_lfanew alignment requirement

// ============================================================================
// Constructor
// ============================================================================

CDosHeaderParser::CDosHeaderParser()
    : m_pFileData(nullptr)
    , m_fileSize(0)
    , m_lastError(EErrorCode::Success)
    , m_isInitialized(false)
    , m_isParsed(false)
{
    // Initialize DOS header info
    m_dosHeader.e_magic  = 0;
    m_dosHeader.e_lfanew = 0;
    m_dosHeader.isValid  = false;
}

// ============================================================================
// IParser Interface Implementation
// ============================================================================

bool CDosHeaderParser::Initialize(const uint8_t* pFileData, size_t fileSize)
{
    // Parameter validation
    if (pFileData == nullptr)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CDosHeaderParser::Initialize: file data pointer is null");
        return false;
    }

    if (fileSize == 0)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CDosHeaderParser::Initialize: file size is 0");
        return false;
    }

    m_pFileData = pFileData;
    m_fileSize  = fileSize;
    m_isInitialized = true;

    LOG_DEBUG_F("CDosHeaderParser::Initialize: initialized successfully (fileSize=%zu)", fileSize);
    return true;
}

bool CDosHeaderParser::Parse()
{
    // Check initialization state
    if (!m_isInitialized)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CDosHeaderParser::Parse: parser not initialized");
        return false;
    }

    // Check if file is large enough to contain DOS header
    if (m_fileSize < DOS_HEADER_SIZE)
    {
        m_lastError = EErrorCode::FileTooSmall;
        LOG_ERROR_F("CDosHeaderParser::Parse: file too small (%zu bytes), cannot contain DOS header (need %zu bytes)",
                     m_fileSize, DOS_HEADER_SIZE);
        return false;
    }

    // Get DOS header pointer
    const IMAGE_DOS_HEADER* pDosHeader =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(m_pFileData);

    // Validate MZ magic
    m_dosHeader.e_magic = pDosHeader->e_magic;
    if (pDosHeader->e_magic != MZ_MAGIC)
    {
        m_lastError = EErrorCode::ParserInvalidDosMagic;
        LOG_ERROR_F("CDosHeaderParser::Parse: invalid DOS magic (expected 0x%04X, actual 0x%04X)",
                     MZ_MAGIC, pDosHeader->e_magic);
        m_dosHeader.isValid = false;
        return false;
    }

    // Extract e_lfanew
    m_dosHeader.e_lfanew = pDosHeader->e_lfanew;

    // Validate e_lfanew
    // 1. Cannot be 0
    if (m_dosHeader.e_lfanew == 0)
    {
        m_lastError = EErrorCode::ParserInvalidELfanew;
        LOG_ERROR("CDosHeaderParser::Parse: e_lfanew is 0");
        m_dosHeader.isValid = false;
        return false;
    }

    // 2. Must be 4-byte aligned
    if (m_dosHeader.e_lfanew % ELFANEW_ALIGNMENT != 0)
    {
        m_lastError = EErrorCode::ParserInvalidELfanew;
        LOG_ERROR_F("CDosHeaderParser::Parse: e_lfanew not aligned (value=%u, alignment=%u)",
                     m_dosHeader.e_lfanew, ELFANEW_ALIGNMENT);
        m_dosHeader.isValid = false;
        return false;
    }

    // 3. Must not be out of bounds (NT header needs at least 4 bytes signature + sizeof(IMAGE_FILE_HEADER))
    constexpr DWord MIN_NT_HEADER_SIZE = sizeof(DWord) + sizeof(IMAGE_FILE_HEADER);
    if (m_dosHeader.e_lfanew + MIN_NT_HEADER_SIZE > m_fileSize)
    {
        m_lastError = EErrorCode::ParserInvalidELfanew;
        LOG_ERROR_F("CDosHeaderParser::Parse: e_lfanew out of bounds (value=%u, fileSize=%zu)",
                     m_dosHeader.e_lfanew, m_fileSize);
        m_dosHeader.isValid = false;
        return false;
    }

    // Parse succeeded
    m_dosHeader.isValid = true;
    m_isParsed = true;
    m_lastError = EErrorCode::Success;

    LOG_INFO_F("CDosHeaderParser::Parse: DOS header parsed successfully (e_lfanew=%u)", m_dosHeader.e_lfanew);
    return true;
}

std::string CDosHeaderParser::GetResult() const
{
    std::ostringstream json;
    json << "{"
         << "\"parser\":\"DosHeaderParser\","
         << "\"isValid\":" << (m_dosHeader.isValid ? "true" : "false") << ","
         << "\"e_magic\":\"0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
         << m_dosHeader.e_magic << "\","
         << "\"e_lfanew\":" << std::dec << m_dosHeader.e_lfanew
         << "}";
    return json.str();
}

EErrorCode CDosHeaderParser::GetLastError() const
{
    return m_lastError;
}

std::string CDosHeaderParser::GetErrorDescription() const
{
    return PE::GetErrorDescription(m_lastError);
}

const DosHeaderInfo& CDosHeaderParser::GetDosHeaderInfo() const
{
    return m_dosHeader;
}

} // namespace PE
