/**
 * @file NtHeadersParser.cpp
 * @brief NT headers parser implementation
 * @date 2026-06-17
 *
 * Implements IMAGE_NT_HEADERS parsing logic.
 * Includes PE signature validation, file header parsing, and optional header parsing (PE32/PE32+).
 */

#include "../../Include/Parsers/NtHeadersParser.h"
#include "../../Include/Core/Logger.h"
#include <sstream>
#include <iomanip>
#include <windows.h>

namespace PE {

// ============================================================================
// Constants
// ============================================================================

constexpr DWord PE_SIGNATURE     = 0x00004550;  ///< PE signature "PE\0\0"
constexpr Word  PE32_MAGIC       = 0x10B;       ///< PE32 optional header magic
constexpr Word  PE32_PLUS_MAGIC  = 0x20B;       ///< PE32+ optional header magic

// ============================================================================
// Constructor
// ============================================================================

CNtHeadersParser::CNtHeadersParser()
    : m_pFileData(nullptr)
    , m_fileSize(0)
    , m_e_lfanew(0)
    , m_lastError(EErrorCode::Success)
    , m_isInitialized(false)
    , m_isParsed(false)
    , m_hasELfanew(false)
{
    m_ntHeaders.signature    = 0;
    m_ntHeaders.isValid      = false;
    m_ntHeaders.fileHeader.isValid      = false;
    m_ntHeaders.optionalHeader.isValid  = false;
}

// ============================================================================
// IParser Interface Implementation
// ============================================================================

bool CNtHeadersParser::Initialize(const uint8_t* pFileData, size_t fileSize)
{
    if (pFileData == nullptr)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CNtHeadersParser::Initialize: file data pointer is null");
        return false;
    }

    if (fileSize == 0)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CNtHeadersParser::Initialize: file size is 0");
        return false;
    }

    m_pFileData = pFileData;
    m_fileSize  = fileSize;
    m_isInitialized = true;

    LOG_DEBUG_F("CNtHeadersParser::Initialize: initialized successfully (fileSize=%zu)", fileSize);
    return true;
}

void CNtHeadersParser::SetELfanew(DWord e_lfanew)
{
    m_e_lfanew = e_lfanew;
    m_hasELfanew = true;
}

bool CNtHeadersParser::Parse()
{
    // Check initialization state
    if (!m_isInitialized)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CNtHeadersParser::Parse: parser not initialized");
        return false;
    }

    // Check if e_lfanew has been set
    if (!m_hasELfanew)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CNtHeadersParser::Parse: e_lfanew not set, please call SetELfanew() first");
        return false;
    }

    // Check if e_lfanew is out of bounds
    if (m_e_lfanew >= m_fileSize)
    {
        m_lastError = EErrorCode::ParserInvalidELfanew;
        LOG_ERROR_F("CNtHeadersParser::Parse: e_lfanew out of bounds (value=%u, fileSize=%zu)",
                     m_e_lfanew, m_fileSize);
        return false;
    }

    // Check if remaining space is enough for PE signature
    if (m_e_lfanew + sizeof(DWord) > m_fileSize)
    {
        m_lastError = EErrorCode::ParserInvalidPESignature;
        LOG_ERROR("CNtHeadersParser::Parse: insufficient space at e_lfanew to read PE signature");
        return false;
    }

    // Locate NT headers start position
    const uint8_t* pNtHeader = m_pFileData + m_e_lfanew;

    // Validate PE signature
    const DWORD* pSignature = reinterpret_cast<const DWORD*>(pNtHeader);
    m_ntHeaders.signature = *pSignature;

    if (*pSignature != PE_SIGNATURE)
    {
        m_lastError = EErrorCode::ParserInvalidPESignature;
        LOG_ERROR_F("CNtHeadersParser::Parse: invalid PE signature (expected 0x%08X, actual 0x%08X)",
                     PE_SIGNATURE, *pSignature);
        m_ntHeaders.isValid = false;
        return false;
    }

    // Locate IMAGE_FILE_HEADER
    const IMAGE_FILE_HEADER* pFileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(pNtHeader + sizeof(DWord));

    // Check if file header is out of bounds
    if (reinterpret_cast<const uint8_t*>(pFileHeader + 1) > m_pFileData + m_fileSize)
    {
        m_lastError = EErrorCode::ParserInvalidFileHeader;
        LOG_ERROR("CNtHeadersParser::Parse: file header exceeds file bounds");
        m_ntHeaders.isValid = false;
        return false;
    }

    // Parse file header
    if (!ParseFileHeader(pFileHeader))
    {
        m_ntHeaders.isValid = false;
        return false;
    }

    // Locate IMAGE_OPTIONAL_HEADER
    const uint8_t* pOptionalHeader = reinterpret_cast<const uint8_t*>(pFileHeader + 1);

    // Check if optional header is out of bounds
    if (pOptionalHeader + m_ntHeaders.fileHeader.sizeOfOptionalHeader > m_pFileData + m_fileSize)
    {
        m_lastError = EErrorCode::ParserInvalidOptionalHeader;
        LOG_ERROR("CNtHeadersParser::Parse: optional header exceeds file bounds");
        m_ntHeaders.isValid = false;
        return false;
    }

    // Determine PE32 or PE32+ based on optional header size
    if (m_ntHeaders.fileHeader.sizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        // Try PE32+
        const IMAGE_OPTIONAL_HEADER64* pOpt64 =
            reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(pOptionalHeader);

        if (pOpt64->Magic == PE32_PLUS_MAGIC)
        {
            if (!ParseOptionalHeader64(pOpt64))
            {
                m_ntHeaders.isValid = false;
                return false;
            }
        }
        else if (pOpt64->Magic == PE32_MAGIC)
        {
            // Fall back to PE32
            const IMAGE_OPTIONAL_HEADER32* pOpt32 =
                reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(pOptionalHeader);
            if (!ParseOptionalHeader32(pOpt32))
            {
                m_ntHeaders.isValid = false;
                return false;
            }
        }
        else
        {
            m_lastError = EErrorCode::ParserInvalidMagic;
            LOG_ERROR_F("CNtHeadersParser::Parse: invalid optional header magic (0x%04X)", pOpt64->Magic);
            m_ntHeaders.isValid = false;
            return false;
        }
    }
    else if (m_ntHeaders.fileHeader.sizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        const IMAGE_OPTIONAL_HEADER32* pOpt32 =
            reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(pOptionalHeader);

        if (pOpt32->Magic == PE32_MAGIC)
        {
            if (!ParseOptionalHeader32(pOpt32))
            {
                m_ntHeaders.isValid = false;
                return false;
            }
        }
        else
        {
            m_lastError = EErrorCode::ParserInvalidMagic;
            LOG_ERROR_F("CNtHeadersParser::Parse: invalid optional header magic (0x%04X)", pOpt32->Magic);
            m_ntHeaders.isValid = false;
            return false;
        }
    }
    else
    {
        m_lastError = EErrorCode::ParserInvalidOptionalHeader;
        LOG_ERROR_F("CNtHeadersParser::Parse: abnormal optional header size (%u bytes)",
                     m_ntHeaders.fileHeader.sizeOfOptionalHeader);
        m_ntHeaders.isValid = false;
        return false;
    }

    // Parse succeeded
    m_ntHeaders.isValid = true;
    m_isParsed = true;
    m_lastError = EErrorCode::Success;

    LOG_INFO("CNtHeadersParser::Parse: NT headers parsed successfully");
    return true;
}

// ============================================================================
// File Header Parsing
// ============================================================================

bool CNtHeadersParser::ParseFileHeader(const IMAGE_FILE_HEADER* pFileHeader)
{
    m_ntHeaders.fileHeader.machine              = pFileHeader->Machine;
    m_ntHeaders.fileHeader.numberOfSections     = pFileHeader->NumberOfSections;
    m_ntHeaders.fileHeader.timeDateStamp        = pFileHeader->TimeDateStamp;
    m_ntHeaders.fileHeader.pointerToSymbolTable = pFileHeader->PointerToSymbolTable;
    m_ntHeaders.fileHeader.numberOfSymbols      = pFileHeader->NumberOfSymbols;
    m_ntHeaders.fileHeader.sizeOfOptionalHeader = pFileHeader->SizeOfOptionalHeader;
    m_ntHeaders.fileHeader.characteristics      = pFileHeader->Characteristics;

    // Validate NumberOfSections
    if (pFileHeader->NumberOfSections == 0 || pFileHeader->NumberOfSections > 96)
    {
        m_lastError = EErrorCode::ParserInvalidFileHeader;
        LOG_ERROR_F("CNtHeadersParser::ParseFileHeader: abnormal section count (%u)",
                     pFileHeader->NumberOfSections);
        m_ntHeaders.fileHeader.isValid = false;
        return false;
    }

    // Validate SizeOfOptionalHeader
    if (pFileHeader->SizeOfOptionalHeader == 0)
    {
        m_lastError = EErrorCode::ParserInvalidFileHeader;
        LOG_ERROR("CNtHeadersParser::ParseFileHeader: SizeOfOptionalHeader is 0");
        m_ntHeaders.fileHeader.isValid = false;
        return false;
    }

    m_ntHeaders.fileHeader.isValid = true;
    return true;
}

// ============================================================================
// Optional Header Parsing (PE32)
// ============================================================================

bool CNtHeadersParser::ParseOptionalHeader32(const IMAGE_OPTIONAL_HEADER32* pOptionalHeader)
{
    m_ntHeaders.optionalHeader.magic                    = pOptionalHeader->Magic;
    m_ntHeaders.optionalHeader.majorLinkerVersion       = pOptionalHeader->MajorLinkerVersion;
    m_ntHeaders.optionalHeader.minorLinkerVersion       = pOptionalHeader->MinorLinkerVersion;
    m_ntHeaders.optionalHeader.sizeOfCode               = pOptionalHeader->SizeOfCode;
    m_ntHeaders.optionalHeader.sizeOfInitializedData    = pOptionalHeader->SizeOfInitializedData;
    m_ntHeaders.optionalHeader.sizeOfUninitializedData  = pOptionalHeader->SizeOfUninitializedData;
    m_ntHeaders.optionalHeader.addressOfEntryPoint      = pOptionalHeader->AddressOfEntryPoint;
    m_ntHeaders.optionalHeader.baseOfCode               = pOptionalHeader->BaseOfCode;
    m_ntHeaders.optionalHeader.imageBase                = pOptionalHeader->ImageBase;
    m_ntHeaders.optionalHeader.sectionAlignment         = pOptionalHeader->SectionAlignment;
    m_ntHeaders.optionalHeader.fileAlignment            = pOptionalHeader->FileAlignment;
    m_ntHeaders.optionalHeader.majorOperatingSystemVersion = pOptionalHeader->MajorOperatingSystemVersion;
    m_ntHeaders.optionalHeader.minorOperatingSystemVersion = pOptionalHeader->MinorOperatingSystemVersion;
    m_ntHeaders.optionalHeader.majorImageVersion        = pOptionalHeader->MajorImageVersion;
    m_ntHeaders.optionalHeader.minorImageVersion        = pOptionalHeader->MinorImageVersion;
    m_ntHeaders.optionalHeader.majorSubsystemVersion    = pOptionalHeader->MajorSubsystemVersion;
    m_ntHeaders.optionalHeader.minorSubsystemVersion    = pOptionalHeader->MinorSubsystemVersion;
    m_ntHeaders.optionalHeader.sizeOfImage              = pOptionalHeader->SizeOfImage;
    m_ntHeaders.optionalHeader.sizeOfHeaders            = pOptionalHeader->SizeOfHeaders;
    m_ntHeaders.optionalHeader.checkSum                 = pOptionalHeader->CheckSum;
    m_ntHeaders.optionalHeader.subsystem                = pOptionalHeader->Subsystem;
    m_ntHeaders.optionalHeader.dllCharacteristics      = pOptionalHeader->DllCharacteristics;

    m_ntHeaders.optionalHeader.isValid = true;

    LOG_DEBUG_F("CNtHeadersParser::ParseOptionalHeader32: PE32 optional header parsed successfully "
                "(EntryPoint=0x%08X, ImageBase=0x%08X)",
                pOptionalHeader->AddressOfEntryPoint,
                pOptionalHeader->ImageBase);
    return true;
}

// ============================================================================
// Optional Header Parsing (PE32+)
// ============================================================================

bool CNtHeadersParser::ParseOptionalHeader64(const IMAGE_OPTIONAL_HEADER64* pOptionalHeader64)
{
    m_ntHeaders.optionalHeader.magic                    = pOptionalHeader64->Magic;
    m_ntHeaders.optionalHeader.majorLinkerVersion       = pOptionalHeader64->MajorLinkerVersion;
    m_ntHeaders.optionalHeader.minorLinkerVersion       = pOptionalHeader64->MinorLinkerVersion;
    m_ntHeaders.optionalHeader.sizeOfCode               = pOptionalHeader64->SizeOfCode;
    m_ntHeaders.optionalHeader.sizeOfInitializedData    = pOptionalHeader64->SizeOfInitializedData;
    m_ntHeaders.optionalHeader.sizeOfUninitializedData  = pOptionalHeader64->SizeOfUninitializedData;
    m_ntHeaders.optionalHeader.addressOfEntryPoint      = pOptionalHeader64->AddressOfEntryPoint;
    m_ntHeaders.optionalHeader.baseOfCode               = pOptionalHeader64->BaseOfCode;
    m_ntHeaders.optionalHeader.imageBase                = pOptionalHeader64->ImageBase;
    m_ntHeaders.optionalHeader.sectionAlignment         = pOptionalHeader64->SectionAlignment;
    m_ntHeaders.optionalHeader.fileAlignment            = pOptionalHeader64->FileAlignment;
    m_ntHeaders.optionalHeader.majorOperatingSystemVersion = pOptionalHeader64->MajorOperatingSystemVersion;
    m_ntHeaders.optionalHeader.minorOperatingSystemVersion = pOptionalHeader64->MinorOperatingSystemVersion;
    m_ntHeaders.optionalHeader.majorImageVersion        = pOptionalHeader64->MajorImageVersion;
    m_ntHeaders.optionalHeader.minorImageVersion        = pOptionalHeader64->MinorImageVersion;
    m_ntHeaders.optionalHeader.majorSubsystemVersion    = pOptionalHeader64->MajorSubsystemVersion;
    m_ntHeaders.optionalHeader.minorSubsystemVersion    = pOptionalHeader64->MinorSubsystemVersion;
    m_ntHeaders.optionalHeader.sizeOfImage              = pOptionalHeader64->SizeOfImage;
    m_ntHeaders.optionalHeader.sizeOfHeaders            = pOptionalHeader64->SizeOfHeaders;
    m_ntHeaders.optionalHeader.checkSum                 = pOptionalHeader64->CheckSum;
    m_ntHeaders.optionalHeader.subsystem                = pOptionalHeader64->Subsystem;
    m_ntHeaders.optionalHeader.dllCharacteristics      = pOptionalHeader64->DllCharacteristics;

    // PE32+ does not have BaseOfData field
    m_ntHeaders.optionalHeader.isValid = true;

    LOG_DEBUG_F("CNtHeadersParser::ParseOptionalHeader64: PE32+ optional header parsed successfully "
                "(EntryPoint=0x%08X, ImageBase=0x%016llX)",
                pOptionalHeader64->AddressOfEntryPoint,
                pOptionalHeader64->ImageBase);
    return true;
}

// ============================================================================
// Result Retrieval
// ============================================================================

std::string CNtHeadersParser::GetResult() const
{
    std::ostringstream json;
    json << "{"
         << "\"parser\":\"NtHeadersParser\","
         << "\"isValid\":" << (m_ntHeaders.isValid ? "true" : "false") << ","
         << "\"signature\":\"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
         << m_ntHeaders.signature << "\","
         << "\"fileHeader\":{"
         << "\"machine\":\"0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
         << m_ntHeaders.fileHeader.machine << "\","
         << "\"numberOfSections\":" << std::dec << m_ntHeaders.fileHeader.numberOfSections << ","
         << "\"sizeOfOptionalHeader\":" << m_ntHeaders.fileHeader.sizeOfOptionalHeader << ","
         << "\"characteristics\":\"0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
         << m_ntHeaders.fileHeader.characteristics << "\""
         << "},"
         << "\"optionalHeader\":{"
         << "\"magic\":\"0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
         << m_ntHeaders.optionalHeader.magic << "\","
         << "\"addressOfEntryPoint\":\"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
         << m_ntHeaders.optionalHeader.addressOfEntryPoint << "\","
         << "\"imageBase\":\"0x" << std::hex << std::uppercase
         << m_ntHeaders.optionalHeader.imageBase << "\","
         << "\"sizeOfImage\":" << std::dec << m_ntHeaders.optionalHeader.sizeOfImage << ","
         << "\"sizeOfHeaders\":" << m_ntHeaders.optionalHeader.sizeOfHeaders << ","
         << "\"checkSum\":\"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
         << m_ntHeaders.optionalHeader.checkSum << "\","
         << "\"subsystem\":" << std::dec << m_ntHeaders.optionalHeader.subsystem
         << "}"
         << "}";
    return json.str();
}

EErrorCode CNtHeadersParser::GetLastError() const
{
    return m_lastError;
}

std::string CNtHeadersParser::GetErrorDescription() const
{
    return PE::GetErrorDescription(m_lastError);
}

const NtHeadersInfo& CNtHeadersParser::GetNtHeadersInfo() const
{
    return m_ntHeaders;
}

} // namespace PE
