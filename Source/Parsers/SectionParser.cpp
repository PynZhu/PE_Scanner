/**
 * @file SectionParser.cpp
 * @brief Section table parser implementation
 * @date 2026-06-17
 *
 * Implements IMAGE_SECTION_HEADER array parsing logic.
 * Iterates through all sections, extracts detailed information, and calculates entropy.
 */

#include "../../Include/Parsers/SectionParser.h"
#include "../../Include/Core/Logger.h"
#include "../../Include/Utils/EntropyCalculator.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <windows.h>

namespace PE {

// ============================================================================
// Constants
// ============================================================================

constexpr size_t SECTION_NAME_LENGTH = 8;  ///< Section name length (IMAGE_SIZEOF_SHORT_NAME)

// ============================================================================
// Constructor
// ============================================================================

CSectionParser::CSectionParser()
    : m_pFileData(nullptr)
    , m_fileSize(0)
    , m_numberOfSections(0)
    , m_sizeOfOptionalHeader(0)
    , m_sectionAlignment(0)
    , m_hasNtHeadersInfo(false)
    , m_lastError(EErrorCode::Success)
    , m_isInitialized(false)
    , m_isParsed(false)
{
}

// ============================================================================
// IParser Interface Implementation
// ============================================================================

bool CSectionParser::Initialize(const uint8_t* pFileData, size_t fileSize)
{
    if (pFileData == nullptr)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CSectionParser::Initialize: file data pointer is null");
        return false;
    }

    if (fileSize == 0)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CSectionParser::Initialize: file size is 0");
        return false;
    }

    m_pFileData = pFileData;
    m_fileSize  = fileSize;
    m_isInitialized = true;

    LOG_DEBUG_F("CSectionParser::Initialize: initialized successfully (fileSize=%zu)", fileSize);
    return true;
}

void CSectionParser::SetNtHeadersInfo(Word numberOfSections, Word sizeOfOptionalHeader,
                                       DWord sectionAlignment)
{
    m_numberOfSections     = numberOfSections;
    m_sizeOfOptionalHeader = sizeOfOptionalHeader;
    m_sectionAlignment     = sectionAlignment;
    m_hasNtHeadersInfo     = true;
}

bool CSectionParser::Parse()
{
    // Check initialization state
    if (!m_isInitialized)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CSectionParser::Parse: parser not initialized");
        return false;
    }

    // Check if NT headers info has been set
    if (!m_hasNtHeadersInfo)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CSectionParser::Parse: NT headers info not set, please call SetNtHeadersInfo() first");
        return false;
    }

    // Check section count
    if (m_numberOfSections == 0)
    {
        LOG_WARNING("CSectionParser::Parse: no sections in file");
        m_isParsed = true;
        return true;
    }

    // Calculate section table start position
    // NT header start = e_lfanew (provided externally, assuming already positioned at NT header)
    // Section table start = NT header start + 4 (signature) + sizeof(IMAGE_FILE_HEADER) + SizeOfOptionalHeader
    // But we don't know e_lfanew, so we need to calculate from file start
    // Actually, section table follows immediately after the optional header
    // Since we don't know e_lfanew, we use a simplified method:
    // Read DOS header from file start to get e_lfanew
    if (m_fileSize < sizeof(IMAGE_DOS_HEADER))
    {
        m_lastError = EErrorCode::FileTooSmall;
        LOG_ERROR("CSectionParser::Parse: file too small to read DOS header");
        return false;
    }

    const IMAGE_DOS_HEADER* pDosHeader =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(m_pFileData);
    DWord e_lfanew = pDosHeader->e_lfanew;

    // Calculate section table offset
    // NT header = e_lfanew
    // File header = NT header + 4 (signature)
    // Optional header = File header + sizeof(IMAGE_FILE_HEADER)
    // Section table = Optional header + SizeOfOptionalHeader
    DWord sectionTableOffset = e_lfanew
        + sizeof(DWord)                       // PE signature
        + sizeof(IMAGE_FILE_HEADER)           // File header
        + m_sizeOfOptionalHeader;             // Optional header

    // Check if section table is out of bounds
    size_t sectionTableSize = static_cast<size_t>(m_numberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (static_cast<size_t>(sectionTableOffset) + sectionTableSize > m_fileSize)
    {
        m_lastError = EErrorCode::ParserInvalidFileHeader;
        LOG_ERROR_F("CSectionParser::Parse: section table exceeds file bounds (offset=%u, size=%zu, fileSize=%zu)",
                     sectionTableOffset, sectionTableSize, m_fileSize);
        return false;
    }

    // Locate section table
    const IMAGE_SECTION_HEADER* pSectionHeaders =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(m_pFileData + sectionTableOffset);

    // Clear previous parse results
    m_sections.clear();
    m_sections.reserve(m_numberOfSections);

    // Iterate through all sections
    for (Word i = 0; i < m_numberOfSections; ++i)
    {
        const IMAGE_SECTION_HEADER* pSection = &pSectionHeaders[i];
        SectionHeaderInfo info;

        // Parse section name
        info.name = CleanSectionName(reinterpret_cast<const char*>(pSection->Name));

        // Parse basic fields
        info.virtualSize          = pSection->Misc.VirtualSize;
        info.virtualAddress       = pSection->VirtualAddress;
        info.sizeOfRawData        = pSection->SizeOfRawData;
        info.pointerToRawData     = pSection->PointerToRawData;
        info.pointerToRelocations = pSection->PointerToRelocations;
        info.pointerToLinenumbers = pSection->PointerToLinenumbers;
        info.numberOfRelocations  = pSection->NumberOfRelocations;
        info.numberOfLinenumbers  = pSection->NumberOfLinenumbers;
        info.characteristics      = pSection->Characteristics;

        // Parse characteristic flags
        ParseCharacteristics(pSection->Characteristics, info);

        // Calculate entropy
        if (info.sizeOfRawData > 0 && info.pointerToRawData > 0)
        {
            // Check if raw data is within file bounds
            if (static_cast<size_t>(info.pointerToRawData) + info.sizeOfRawData <= m_fileSize)
            {
                const uint8_t* pSectionData = m_pFileData + info.pointerToRawData;
                info.entropy = CEntropyCalculator::CalculateEntropy(pSectionData, info.sizeOfRawData);
            }
            else
            {
                // Data exceeds file bounds, mark as invalid
                info.entropy = 0.0f;
                LOG_WARNING_F("CSectionParser::Parse: section '%s' data exceeds file bounds",
                              info.name.c_str());
            }
        }
        else
        {
            // No raw data (e.g., BSS section)
            info.entropy = 0.0f;
        }

        info.isValid = true;
        m_sections.push_back(info);

        LOG_DEBUG_F("CSectionParser::Parse: section '%s' (VA=0x%08X, Size=%u, Entropy=%.2f)",
                     info.name.c_str(), info.virtualAddress, info.sizeOfRawData, info.entropy);
    }

    m_isParsed = true;
    m_lastError = EErrorCode::Success;

    LOG_INFO_F("CSectionParser::Parse: section table parsed successfully (%u sections)", m_numberOfSections);
    return true;
}

// ============================================================================
// Characteristic Parsing
// ============================================================================

void CSectionParser::ParseCharacteristics(DWord characteristics, SectionHeaderInfo& info)
{
    // IMAGE_SCN_MEM_EXECUTE = 0x20000000
    info.isExecutable = (characteristics & 0x20000000) != 0;

    // IMAGE_SCN_MEM_READ = 0x40000000
    info.isReadable = (characteristics & 0x40000000) != 0;

    // IMAGE_SCN_MEM_WRITE = 0x80000000
    info.isWritable = (characteristics & 0x80000000) != 0;
}

// ============================================================================
// Name Cleaning
// ============================================================================

std::string CSectionParser::CleanSectionName(const char* rawName) const
{
    // Section name is an 8-byte fixed-length field, may not be null-terminated
    // Find the first null or space position
    size_t len = 0;
    while (len < SECTION_NAME_LENGTH && rawName[len] != '\0' && rawName[len] != ' ')
    {
        ++len;
    }
    return std::string(rawName, len);
}

// ============================================================================
// Result Retrieval
// ============================================================================

std::string CSectionParser::GetResult() const
{
    std::ostringstream json;
    json << "{"
         << "\"parser\":\"SectionParser\","
         << "\"sectionCount\":" << m_sections.size() << ","
         << "\"sections\":[";

    for (size_t i = 0; i < m_sections.size(); ++i)
    {
        if (i > 0)
        {
            json << ",";
        }

        const auto& sec = m_sections[i];
        json << "{"
             << "\"name\":\"" << sec.name << "\","
             << "\"virtualAddress\":\"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
             << sec.virtualAddress << "\","
             << "\"virtualSize\":" << std::dec << sec.virtualSize << ","
             << "\"sizeOfRawData\":" << sec.sizeOfRawData << ","
             << "\"pointerToRawData\":" << sec.pointerToRawData << ","
             << "\"characteristics\":\"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
             << sec.characteristics << "\","
             << "\"isExecutable\":" << (sec.isExecutable ? "true" : "false") << ","
             << "\"isReadable\":" << (sec.isReadable ? "true" : "false") << ","
             << "\"isWritable\":" << (sec.isWritable ? "true" : "false") << ","
             << "\"entropy\":" << std::fixed << std::setprecision(4) << sec.entropy
             << "}";
    }

    json << "]}";
    return json.str();
}

EErrorCode CSectionParser::GetLastError() const
{
    return m_lastError;
}

std::string CSectionParser::GetErrorDescription() const
{
    return PE::GetErrorDescription(m_lastError);
}

const std::vector<SectionHeaderInfo>& CSectionParser::GetSections() const
{
    return m_sections;
}

} // namespace PE
