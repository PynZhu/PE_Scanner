/**
 * @file ExportTableParser.cpp
 * @brief Export table parser implementation
 * @date 2026-06-17
 *
 * Implements IMAGE_EXPORT_DIRECTORY parsing logic.
 * Extracts exported function names, ordinals, and forwarder address information.
 */

#include "../../Include/Parsers/ExportTableParser.h"
#include "../../Include/Core/Logger.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <windows.h>

namespace PE {

// ============================================================================
// Constructor
// ============================================================================

CExportTableParser::CExportTableParser()
    : m_pFileData(nullptr)
    , m_fileSize(0)
    , m_dataDirectoryRVA(0)
    , m_dataDirectorySize(0)
    , m_hasNtHeadersInfo(false)
    , m_lastError(EErrorCode::Success)
    , m_isInitialized(false)
    , m_isParsed(false)
{
}

// ============================================================================
// IParser Interface Implementation
// ============================================================================

bool CExportTableParser::Initialize(const uint8_t* pFileData, size_t fileSize)
{
    if (pFileData == nullptr)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CExportTableParser::Initialize: file data pointer is null");
        return false;
    }

    if (fileSize == 0)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CExportTableParser::Initialize: file size is 0");
        return false;
    }

    m_pFileData = pFileData;
    m_fileSize  = fileSize;
    m_isInitialized = true;

    LOG_DEBUG_F("CExportTableParser::Initialize: initialized successfully (fileSize=%zu)", fileSize);
    return true;
}

void CExportTableParser::SetNtHeadersInfo(DWord dataDirectoryRVA, DWord dataDirectorySize)
{
    m_dataDirectoryRVA  = dataDirectoryRVA;
    m_dataDirectorySize = dataDirectorySize;
    m_hasNtHeadersInfo  = true;
}

bool CExportTableParser::Parse()
{
    // Check initialization state
    if (!m_isInitialized)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CExportTableParser::Parse: parser not initialized");
        return false;
    }

    // Check if NT headers info has been set
    if (!m_hasNtHeadersInfo)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CExportTableParser::Parse: NT headers info not set, please call SetNtHeadersInfo() first");
        return false;
    }

    // Clear previous parse results
    m_exports.clear();

    // Check if export table data directory is valid
    if (m_dataDirectoryRVA == 0 || m_dataDirectorySize == 0)
    {
        LOG_WARNING("CExportTableParser::Parse: no export table in file");
        m_isParsed = true;
        return true;
    }

    // Convert export table RVA to file offset
    DWord exportTableOffset = RvaToFileOffset(m_dataDirectoryRVA);
    if (exportTableOffset == 0)
    {
        LOG_WARNING("CExportTableParser::Parse: unable to convert export table RVA to file offset");
        m_isParsed = true;
        return true;
    }

    // Check if export table is within file bounds
    if (static_cast<size_t>(exportTableOffset) + sizeof(IMAGE_EXPORT_DIRECTORY) > m_fileSize)
    {
        LOG_WARNING("CExportTableParser::Parse: export table exceeds file bounds");
        m_isParsed = true;
        return true;
    }

    // Locate export table
    const IMAGE_EXPORT_DIRECTORY* pExportDir =
        reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(m_pFileData + exportTableOffset);

    // Get export table basic info
    DWord numberOfFunctions  = pExportDir->NumberOfFunctions;
    DWord numberOfNames      = pExportDir->NumberOfNames;
    DWord addressOfFunctions = pExportDir->AddressOfFunctions;
    DWord addressOfNames     = pExportDir->AddressOfNames;
    DWord addressOfNameOrdinals = pExportDir->AddressOfNameOrdinals;
    DWord baseOrdinal        = pExportDir->Base;

    LOG_DEBUG_F("CExportTableParser::Parse: export table info (Functions=%u, Names=%u, Base=%u)",
                numberOfFunctions, numberOfNames, baseOrdinal);

    // Check if there are exported functions
    if (numberOfFunctions == 0)
    {
        LOG_WARNING("CExportTableParser::Parse: no functions in export table");
        m_isParsed = true;
        return true;
    }

    // Convert address table offsets
    DWord funcAddrOffset = RvaToFileOffset(addressOfFunctions);
    DWord nameAddrOffset = RvaToFileOffset(addressOfNames);
    DWord ordinalOffset  = RvaToFileOffset(addressOfNameOrdinals);

    if (funcAddrOffset == 0)
    {
        LOG_WARNING("CExportTableParser::Parse: unable to convert function address table RVA");
        m_isParsed = true;
        return true;
    }

    // Get the starting RVA of the section containing the export table, used to determine forwarder addresses
    // If the function address is within the export table's section, it is a forwarder address
    DWord exportSectionStart = 0;
    DWord exportSectionEnd   = 0;

    // Find the section containing the export table by iterating through section table
    if (m_fileSize >= sizeof(IMAGE_DOS_HEADER))
    {
        const IMAGE_DOS_HEADER* pDosHeader =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(m_pFileData);
        DWord e_lfanew = pDosHeader->e_lfanew;

        if (e_lfanew + sizeof(DWord) + sizeof(IMAGE_FILE_HEADER) <= m_fileSize)
        {
            const IMAGE_FILE_HEADER* pFileHeader =
                reinterpret_cast<const IMAGE_FILE_HEADER*>(m_pFileData + e_lfanew + sizeof(DWord));
            Word sizeOfOptionalHeader = pFileHeader->SizeOfOptionalHeader;
            Word numberOfSections = pFileHeader->NumberOfSections;

            DWord sectionTableOffset = e_lfanew
                + sizeof(DWord)
                + sizeof(IMAGE_FILE_HEADER)
                + sizeOfOptionalHeader;

            for (Word i = 0; i < numberOfSections; ++i)
            {
                size_t secOffset = static_cast<size_t>(sectionTableOffset) + i * sizeof(IMAGE_SECTION_HEADER);
                if (secOffset + sizeof(IMAGE_SECTION_HEADER) > m_fileSize)
                {
                    break;
                }

                const IMAGE_SECTION_HEADER* pSection =
                    reinterpret_cast<const IMAGE_SECTION_HEADER*>(m_pFileData + secOffset);

                // Check if export table RVA is within this section
                if (m_dataDirectoryRVA >= pSection->VirtualAddress &&
                    m_dataDirectoryRVA < pSection->VirtualAddress + pSection->Misc.VirtualSize)
                {
                    exportSectionStart = pSection->VirtualAddress;
                    exportSectionEnd   = pSection->VirtualAddress + pSection->Misc.VirtualSize;
                    break;
                }
            }
        }
    }

    // Parse function address table
    const DWord* pFunctions = reinterpret_cast<const DWord*>(m_pFileData + funcAddrOffset);

    // Parse name pointer table (if exists)
    const DWord* pNames = nullptr;
    if (nameAddrOffset != 0)
    {
        pNames = reinterpret_cast<const DWord*>(m_pFileData + nameAddrOffset);
    }

    // Parse name ordinal table (if exists)
    const Word* pNameOrdinals = nullptr;
    if (ordinalOffset != 0)
    {
        pNameOrdinals = reinterpret_cast<const Word*>(m_pFileData + ordinalOffset);
    }

    // Build name-to-ordinal mapping
    // Used to associate names with function addresses
    std::vector<std::pair<Word, std::string>> nameOrdinalPairs;
    if (pNames != nullptr && pNameOrdinals != nullptr)
    {
        for (DWord i = 0; i < numberOfNames; ++i)
        {
            // Check if name pointer is within file bounds
            size_t namePtrOffset = nameAddrOffset + i * sizeof(DWord);
            if (namePtrOffset + sizeof(DWord) > m_fileSize)
            {
                break;
            }

            DWord nameRVA = pNames[i];
            DWord nameFileOffset = RvaToFileOffset(nameRVA);
            if (nameFileOffset != 0 && nameFileOffset < m_fileSize)
            {
                std::string funcName = reinterpret_cast<const char*>(m_pFileData + nameFileOffset);
                nameOrdinalPairs.emplace_back(pNameOrdinals[i], funcName);
            }
        }
    }

    // Iterate through all exported functions
    for (DWord i = 0; i < numberOfFunctions; ++i)
    {
        // Check if function address is within file bounds
        size_t funcAddrOffset_check = funcAddrOffset + i * sizeof(DWord);
        if (funcAddrOffset_check + sizeof(DWord) > m_fileSize)
        {
            break;
        }

        DWord funcRVA = pFunctions[i];
        if (funcRVA == 0)
        {
            // Address 0 means this ordinal has no exported function
            continue;
        }

        ExportFunctionInfo exportInfo;
        exportInfo.address    = funcRVA;
        exportInfo.ordinal    = static_cast<Word>(baseOrdinal + i);
        exportInfo.isForwarder = false;

        // Find corresponding function name
        for (const auto& pair : nameOrdinalPairs)
        {
            if (pair.first == i)
            {
                exportInfo.name = pair.second;
                break;
            }
        }

        // Determine if it is a forwarder address
        // If the function address is within the export table's section, it is a forwarder address
        if (exportSectionStart != 0 && exportSectionEnd != 0)
        {
            if (funcRVA >= exportSectionStart && funcRVA < exportSectionEnd)
            {
                exportInfo.isForwarder = true;

                // Read forwarder string
                DWord forwarderOffset = RvaToFileOffset(funcRVA);
                if (forwarderOffset != 0 && forwarderOffset < m_fileSize)
                {
                    exportInfo.forwarderName =
                        reinterpret_cast<const char*>(m_pFileData + forwarderOffset);
                }
            }
        }

        m_exports.push_back(exportInfo);
    }

    m_isParsed = true;
    m_lastError = EErrorCode::Success;

    LOG_INFO_F("CExportTableParser::Parse: export table parsed successfully (%zu functions)", m_exports.size());
    return true;
}

// ============================================================================
// RVA to File Offset Conversion
// ============================================================================

DWord CExportTableParser::RvaToFileOffset(DWord rva) const
{
    // Convert RVA to file offset by iterating through section table
    if (m_fileSize < sizeof(IMAGE_DOS_HEADER))
    {
        return 0;
    }

    const IMAGE_DOS_HEADER* pDosHeader =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(m_pFileData);
    DWord e_lfanew = pDosHeader->e_lfanew;

    if (e_lfanew + sizeof(DWord) + sizeof(IMAGE_FILE_HEADER) > m_fileSize)
    {
        return 0;
    }

    const IMAGE_FILE_HEADER* pFileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(m_pFileData + e_lfanew + sizeof(DWord));
    Word sizeOfOptionalHeader = pFileHeader->SizeOfOptionalHeader;
    Word numberOfSections = pFileHeader->NumberOfSections;

    DWord sectionTableOffset = e_lfanew
        + sizeof(DWord)
        + sizeof(IMAGE_FILE_HEADER)
        + sizeOfOptionalHeader;

    for (Word i = 0; i < numberOfSections; ++i)
    {
        size_t sectionOffset = static_cast<size_t>(sectionTableOffset) + i * sizeof(IMAGE_SECTION_HEADER);
        if (sectionOffset + sizeof(IMAGE_SECTION_HEADER) > m_fileSize)
        {
            break;
        }

        const IMAGE_SECTION_HEADER* pSection =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(m_pFileData + sectionOffset);

        if (rva >= pSection->VirtualAddress &&
            rva < pSection->VirtualAddress + pSection->Misc.VirtualSize)
        {
            DWord offset = rva - pSection->VirtualAddress;
            return pSection->PointerToRawData + offset;
        }
    }

    return 0;
}

// ============================================================================
// Result Retrieval
// ============================================================================

std::string CExportTableParser::GetResult() const
{
    std::ostringstream json;
    json << "{"
         << "\"parser\":\"ExportTableParser\","
         << "\"exportCount\":" << m_exports.size() << ","
         << "\"exports\":[";

    for (size_t i = 0; i < m_exports.size(); ++i)
    {
        if (i > 0)
        {
            json << ",";
        }

        const auto& exp = m_exports[i];
        json << "{"
             << "\"name\":\"" << exp.name << "\","
             << "\"ordinal\":" << exp.ordinal << ","
             << "\"address\":\"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
             << exp.address << "\","
             << "\"isForwarder\":" << (exp.isForwarder ? "true" : "false");

        if (exp.isForwarder && !exp.forwarderName.empty())
        {
            json << ",\"forwarderName\":\"" << exp.forwarderName << "\"";
        }

        json << "}";
    }

    json << "]}";
    return json.str();
}

EErrorCode CExportTableParser::GetLastError() const
{
    return m_lastError;
}

std::string CExportTableParser::GetErrorDescription() const
{
    return PE::GetErrorDescription(m_lastError);
}

const std::vector<ExportFunctionInfo>& CExportTableParser::GetExports() const
{
    return m_exports;
}

} // namespace PE
