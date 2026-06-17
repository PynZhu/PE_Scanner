/**
 * @file ImportTableParser.cpp
 * @brief Import table parser implementation
 * @date 2026-06-17
 *
 * Implements IMAGE_IMPORT_DESCRIPTOR array parsing logic.
 * Iterates through import descriptors, extracts DLL names and imported function information.
 */

#include "../../Include/Parsers/ImportTableParser.h"
#include "../../Include/Core/Logger.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <windows.h>

namespace PE {

// ============================================================================
// Constants
// ============================================================================

constexpr DWord ORDINAL_FLAG32  = 0x80000000;  ///< 32-bit ordinal flag
constexpr QWord ORDINAL_FLAG64  = 0x8000000000000000ULL;  ///< 64-bit ordinal flag
constexpr Word  ORDINAL_MASK32  = 0x0000FFFF;  ///< 32-bit ordinal mask
constexpr Word  ORDINAL_MASK64  = 0x0000FFFF;  ///< 64-bit ordinal mask

// ============================================================================
// Constructor
// ============================================================================

CImportTableParser::CImportTableParser()
    : m_pFileData(nullptr)
    , m_fileSize(0)
    , m_dataDirectoryRVA(0)
    , m_dataDirectorySize(0)
    , m_isPE32Plus(false)
    , m_imageBase(0)
    , m_hasNtHeadersInfo(false)
    , m_lastError(EErrorCode::Success)
    , m_isInitialized(false)
    , m_isParsed(false)
{
}

// ============================================================================
// IParser Interface Implementation
// ============================================================================

bool CImportTableParser::Initialize(const uint8_t* pFileData, size_t fileSize)
{
    if (pFileData == nullptr)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CImportTableParser::Initialize: file data pointer is null");
        return false;
    }

    if (fileSize == 0)
    {
        m_lastError = EErrorCode::InvalidParameter;
        LOG_ERROR("CImportTableParser::Initialize: file size is 0");
        return false;
    }

    m_pFileData = pFileData;
    m_fileSize  = fileSize;
    m_isInitialized = true;

    LOG_DEBUG_F("CImportTableParser::Initialize: initialized successfully (fileSize=%zu)", fileSize);
    return true;
}

void CImportTableParser::SetNtHeadersInfo(DWord dataDirectoryRVA, DWord dataDirectorySize,
                                           bool isPE32Plus, QWord imageBase)
{
    m_dataDirectoryRVA  = dataDirectoryRVA;
    m_dataDirectorySize = dataDirectorySize;
    m_isPE32Plus        = isPE32Plus;
    m_imageBase         = imageBase;
    m_hasNtHeadersInfo  = true;
}

bool CImportTableParser::Parse()
{
    // Check initialization state
    if (!m_isInitialized)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CImportTableParser::Parse: parser not initialized");
        return false;
    }

    // Check if NT headers info has been set
    if (!m_hasNtHeadersInfo)
    {
        m_lastError = EErrorCode::InvalidState;
        LOG_ERROR("CImportTableParser::Parse: NT headers info not set, please call SetNtHeadersInfo() first");
        return false;
    }

    // Clear previous parse results
    m_imports.clear();

    // Check if import table data directory is valid
    if (m_dataDirectoryRVA == 0 || m_dataDirectorySize == 0)
    {
        LOG_WARNING("CImportTableParser::Parse: no import table in file");
        m_isParsed = true;
        return true;
    }

    // Convert import table RVA to file offset
    DWord importTableOffset = RvaToFileOffset(m_dataDirectoryRVA);
    if (importTableOffset == 0)
    {
        LOG_WARNING("CImportTableParser::Parse: unable to convert import table RVA to file offset");
        m_isParsed = true;
        return true;
    }

    // Check if import table is within file bounds
    if (static_cast<size_t>(importTableOffset) + sizeof(IMAGE_IMPORT_DESCRIPTOR) > m_fileSize)
    {
        LOG_WARNING("CImportTableParser::Parse: import table exceeds file bounds");
        m_isParsed = true;
        return true;
    }

    // Locate import table
    const IMAGE_IMPORT_DESCRIPTOR* pImportDesc =
        reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(m_pFileData + importTableOffset);

    // Iterate through import descriptor array (terminated by all-zero entry)
    DWord index = 0;
    while (true)
    {
        // Check if reached end marker (all fields are 0)
        if (pImportDesc[index].OriginalFirstThunk == 0 &&
            pImportDesc[index].TimeDateStamp == 0 &&
            pImportDesc[index].ForwarderChain == 0 &&
            pImportDesc[index].Name == 0 &&
            pImportDesc[index].FirstThunk == 0)
        {
            break;
        }

        // Check if exceeding data directory bounds
        size_t currentOffset = importTableOffset + (index + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (currentOffset > m_fileSize)
        {
            LOG_WARNING("CImportTableParser::Parse: import descriptor exceeds file bounds");
            break;
        }

        // Parse current import descriptor
        ImportDllInfo importInfo;
        if (!ParseImportDescriptor(&pImportDesc[index], importInfo))
        {
            // Parse failed, continue to next
            ++index;
            continue;
        }

        m_imports.push_back(importInfo);
        ++index;
    }

    // Try to parse delay-load imports
    ParseDelayLoadImports();

    m_isParsed = true;
    m_lastError = EErrorCode::Success;

    LOG_INFO_F("CImportTableParser::Parse: import table parsed successfully (%zu DLLs)", m_imports.size());
    return true;
}

// ============================================================================
// RVA to File Offset Conversion
// ============================================================================

DWord CImportTableParser::RvaToFileOffset(DWord rva) const
{
    // Convert RVA to file offset by iterating through section table
    // First read DOS header to get e_lfanew
    if (m_fileSize < sizeof(IMAGE_DOS_HEADER))
    {
        return 0;
    }

    const IMAGE_DOS_HEADER* pDosHeader =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(m_pFileData);
    DWord e_lfanew = pDosHeader->e_lfanew;

    // Locate NT headers
    if (e_lfanew + sizeof(DWord) + sizeof(IMAGE_FILE_HEADER) > m_fileSize)
    {
        return 0;
    }

    // Get SizeOfOptionalHeader from file header
    const IMAGE_FILE_HEADER* pFileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(m_pFileData + e_lfanew + sizeof(DWord));
    Word sizeOfOptionalHeader = pFileHeader->SizeOfOptionalHeader;

    // Calculate section table offset
    DWord sectionTableOffset = e_lfanew
        + sizeof(DWord)
        + sizeof(IMAGE_FILE_HEADER)
        + sizeOfOptionalHeader;

    // Iterate through section table
    Word numberOfSections = pFileHeader->NumberOfSections;
    for (Word i = 0; i < numberOfSections; ++i)
    {
        size_t sectionOffset = static_cast<size_t>(sectionTableOffset) + i * sizeof(IMAGE_SECTION_HEADER);
        if (sectionOffset + sizeof(IMAGE_SECTION_HEADER) > m_fileSize)
        {
            break;
        }

        const IMAGE_SECTION_HEADER* pSection =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(m_pFileData + sectionOffset);

        // Check if RVA is within this section
        if (rva >= pSection->VirtualAddress &&
            rva < pSection->VirtualAddress + pSection->Misc.VirtualSize)
        {
            // Calculate file offset
            DWord offset = rva - pSection->VirtualAddress;
            return pSection->PointerToRawData + offset;
        }
    }

    // No matching section found
    return 0;
}

// ============================================================================
// Import Descriptor Parsing
// ============================================================================

bool CImportTableParser::ParseImportDescriptor(const IMAGE_IMPORT_DESCRIPTOR* pImportDesc,
                                                ImportDllInfo& importInfo)
{
    // Clear import info
    importInfo = ImportDllInfo{};

    // Save original fields
    importInfo.originalFirstThunk = pImportDesc->OriginalFirstThunk;
    importInfo.firstThunk         = pImportDesc->FirstThunk;
    importInfo.timeDateStamp      = pImportDesc->TimeDateStamp;
    importInfo.isDelayLoad        = false;

    // Parse DLL name
    DWord nameRVA = pImportDesc->Name;
    DWord nameOffset = RvaToFileOffset(nameRVA);
    if (nameOffset == 0 || nameOffset >= m_fileSize)
    {
        LOG_WARNING("CImportTableParser::ParseImportDescriptor: unable to parse DLL name");
        return false;
    }

    // Read DLL name (null-terminated ASCII string)
    importInfo.dllName = reinterpret_cast<const char*>(m_pFileData + nameOffset);

    // Determine which thunk table to use
    // OriginalFirstThunk takes priority; if 0, use FirstThunk
    DWord thunkRVA = pImportDesc->OriginalFirstThunk;
    if (thunkRVA == 0)
    {
        thunkRVA = pImportDesc->FirstThunk;
    }

    if (thunkRVA == 0)
    {
        LOG_WARNING_F("CImportTableParser::ParseImportDescriptor: DLL '%s' has no thunk table",
                      importInfo.dllName.c_str());
        return false;
    }

    // Parse import functions
    if (!ParseImportFunctions(thunkRVA, importInfo.functions))
    {
        LOG_WARNING_F("CImportTableParser::ParseImportDescriptor: DLL '%s' function parsing failed",
                      importInfo.dllName.c_str());
        return false;
    }

    LOG_DEBUG_F("CImportTableParser::ParseImportDescriptor: DLL '%s' (%zu functions)",
                importInfo.dllName.c_str(), importInfo.functions.size());
    return true;
}

// ============================================================================
// Import Functions Parsing
// ============================================================================

bool CImportTableParser::ParseImportFunctions(DWord thunkRVA,
                                               std::vector<ImportFunctionInfo>& functions)
{
    // Convert thunk table RVA to file offset
    DWord thunkOffset = RvaToFileOffset(thunkRVA);
    if (thunkOffset == 0)
    {
        return false;
    }

    // Clear function list
    functions.clear();

    // Use different thunk size based on PE32/PE32+
    size_t thunkSize = m_isPE32Plus ? sizeof(QWord) : sizeof(DWord);

    // Iterate through thunk table (terminated by 0)
    DWord index = 0;
    while (true)
    {
        size_t currentOffset = static_cast<size_t>(thunkOffset) + index * thunkSize;
        if (currentOffset + thunkSize > m_fileSize)
        {
            break;
        }

        ImportFunctionInfo funcInfo;

        if (m_isPE32Plus)
        {
            // 64-bit thunk
            const QWord* pThunk = reinterpret_cast<const QWord*>(m_pFileData + currentOffset);
            QWord thunkValue = *pThunk;

            if (thunkValue == 0)
            {
                break;  // Reached end marker
            }

            funcInfo.thunkValue = thunkValue;

            // Check if imported by ordinal
            if (thunkValue & ORDINAL_FLAG64)
            {
                funcInfo.isOrdinal = true;
                funcInfo.ordinal   = static_cast<Word>(thunkValue & ORDINAL_MASK64);
                funcInfo.name      = "";
            }
            else
            {
                funcInfo.isOrdinal = false;

                // Get function name via IMAGE_IMPORT_BY_NAME structure
                DWORD importByNameOffset = RvaToFileOffset(static_cast<DWord>(thunkValue));
                if (importByNameOffset != 0 &&
                    importByNameOffset + sizeof(Word) < m_fileSize)
                {
                    const Word* pHint = reinterpret_cast<const Word*>(m_pFileData + importByNameOffset);
                    funcInfo.hint = *pHint;
                    funcInfo.name = reinterpret_cast<const char*>(m_pFileData + importByNameOffset + sizeof(Word));
                }
            }
        }
        else
        {
            // 32-bit thunk
            const DWord* pThunk = reinterpret_cast<const DWord*>(m_pFileData + currentOffset);
            DWord thunkValue = *pThunk;

            if (thunkValue == 0)
            {
                break;  // Reached end marker
            }

            funcInfo.thunkValue = thunkValue;

            // Check if imported by ordinal
            if (thunkValue & ORDINAL_FLAG32)
            {
                funcInfo.isOrdinal = true;
                funcInfo.ordinal   = static_cast<Word>(thunkValue & ORDINAL_MASK32);
                funcInfo.name      = "";
            }
            else
            {
                funcInfo.isOrdinal = false;

                // Get function name via IMAGE_IMPORT_BY_NAME structure
                DWORD importByNameOffset = RvaToFileOffset(thunkValue);
                if (importByNameOffset != 0 &&
                    importByNameOffset + sizeof(Word) < m_fileSize)
                {
                    const Word* pHint = reinterpret_cast<const Word*>(m_pFileData + importByNameOffset);
                    funcInfo.hint = *pHint;
                    funcInfo.name = reinterpret_cast<const char*>(m_pFileData + importByNameOffset + sizeof(Word));
                }
            }
        }

        functions.push_back(funcInfo);
        ++index;
    }

    return true;
}

// ============================================================================
// Delay-Load Import Parsing
// ============================================================================

bool CImportTableParser::ParseDelayLoadImports()
{
    // Delay-Load imports use IMAGE_DELAYLOAD_DESCRIPTOR structure
    // Its data directory index is 15 (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
    // Since we don't directly access the data directory, we get it through the optional header's DataDirectory array

    // Locate NT headers
    if (m_fileSize < sizeof(IMAGE_DOS_HEADER))
    {
        return false;
    }

    const IMAGE_DOS_HEADER* pDosHeader =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(m_pFileData);
    DWord e_lfanew = pDosHeader->e_lfanew;

    // Locate data directory in optional header
    // NT header = e_lfanew
    // File header = NT header + 4 (signature)
    // Optional header = File header + sizeof(IMAGE_FILE_HEADER)
    // Data directory = Optional header + optional header size - data directory size (at end of optional header)
    // Actually, the data directory is part of the optional header, at offset 96 for PE32, 112 for PE32+

    // Simplified handling: we only parse standard import table
    // Delay-load imports require more complex positioning
    // In actual projects, can be obtained via IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT index
    LOG_DEBUG("CImportTableParser::ParseDelayLoadImports: delay-load import parsing (reserved)");
    return true;
}

// ============================================================================
// Result Retrieval
// ============================================================================

std::string CImportTableParser::GetResult() const
{
    std::ostringstream json;
    json << "{"
         << "\"parser\":\"ImportTableParser\","
         << "\"dllCount\":" << m_imports.size() << ","
         << "\"imports\":[";

    for (size_t i = 0; i < m_imports.size(); ++i)
    {
        if (i > 0)
        {
            json << ",";
        }

        const auto& dll = m_imports[i];
        json << "{"
             << "\"dllName\":\"" << dll.dllName << "\","
             << "\"isDelayLoad\":" << (dll.isDelayLoad ? "true" : "false") << ","
             << "\"functions\":[";

        for (size_t j = 0; j < dll.functions.size(); ++j)
        {
            if (j > 0)
            {
                json << ",";
            }

            const auto& func = dll.functions[j];
            json << "{";
            if (func.isOrdinal)
            {
                json << "\"type\":\"ordinal\","
                     << "\"ordinal\":" << func.ordinal;
            }
            else
            {
                json << "\"type\":\"name\","
                     << "\"name\":\"" << func.name << "\","
                     << "\"hint\":" << func.hint;
            }
            json << "}";
        }

        json << "]}";
    }

    json << "]}";
    return json.str();
}

EErrorCode CImportTableParser::GetLastError() const
{
    return m_lastError;
}

std::string CImportTableParser::GetErrorDescription() const
{
    return PE::GetErrorDescription(m_lastError);
}

const std::vector<ImportDllInfo>& CImportTableParser::GetImportDlls() const
{
    return m_imports;
}

} // namespace PE
