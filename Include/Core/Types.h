/**
 * @file Types.h
 * @brief PE Static Sentinel base type definitions
 * @date 2026-06-17
 *
 * This file defines the base types, enums, and structures used throughout the project.
 * All types are in the PE namespace and follow C++17 standards.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

namespace PE {

// ============================================================================
// Base Type Aliases
// ============================================================================

using Byte        = uint8_t;   ///< Single byte type
using Word        = uint16_t;  ///< Double byte type (corresponds to WORD in IMAGE_FILE_HEADER)
using DWord       = uint32_t;  ///< Four byte type (corresponds to DWORD in IMAGE_FILE_HEADER)
using QWord       = uint64_t;  ///< Eight byte type
using FileOffset  = uint32_t;  ///< File offset type
using RVA         = uint32_t;  ///< Relative virtual address type
using VA          = uint64_t;  ///< Virtual address type

// ============================================================================
// Risk Level Enumeration
// ============================================================================

/**
 * @brief Security analysis risk level
 */
enum class ERiskLevel : uint8_t
{
    None     = 0,  ///< No risk
    Low      = 1,  ///< Low risk
    Medium   = 2,  ///< Medium risk
    High     = 3,  ///< High risk
    Critical = 4   ///< Critical risk
};

// ============================================================================
// PE Structure Definitions
// ============================================================================

/**
 * @brief DOS header parsing result
 */
struct DosHeaderInfo
{
    Word    e_magic;        ///< MZ magic (should be 0x5A4D)
    DWord   e_lfanew;       ///< File offset pointing to NT headers
    bool    isValid;        ///< Whether validation passed
};

/**
 * @brief File header (IMAGE_FILE_HEADER) parsing result
 */
struct FileHeaderInfo
{
    Word    machine;                ///< Target machine type
    Word    numberOfSections;       ///< Number of sections
    DWord   timeDateStamp;          ///< Timestamp
    DWord   pointerToSymbolTable;   ///< COFF symbol table offset (deprecated)
    DWord   numberOfSymbols;        ///< Number of symbols (deprecated)
    Word    sizeOfOptionalHeader;   ///< Size of optional header
    Word    characteristics;        ///< File characteristics
    bool    isValid;                ///< Whether validation passed
};

/**
 * @brief Optional header (IMAGE_OPTIONAL_HEADER) parsing result
 */
struct OptionalHeaderInfo
{
    Word    magic;                  ///< Magic (PE32 = 0x10B, PE32+ = 0x20B)
    Byte    majorLinkerVersion;     ///< Linker major version
    Byte    minorLinkerVersion;     ///< Linker minor version
    DWord   sizeOfCode;             ///< Size of code section
    DWord   sizeOfInitializedData;  ///< Size of initialized data
    DWord   sizeOfUninitializedData;///< Size of uninitialized data
    DWord   addressOfEntryPoint;    ///< Entry point RVA
    DWord   baseOfCode;             ///< Base of code
    QWord   imageBase;              ///< Preferred load address
    DWord   sectionAlignment;       ///< Section alignment granularity
    DWord   fileAlignment;          ///< File alignment granularity
    Word    majorOperatingSystemVersion; ///< Required OS major version
    Word    minorOperatingSystemVersion; ///< Required OS minor version
    Word    majorImageVersion;      ///< Image major version
    Word    minorImageVersion;      ///< Image minor version
    Word    majorSubsystemVersion;  ///< Subsystem major version
    Word    minorSubsystemVersion;  ///< Subsystem minor version
    DWord   sizeOfImage;            ///< Image size (in memory)
    DWord   sizeOfHeaders;          ///< Size of all headers
    DWord   checkSum;               ///< Checksum
    Word    subsystem;              ///< Subsystem type
    DWord   dllCharacteristics;     ///< DLL characteristics
    bool    isValid;                ///< Whether validation passed
};

/**
 * @brief NT headers parsing result
 */
struct NtHeadersInfo
{
    DWord           signature;          ///< PE signature (should be 0x00004550)
    FileHeaderInfo  fileHeader;         ///< File header
    OptionalHeaderInfo optionalHeader;  ///< Optional header
    bool            isValid;            ///< Whether validation passed
};

// ============================================================================
// Section Table Related Structures
// ============================================================================

/**
 * @brief Section header information
 */
struct SectionHeaderInfo
{
    std::string name;               ///< Section name (8 bytes, may not be null-terminated)
    DWord       virtualSize;        ///< Section size in memory
    DWord       virtualAddress;     ///< Section RVA
    DWord       sizeOfRawData;      ///< Section size in file
    DWord       pointerToRawData;   ///< Section offset in file
    DWord       pointerToRelocations;   ///< Relocation offset
    DWord       pointerToLinenumbers;   ///< Line number offset
    Word        numberOfRelocations;    ///< Number of relocations
    Word        numberOfLinenumbers;    ///< Number of line numbers
    DWord       characteristics;    ///< Section characteristics
    bool        isExecutable;       ///< Whether executable
    bool        isReadable;         ///< Whether readable
    bool        isWritable;         ///< Whether writable
    float       entropy;            ///< Shannon entropy value
    bool        isValid;            ///< Whether valid
};

// ============================================================================
// Import Table Related Structures
// ============================================================================

/**
 * @brief Import function information
 */
struct ImportFunctionInfo
{
    std::string name;           ///< Function name (may be empty if imported by ordinal)
    Word        hint;           ///< Hint ordinal
    Word        ordinal;        ///< Ordinal (if imported by ordinal)
    bool        isOrdinal;      ///< Whether imported by ordinal
    QWord       thunkValue;     ///< Thunk value (original value)
};

/**
 * @brief Import DLL information
 */
struct ImportDllInfo
{
    std::string                     dllName;        ///< DLL name
    std::vector<ImportFunctionInfo> functions;      ///< Imported functions list
    DWord                           originalFirstThunk; ///< OriginalFirstThunk RVA
    DWord                           firstThunk;     ///< FirstThunk RVA
    DWord                           timeDateStamp;  ///< Timestamp (bound import)
    bool                            isDelayLoad;    ///< Whether delay-load import
};

// ============================================================================
// Export Table Related Structures
// ============================================================================

/**
 * @brief Export function information
 */
struct ExportFunctionInfo
{
    std::string name;           ///< Function name (may be empty)
    Word        ordinal;        ///< Export ordinal
    DWord       address;        ///< Function address (RVA)
    bool        isForwarder;    ///< Whether forwarder function
    std::string forwarderName;  ///< Forwarder target name (e.g. "NTDLL.RtlNtStatusToDosError")
};

// ============================================================================
// PE Information Aggregate Structure
// ============================================================================

/**
 * @brief Complete PE information structure
 *
 * Contains all parsed PE file information from all parsers.
 * This structure will be gradually expanded as the project progresses.
 */
struct PEInfo
{
    std::wstring    filePath;       ///< File path
    size_t          fileSize;       ///< File size
    bool            isPE32Plus;     ///< Whether PE32+ (64-bit)

    DosHeaderInfo   dosHeader;      ///< DOS header information
    NtHeadersInfo   ntHeaders;      ///< NT headers information

    // Section table information
    std::vector<SectionHeaderInfo> sections;     ///< Section table information

    // Import table information
    std::vector<ImportDllInfo>     imports;       ///< Import table information

    // Export table information
    std::vector<ExportFunctionInfo> exports;      ///< Export table information

    // Future stages will add:
    // ResourceInfo                   resources;     ///< Resource table information
    // RelocationInfo                 relocations;   ///< Relocation table information
};

} // namespace PE
