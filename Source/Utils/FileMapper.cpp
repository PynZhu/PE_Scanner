/**
 * @file FileMapper.cpp
 * @brief File mapping utility implementation
 * @date 2026-06-17
 *
 * Implements memory-mapped file I/O using Windows API.
 * Provides RAII resource management for CreateFileMapping/MapViewOfFile.
 */

#include "../../Include/Utils/FileMapper.h"
#include "../../Include/Core/Logger.h"

namespace PE {

// ============================================================================
// Constants
// ============================================================================

constexpr LONGLONG MAX_FILE_SIZE = 0xFFFFFFFF;  ///< Maximum file size (4GB)

// ============================================================================
// Constructor / Destructor
// ============================================================================

CFileMapper::CFileMapper()
    : m_hFile(INVALID_HANDLE_VALUE)
    , m_hFileMapping(nullptr)
    , m_pFileData(nullptr)
    , m_fileSize(0)
    , m_isMapped(false)
    , m_lastError(EErrorCode::Success)
    , m_lastWin32Error(0)
{
}

CFileMapper::~CFileMapper()
{
    ReleaseResources();
}

// ============================================================================
// Move Operations
// ============================================================================

CFileMapper::CFileMapper(CFileMapper&& other) noexcept
    : m_hFile(other.m_hFile)
    , m_hFileMapping(other.m_hFileMapping)
    , m_pFileData(other.m_pFileData)
    , m_fileSize(other.m_fileSize)
    , m_filePath(std::move(other.m_filePath))
    , m_isMapped(other.m_isMapped)
    , m_lastError(other.m_lastError)
    , m_lastWin32Error(other.m_lastWin32Error)
{
    // Reset source object
    other.m_hFile = INVALID_HANDLE_VALUE;
    other.m_hFileMapping = nullptr;
    other.m_pFileData = nullptr;
    other.m_fileSize = 0;
    other.m_isMapped = false;
    other.m_lastError = EErrorCode::Success;
    other.m_lastWin32Error = 0;
}

CFileMapper& CFileMapper::operator=(CFileMapper&& other) noexcept
{
    if (this != &other)
    {
        // Release current resources
        ReleaseResources();

        // Move resources
        m_hFile = other.m_hFile;
        m_hFileMapping = other.m_hFileMapping;
        m_pFileData = other.m_pFileData;
        m_fileSize = other.m_fileSize;
        m_filePath = std::move(other.m_filePath);
        m_isMapped = other.m_isMapped;
        m_lastError = other.m_lastError;
        m_lastWin32Error = other.m_lastWin32Error;

        // Reset source object
        other.m_hFile = INVALID_HANDLE_VALUE;
        other.m_hFileMapping = nullptr;
        other.m_pFileData = nullptr;
        other.m_fileSize = 0;
        other.m_isMapped = false;
        other.m_lastError = EErrorCode::Success;
        other.m_lastWin32Error = 0;
    }
    return *this;
}

// ============================================================================
// File Mapping
// ============================================================================

bool CFileMapper::MapFile(const std::wstring& filePath)
{
    // Release any previously mapped file
    ReleaseResources();

    // Save file path
    m_filePath = filePath;

    // Open file with read-only access, shared read
    m_hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_hFile == INVALID_HANDLE_VALUE)
    {
        m_lastError = EErrorCode::FileOpenFailed;
        m_lastWin32Error = ::GetLastError();
        LOG_ERROR_F("CFileMapper::MapFile: failed to open file '%ls' (error=%lu)",
                     filePath.c_str(), m_lastWin32Error);
        return false;
    }

    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(m_hFile, &fileSize))
    {
        m_lastError = EErrorCode::FileOpenFailed;
        m_lastWin32Error = ::GetLastError();
        LOG_ERROR_F("CFileMapper::MapFile: failed to get file size (error=%lu)", m_lastWin32Error);
        ReleaseResources();
        return false;
    }

    // Check file size
    if (fileSize.QuadPart == 0)
    {
        m_lastError = EErrorCode::FileTooSmall;
        LOG_ERROR("CFileMapper::MapFile: file is empty");
        ReleaseResources();
        return false;
    }

    // Check if file is too large (max 4GB for 32-bit mapping)
    if (fileSize.QuadPart > MAX_FILE_SIZE)
    {
        m_lastError = EErrorCode::FileTooLarge;
        LOG_ERROR_F("CFileMapper::MapFile: file too large (%lld bytes, max=%lld bytes)",
                     fileSize.QuadPart, MAX_FILE_SIZE);
        ReleaseResources();
        return false;
    }

    m_fileSize = static_cast<size_t>(fileSize.QuadPart);

    // Create file mapping object
    m_hFileMapping = CreateFileMappingW(
        m_hFile,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );

    if (m_hFileMapping == nullptr)
    {
        m_lastError = EErrorCode::FileMappingFailed;
        m_lastWin32Error = ::GetLastError();
        LOG_ERROR_F("CFileMapper::MapFile: failed to create file mapping (error=%lu)", m_lastWin32Error);
        ReleaseResources();
        return false;
    }

    // Map view of file
    m_pFileData = MapViewOfFile(
        m_hFileMapping,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (m_pFileData == nullptr)
    {
        m_lastError = EErrorCode::FileMappingFailed;
        m_lastWin32Error = ::GetLastError();
        LOG_ERROR_F("CFileMapper::MapFile: failed to map view of file (error=%lu)", m_lastWin32Error);
        ReleaseResources();
        return false;
    }

    m_isMapped = true;
    m_lastError = EErrorCode::Success;
    m_lastWin32Error = 0;

    LOG_INFO_F("CFileMapper::MapFile: file mapped successfully (size=%zu bytes)", m_fileSize);
    return true;
}

void CFileMapper::Unmap()
{
    ReleaseResources();
}

// ============================================================================
// Accessors
// ============================================================================

const uint8_t* CFileMapper::GetData() const
{
    return static_cast<const uint8_t*>(m_pFileData);
}

size_t CFileMapper::GetSize() const
{
    return m_fileSize;
}

bool CFileMapper::IsMapped() const
{
    return m_isMapped;
}

const std::wstring& CFileMapper::GetFilePath() const
{
    return m_filePath;
}

EErrorCode CFileMapper::GetLastError() const
{
    return m_lastError;
}

DWORD CFileMapper::GetLastWin32Error() const
{
    return m_lastWin32Error;
}

// ============================================================================
// Internal Helpers
// ============================================================================

void CFileMapper::ReleaseResources()
{
    // Unmap view of file
    if (m_pFileData != nullptr)
    {
        UnmapViewOfFile(m_pFileData);
        m_pFileData = nullptr;
    }

    // Close file mapping handle
    if (m_hFileMapping != nullptr)
    {
        CloseHandle(m_hFileMapping);
        m_hFileMapping = nullptr;
    }

    // Close file handle
    if (m_hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }

    // Reset state
    m_fileSize = 0;
    m_isMapped = false;
    m_lastError = EErrorCode::Success;
    m_lastWin32Error = 0;
}

} // namespace PE
