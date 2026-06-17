/**
 * @file FileMapper.h
 * @brief 鏂囦欢鍐呭瓨鏄犲皠宸ュ叿澹版槑
 * @date 2026-06-17
 *
 * 浣跨敤 Windows 鍐呭瓨鏄犲皠鏂囦欢 API 灏?PE 鏂囦欢鏄犲皠鍒拌繘绋嬪湴鍧€绌洪棿銆?
 * 閲囩敤 RAII 鏈哄埗绠＄悊璧勬簮锛岀‘淇濊祫婧愯嚜鍔ㄩ噴鏀俱€?
 */

#pragma once

#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>
#include <windows.h>

namespace PE {

/**
 * @brief 鏂囦欢鍐呭瓨鏄犲皠绫?(RAII)
 *
 * 灏佽 Windows 鍐呭瓨鏄犲皠鏂囦欢 API (CreateFile, CreateFileMapping, MapViewOfFile)锛?
 * 鎻愪緵瀹夊叏銆佷究鎹风殑鏂囦欢鏄犲皠鍔熻兘銆?
 *
 * 鐗规€э細
 * - RAII 璧勬簮绠＄悊锛氭瀽鏋勬椂鑷姩閲婃斁鎵€鏈夎祫婧?
 * - 鍙鏄犲皠锛氫繚璇佹枃浠舵暟鎹笉琚剰澶栦慨鏀?
 * - 瀹屾暣閿欒澶勭悊锛氭墍鏈?API 璋冪敤鍧囨鏌ヨ繑鍥炲€?
 * - 鏀寔澶ф枃浠讹細閫氳繃鍐呭瓨鏄犲皠楂樻晥澶勭悊澶ф枃浠?
 *
 * 浣跨敤绀轰緥锛?
 * @code
 * CFileMapper mapper;
 * if (mapper.MapFile(L"test.exe"))
 * {
 *     const uint8_t* pData = mapper.GetData();
 *     size_t size = mapper.GetSize();
 *     // 澶勭悊鏂囦欢鏁版嵁...
 * }
 * @endcode
 */
class CFileMapper
{
public:
    CFileMapper();
    ~CFileMapper();

    // 绂佺敤鎷疯礉
    CFileMapper(const CFileMapper&) = delete;
    CFileMapper& operator=(const CFileMapper&) = delete;

    // 鍏佽绉诲姩
    CFileMapper(CFileMapper&& other) noexcept;
    CFileMapper& operator=(CFileMapper&& other) noexcept;

    /**
     * @brief 鏄犲皠鏂囦欢鍒板唴瀛?
     * @param filePath 鏂囦欢璺緞 (瀹藉瓧绗?
     * @return true 鏄犲皠鎴愬姛锛宖alse 鏄犲皠澶辫触
     *
     * 鏄犲皠鎴愬姛鍚庯紝鍙€氳繃 GetData() 鍜?GetSize() 鑾峰彇鏁版嵁鎸囬拡鍜屽ぇ灏忋€?
     * 濡傛灉涔嬪墠宸叉槧灏勫叾浠栨枃浠讹紝浼氳嚜鍔ㄥ厛閲婃斁銆?
     */
    bool MapFile(const std::wstring& filePath);

    /**
     * @brief 鍙栨秷鏄犲皠骞堕噴鏀捐祫婧?
     *
     * 瀹夊叏閲婃斁鎵€鏈?Windows 鍐呮牳瀵硅薄鍙ユ焺銆?
     * 姝ゅ嚱鏁板彲澶氭璋冪敤锛屽箓绛夋搷浣溿€?
     */
    void Unmap();

    /**
     * @brief 鑾峰彇鏄犲皠鍚庣殑鏂囦欢鏁版嵁鎸囬拡
     * @return 鏂囦欢鏁版嵁鎸囬拡锛屾湭鏄犲皠鏃惰繑鍥?nullptr
     */
    const uint8_t* GetData() const;

    /**
     * @brief 鑾峰彇鏂囦欢澶у皬
     * @return 鏂囦欢澶у皬 (瀛楄妭)锛屾湭鏄犲皠鏃惰繑鍥?0
     */
    size_t GetSize() const;

    /**
     * @brief 妫€鏌ユ槸鍚﹀凡鎴愬姛鏄犲皠
     * @return true 宸叉槧灏?
     */
    bool IsMapped() const;

    /**
     * @brief 鑾峰彇鏂囦欢璺緞
     * @return 鏂囦欢璺緞
     */
    const std::wstring& GetFilePath() const;

    /**
     * @brief 鑾峰彇鏈€鍚庝竴娆￠敊璇爜
     * @return 閿欒鐮?
     */
    EErrorCode GetLastError() const;

    /**
     * @brief 鑾峰彇 Windows 閿欒鐮?
     * @return GetLastError() 鐨勫€?
     */
    DWORD GetLastWin32Error() const;

private:
    /**
     * @brief 閲婃斁鎵€鏈夎祫婧?(鍐呴儴璋冪敤)
     */
    void ReleaseResources();

    HANDLE          m_hFile;            ///< 鏂囦欢鍙ユ焺
    HANDLE          m_hFileMapping;     ///< 鏂囦欢鏄犲皠鍙ユ焺
    LPVOID          m_pFileData;        ///< 鏄犲皠瑙嗗浘鎸囬拡
    size_t          m_fileSize;         ///< 鏂囦欢澶у皬
    std::wstring    m_filePath;         ///< 鏂囦欢璺緞
    EErrorCode      m_lastError;        ///< 鏈€鍚庝竴娆￠敊璇爜
    DWORD           m_lastWin32Error;   ///< 鏈€鍚庝竴娆?Windows 閿欒鐮?
    bool            m_isMapped;         ///< 鏄惁宸叉槧灏?
};

} // namespace PE
