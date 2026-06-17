/**
 * @file NtHeadersParser.h
 * @brief NT澶磋В鏋愬櫒澹版槑
 * @date 2026-06-17
 *
 * NT澶磋В鏋愬櫒璐熻矗瑙ｆ瀽 PE 鏂囦欢鐨?NT 澶撮儴鍒嗭紝
 * 鍖呮嫭 PE 绛惧悕楠岃瘉銆佹枃浠跺ご瑙ｆ瀽鍜屽彲閫夊ご瑙ｆ瀽銆?
 */

#pragma once

#include "../Interfaces/IParser.h"
#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>

namespace PE {

/**
 * @brief NT澶磋В鏋愬櫒
 *
 * 瑙ｆ瀽 IMAGE_NT_HEADERS 缁撴瀯锛屽寘鎷細
 * - PE 绛惧悕楠岃瘉 (0x00004550 "PE\0\0")
 * - IMAGE_FILE_HEADER 瑙ｆ瀽
 * - IMAGE_OPTIONAL_HEADER 瑙ｆ瀽 (鏀寔 PE32 鍜?PE32+)
 *
 * 閿欒鍦烘櫙锛?
 * - 鏂囦欢鏁版嵁涓虹┖
 * - PE 绛惧悕涓嶅尮閰?
 * - 鍙€夊ご榄旀暟鏃犳晥
 * - 涓嶆敮鎸佺殑鏋舵瀯
 */
class CNtHeadersParser : public IParser
{
public:
    CNtHeadersParser();
    virtual ~CNtHeadersParser() = default;

    // 绂佺敤鎷疯礉
    CNtHeadersParser(const CNtHeadersParser&) = delete;
    CNtHeadersParser& operator=(const CNtHeadersParser&) = delete;

    // === IParser 鎺ュ彛瀹炵幇 ===

    /**
     * @brief 鍒濆鍖?NT 澶磋В鏋愬櫒
     * @param pFileData 鏄犲皠鍚庣殑鏂囦欢鏁版嵁鍩哄潃
     * @param fileSize 鏂囦欢澶у皬
     * @return true 鍒濆鍖栨垚鍔燂紝false 鍒濆鍖栧け璐?
     */
    virtual bool Initialize(const uint8_t* pFileData, size_t fileSize) override;

    /**
     * @brief 鎵ц NT 澶磋В鏋?
     * @return true 瑙ｆ瀽鎴愬姛锛宖alse 瑙ｆ瀽澶辫触
     *
     * 娉ㄦ剰锛氬湪璋冪敤 Parse() 涔嬪墠锛屽繀椤诲厛璋冪敤 SetELfanew()
     * 璁剧疆 DOS 澶翠腑瑙ｆ瀽鍑虹殑 e_lfanew 鍊笺€?
     */
    virtual bool Parse() override;

    /**
     * @brief 鑾峰彇瑙ｆ瀽缁撴灉 (JSON鏍煎紡)
     * @return JSON 瀛楃涓?
     */
    virtual std::string GetResult() const override;

    /**
     * @brief 鑾峰彇閿欒鐮?
     * @return 閿欒鐮?
     */
    virtual EErrorCode GetLastError() const override;

    /**
     * @brief 鑾峰彇閿欒鎻忚堪
     * @return 閿欒鎻忚堪瀛楃涓?
     */
    virtual std::string GetErrorDescription() const override;

    /**
     * @brief 鑾峰彇瑙ｆ瀽鍚庣殑 NT 澶翠俊鎭?
     * @return 甯搁噺寮曠敤鍒?NtHeadersInfo
     */
    const NtHeadersInfo& GetNtHeadersInfo() const;

    /**
     * @brief 璁剧疆 e_lfanew 鍊?(鐢?DOS 澶磋В鏋愬櫒鎻愪緵)
     * @param e_lfanew DOS 澶翠腑鐨?e_lfanew 瀛楁鍊?
     */
    void SetELfanew(DWord e_lfanew);

private:
    /**
     * @brief 瑙ｆ瀽 IMAGE_FILE_HEADER
     * @param pFileHeader 鎸囧悜鏂囦欢澶寸殑鎸囬拡
     * @return true 瑙ｆ瀽鎴愬姛
     */
    bool ParseFileHeader(const IMAGE_FILE_HEADER* pFileHeader);

    /**
     * @brief 瑙ｆ瀽 IMAGE_OPTIONAL_HEADER (PE32)
     * @param pOptionalHeader 鎸囧悜 32 浣嶅彲閫夊ご鐨勬寚閽?
     * @return true 瑙ｆ瀽鎴愬姛
     */
    bool ParseOptionalHeader32(const IMAGE_OPTIONAL_HEADER32* pOptionalHeader);

    /**
     * @brief 瑙ｆ瀽 IMAGE_OPTIONAL_HEADER (PE32+)
     * @param pOptionalHeader64 鎸囧悜 64 浣嶅彲閫夊ご鐨勬寚閽?
     * @return true 瑙ｆ瀽鎴愬姛
     */
    bool ParseOptionalHeader64(const IMAGE_OPTIONAL_HEADER64* pOptionalHeader64);

    const uint8_t*  m_pFileData;        ///< 鏂囦欢鏁版嵁鍩哄潃
    size_t          m_fileSize;         ///< 鏂囦欢澶у皬
    DWord           m_e_lfanew;         ///< DOS 澶翠腑鐨?e_lfanew 鍊?
    NtHeadersInfo   m_ntHeaders;        ///< 瑙ｆ瀽缁撴灉
    EErrorCode      m_lastError;        ///< 鏈€鍚庝竴娆￠敊璇爜
    bool            m_isInitialized;    ///< 鏄惁宸插垵濮嬪寲
    bool            m_isParsed;         ///< 鏄惁宸茶В鏋?
    bool            m_hasELfanew;       ///< 鏄惁宸茶缃?e_lfanew
};

} // namespace PE
