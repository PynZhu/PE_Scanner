/**
 * @file DosHeaderParser.h
 * @brief DOS澶磋В鏋愬櫒澹版槑
 * @date 2026-06-17
 *
 * DOS澶磋В鏋愬櫒璐熻矗瑙ｆ瀽 PE 鏂囦欢鐨?DOS 澶撮儴鍒嗐€?
 * 涓昏鍔熻兘鍖呮嫭楠岃瘉 MZ 榄旀暟鍜屽畾浣?e_lfanew 瀛楁銆?
 */

#pragma once

#include "../Interfaces/IParser.h"
#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>

namespace PE {

/**
 * @brief DOS澶磋В鏋愬櫒
 *
 * 瑙ｆ瀽 IMAGE_DOS_HEADER 缁撴瀯锛岄獙璇?MZ 绛惧悕锛?
 * 骞舵彁鍙?e_lfanew 瀛楁鐢ㄤ簬鍚庣画 NT 澶村畾浣嶃€?
 *
 * 閿欒鍦烘櫙锛?
 * - 鏂囦欢鏁版嵁涓虹┖
 * - 鏂囦欢澶у皬灏忎簬 DOS 澶村ぇ灏?
 * - MZ 榄旀暟涓嶅尮閰?
 * - e_lfanew 鍊艰秺鐣屾垨鏈榻?
 */
class CDosHeaderParser : public IParser
{
public:
    CDosHeaderParser();
    virtual ~CDosHeaderParser() = default;

    // 绂佺敤鎷疯礉
    CDosHeaderParser(const CDosHeaderParser&) = delete;
    CDosHeaderParser& operator=(const CDosHeaderParser&) = delete;

    // === IParser 鎺ュ彛瀹炵幇 ===

    /**
     * @brief 鍒濆鍖?DOS 澶磋В鏋愬櫒
     * @param pFileData 鏄犲皠鍚庣殑鏂囦欢鏁版嵁鍩哄潃
     * @param fileSize 鏂囦欢澶у皬
     * @return true 鍒濆鍖栨垚鍔燂紝false 鍒濆鍖栧け璐?
     */
    virtual bool Initialize(const uint8_t* pFileData, size_t fileSize) override;

    /**
     * @brief 鎵ц DOS 澶磋В鏋?
     * @return true 瑙ｆ瀽鎴愬姛锛宖alse 瑙ｆ瀽澶辫触
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
     * @brief 鑾峰彇瑙ｆ瀽鍚庣殑 DOS 澶翠俊鎭?
     * @return 甯搁噺寮曠敤鍒?DosHeaderInfo
     */
    const DosHeaderInfo& GetDosHeaderInfo() const;

private:
    const uint8_t*  m_pFileData;    ///< 鏂囦欢鏁版嵁鍩哄潃
    size_t          m_fileSize;     ///< 鏂囦欢澶у皬
    DosHeaderInfo   m_dosHeader;    ///< 瑙ｆ瀽缁撴灉
    EErrorCode      m_lastError;    ///< 鏈€鍚庝竴娆￠敊璇爜
    bool            m_isInitialized;///< 鏄惁宸插垵濮嬪寲
    bool            m_isParsed;     ///< 鏄惁宸茶В鏋?
};

} // namespace PE
