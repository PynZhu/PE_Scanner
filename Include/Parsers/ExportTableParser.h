/**
 * @file ExportTableParser.h
 * @brief 瀵煎嚭琛ㄨВ鏋愬櫒澹版槑
 * @date 2026-06-17
 *
 * 瀵煎嚭琛ㄨВ鏋愬櫒璐熻矗瑙ｆ瀽 PE 鏂囦欢鐨勫鍑鸿〃 (Export Table)锛?
 * 鎻愬彇瀵煎嚭鍑芥暟鍚嶇О銆佸簭鍙峰拰杞彂鍦板潃淇℃伅銆?
 */

#pragma once

#include "../Interfaces/IParser.h"
#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>
#include <vector>

namespace PE {

/**
 * @brief 瀵煎嚭琛ㄨВ鏋愬櫒
 *
 * 瑙ｆ瀽 IMAGE_EXPORT_DIRECTORY锛屾彁鍙栵細
 * - 瀵煎嚭鍑芥暟鍚嶇О鍒楄〃
 * - 瀵煎嚭搴忓彿 (Ordinal)
 * - 鍑芥暟鍦板潃 (RVA)
 * - 杞彂鍦板潃 (Forwarder) 淇℃伅
 *
 * 娉ㄦ剰锛氭瑙ｆ瀽鍣ㄤ緷璧栦簬 CNtHeadersParser 鎻愪緵鐨勪俊鎭紝
 * 鍦ㄨ皟鐢?Parse() 涔嬪墠蹇呴』鍏堣皟鐢?SetNtHeadersInfo()銆?
 */
class CExportTableParser : public IParser
{
public:
    CExportTableParser();
    virtual ~CExportTableParser() = default;

    // 绂佺敤鎷疯礉
    CExportTableParser(const CExportTableParser&) = delete;
    CExportTableParser& operator=(const CExportTableParser&) = delete;

    // === IParser 鎺ュ彛瀹炵幇 ===

    /**
     * @brief 鍒濆鍖栧鍑鸿〃瑙ｆ瀽鍣?
     * @param pFileData 鏄犲皠鍚庣殑鏂囦欢鏁版嵁鍩哄潃
     * @param fileSize 鏂囦欢澶у皬
     * @return true 鍒濆鍖栨垚鍔燂紝false 鍒濆鍖栧け璐?
     */
    virtual bool Initialize(const uint8_t* pFileData, size_t fileSize) override;

    /**
     * @brief 鎵ц瀵煎嚭琛ㄨВ鏋?
     * @return true 瑙ｆ瀽鎴愬姛锛宖alse 瑙ｆ瀽澶辫触
     *
     * 娉ㄦ剰锛氬湪璋冪敤 Parse() 涔嬪墠锛屽繀椤诲厛璋冪敤 SetNtHeadersInfo()
     * 璁剧疆 NT 澶磋В鏋愬櫒鎻愪緵鐨勫鍑鸿〃 RVA 鍜屽ぇ灏忋€?
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
     * @brief 鑾峰彇瑙ｆ瀽鍚庣殑瀵煎嚭鍑芥暟淇℃伅
     * @return 甯搁噺寮曠敤鍒板鍑哄嚱鏁颁俊鎭悜閲?
     */
    const std::vector<ExportFunctionInfo>& GetExports() const;

    /**
     * @brief 璁剧疆 NT 澶磋В鏋愪俊鎭?(鐢?CPEAnalyzer 鎻愪緵)
     * @param dataDirectoryRVA 瀵煎嚭琛ㄦ暟鎹洰褰?RVA
     * @param dataDirectorySize 瀵煎嚭琛ㄦ暟鎹洰褰曞ぇ灏?
     */
    void SetNtHeadersInfo(DWord dataDirectoryRVA, DWord dataDirectorySize);

private:
    /**
     * @brief 灏?RVA 杞崲涓烘枃浠跺亸绉?
     * @param rva 鐩稿铏氭嫙鍦板潃
     * @return 鏂囦欢鍋忕Щ锛屽鏋滆浆鎹㈠け璐ヨ繑鍥?0
     */
    DWord RvaToFileOffset(DWord rva) const;

    const uint8_t*  m_pFileData;            ///< 鏂囦欢鏁版嵁鍩哄潃
    size_t          m_fileSize;             ///< 鏂囦欢澶у皬
    DWord           m_dataDirectoryRVA;     ///< 瀵煎嚭琛ㄦ暟鎹洰褰?RVA
    DWord           m_dataDirectorySize;    ///< 瀵煎嚭琛ㄦ暟鎹洰褰曞ぇ灏?
    bool            m_hasNtHeadersInfo;     ///< 鏄惁宸茶缃?NT 澶翠俊鎭?

    std::vector<ExportFunctionInfo> m_exports;  ///< 瑙ｆ瀽缁撴灉
    EErrorCode      m_lastError;            ///< 鏈€鍚庝竴娆￠敊璇爜
    bool            m_isInitialized;        ///< 鏄惁宸插垵濮嬪寲
    bool            m_isParsed;             ///< 鏄惁宸茶В鏋?
};

} // namespace PE
