/**
 * @file SectionParser.h
 * @brief 鑺傝〃瑙ｆ瀽鍣ㄥ０鏄?
 * @date 2026-06-17
 *
 * 鑺傝〃瑙ｆ瀽鍣ㄨ礋璐ｈВ鏋?PE 鏂囦欢鐨勮妭琛?(Section Table)锛?
 * 閬嶅巻鎵€鏈夎妭鍖哄苟鎻愬彇璇︾粏淇℃伅锛屽寘鎷悕绉般€佸ぇ灏忋€佺壒寰佸拰鐔靛€笺€?
 */

#pragma once

#include "../Interfaces/IParser.h"
#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>
#include <vector>

namespace PE {

/**
 * @brief 鑺傝〃瑙ｆ瀽鍣?
 *
 * 瑙ｆ瀽 IMAGE_SECTION_HEADER 鏁扮粍锛岄亶鍘嗘墍鏈夎妭鍖哄苟鎻愬彇锛?
 * - 鑺傚尯鍚嶇О
 * - 铏氭嫙鍦板潃鍜岃櫄鎷熷ぇ灏?
 * - 鍘熷鏁版嵁鍋忕Щ鍜屽ぇ灏?
 * - 鐗瑰緛鏍囧織 (鍙墽琛屻€佸彲璇汇€佸彲鍐?
 * - 棣欏啘鐔靛€?
 *
 * 娉ㄦ剰锛氭瑙ｆ瀽鍣ㄤ緷璧栦簬 CNtHeadersParser 鎻愪緵鐨勪俊鎭紝
 * 鍦ㄨ皟鐢?Parse() 涔嬪墠蹇呴』鍏堣皟鐢?SetNtHeadersInfo()銆?
 */
class CSectionParser : public IParser
{
public:
    CSectionParser();
    virtual ~CSectionParser() = default;

    // 绂佺敤鎷疯礉
    CSectionParser(const CSectionParser&) = delete;
    CSectionParser& operator=(const CSectionParser&) = delete;

    // === IParser 鎺ュ彛瀹炵幇 ===

    /**
     * @brief 鍒濆鍖栬妭琛ㄨВ鏋愬櫒
     * @param pFileData 鏄犲皠鍚庣殑鏂囦欢鏁版嵁鍩哄潃
     * @param fileSize 鏂囦欢澶у皬
     * @return true 鍒濆鍖栨垚鍔燂紝false 鍒濆鍖栧け璐?
     */
    virtual bool Initialize(const uint8_t* pFileData, size_t fileSize) override;

    /**
     * @brief 鎵ц鑺傝〃瑙ｆ瀽
     * @return true 瑙ｆ瀽鎴愬姛锛宖alse 瑙ｆ瀽澶辫触
     *
     * 娉ㄦ剰锛氬湪璋冪敤 Parse() 涔嬪墠锛屽繀椤诲厛璋冪敤 SetNtHeadersInfo()
     * 璁剧疆 NT 澶磋В鏋愬櫒鎻愪緵鐨勮妭鍖烘暟閲忓拰鍙€夊ご澶у皬绛変俊鎭€?
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
     * @brief 鑾峰彇瑙ｆ瀽鍚庣殑鑺傝〃淇℃伅
     * @return 甯搁噺寮曠敤鍒拌妭琛ㄤ俊鎭悜閲?
     */
    const std::vector<SectionHeaderInfo>& GetSections() const;

    /**
     * @brief 璁剧疆 NT 澶磋В鏋愪俊鎭?(鐢?CPEAnalyzer 鎻愪緵)
     * @param numberOfSections 鑺傚尯鏁伴噺
     * @param sizeOfOptionalHeader 鍙€夊ご澶у皬
     * @param sectionAlignment 鑺傚尯瀵归綈绮掑害
     */
    void SetNtHeadersInfo(Word numberOfSections, Word sizeOfOptionalHeader,
                          DWord sectionAlignment);

private:
    /**
     * @brief 瑙ｆ瀽鑺傚尯鐗瑰緛鏍囧織
     * @param characteristics 鐗瑰緛鍊?
     * @param info 杈撳嚭鍙傛暟锛屽～鍏呭彲鎵ц/鍙/鍙啓鏍囧織
     */
    void ParseCharacteristics(DWord characteristics, SectionHeaderInfo& info);

    /**
     * @brief 娓呯悊鑺傚尯鍚嶇О (鍘婚櫎灏鹃儴绌烘牸鍜?null)
     * @param rawName 鍘熷 8 瀛楄妭鍚嶇О
     * @return 娓呯悊鍚庣殑鍚嶇О瀛楃涓?
     */
    std::string CleanSectionName(const char* rawName) const;

    const uint8_t*  m_pFileData;            ///< 鏂囦欢鏁版嵁鍩哄潃
    size_t          m_fileSize;             ///< 鏂囦欢澶у皬
    Word            m_numberOfSections;     ///< 鑺傚尯鏁伴噺
    Word            m_sizeOfOptionalHeader; ///< 鍙€夊ご澶у皬
    DWord           m_sectionAlignment;     ///< 鑺傚尯瀵归綈绮掑害
    bool            m_hasNtHeadersInfo;     ///< 鏄惁宸茶缃?NT 澶翠俊鎭?

    std::vector<SectionHeaderInfo> m_sections;  ///< 瑙ｆ瀽缁撴灉
    EErrorCode      m_lastError;            ///< 鏈€鍚庝竴娆￠敊璇爜
    bool            m_isInitialized;        ///< 鏄惁宸插垵濮嬪寲
    bool            m_isParsed;             ///< 鏄惁宸茶В鏋?
};

} // namespace PE
