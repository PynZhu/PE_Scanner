/**
 * @file ImportTableParser.h
 * @brief 瀵煎叆琛ㄨВ鏋愬櫒澹版槑
 * @date 2026-06-17
 *
 * 瀵煎叆琛ㄨВ鏋愬櫒璐熻矗瑙ｆ瀽 PE 鏂囦欢鐨勫鍏ヨ〃 (Import Table)锛?
 * 閬嶅巻 IMAGE_IMPORT_DESCRIPTOR 鏁扮粍锛屾彁鍙栧鍏ョ殑 DLL 鍜屽嚱鏁颁俊鎭€?
 */

#pragma once

#include "../Interfaces/IParser.h"
#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>
#include <vector>

namespace PE {

/**
 * @brief 瀵煎叆琛ㄨВ鏋愬櫒
 *
 * 瑙ｆ瀽 IMAGE_IMPORT_DESCRIPTOR 鏁扮粍锛屾彁鍙栵細
 * - 姣忎釜瀵煎叆鐨?DLL 鍚嶇О
 * - 姣忎釜 DLL 瀵煎叆鐨勫嚱鏁板悕绉版垨搴忓彿
 * - 鏀寔 32 浣嶅拰 64 浣?(浣跨敤涓嶅悓鐨?thunk 缁撴瀯)
 * - 鏀寔寤惰繜鍔犺浇瀵煎叆琛?(Delay-Load Import)
 *
 * 娉ㄦ剰锛氭瑙ｆ瀽鍣ㄤ緷璧栦簬 CNtHeadersParser 鎻愪緵鐨勪俊鎭紝
 * 鍦ㄨ皟鐢?Parse() 涔嬪墠蹇呴』鍏堣皟鐢?SetNtHeadersInfo()銆?
 */
class CImportTableParser : public IParser
{
public:
    CImportTableParser();
    virtual ~CImportTableParser() = default;

    // 绂佺敤鎷疯礉
    CImportTableParser(const CImportTableParser&) = delete;
    CImportTableParser& operator=(const CImportTableParser&) = delete;

    // === IParser 鎺ュ彛瀹炵幇 ===

    /**
     * @brief 鍒濆鍖栧鍏ヨ〃瑙ｆ瀽鍣?
     * @param pFileData 鏄犲皠鍚庣殑鏂囦欢鏁版嵁鍩哄潃
     * @param fileSize 鏂囦欢澶у皬
     * @return true 鍒濆鍖栨垚鍔燂紝false 鍒濆鍖栧け璐?
     */
    virtual bool Initialize(const uint8_t* pFileData, size_t fileSize) override;

    /**
     * @brief 鎵ц瀵煎叆琛ㄨВ鏋?
     * @return true 瑙ｆ瀽鎴愬姛锛宖alse 瑙ｆ瀽澶辫触
     *
     * 娉ㄦ剰锛氬湪璋冪敤 Parse() 涔嬪墠锛屽繀椤诲厛璋冪敤 SetNtHeadersInfo()
     * 璁剧疆 NT 澶磋В鏋愬櫒鎻愪緵鐨勫鍏ヨ〃 RVA 鍜?PE32/PE32+ 鏍囧織銆?
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
     * @brief 鑾峰彇瑙ｆ瀽鍚庣殑瀵煎叆琛ㄤ俊鎭?
     * @return 甯搁噺寮曠敤鍒板鍏?DLL 淇℃伅鍚戦噺
     */
    const std::vector<ImportDllInfo>& GetImportDlls() const;

    /**
     * @brief 璁剧疆 NT 澶磋В鏋愪俊鎭?(鐢?CPEAnalyzer 鎻愪緵)
     * @param dataDirectoryRVA 瀵煎叆琛ㄦ暟鎹洰褰?RVA
     * @param dataDirectorySize 瀵煎叆琛ㄦ暟鎹洰褰曞ぇ灏?
     * @param isPE32Plus 鏄惁涓?PE32+
     * @param imageBase 闀滃儚鍩哄潃
     */
    void SetNtHeadersInfo(DWord dataDirectoryRVA, DWord dataDirectorySize,
                          bool isPE32Plus, QWord imageBase);

private:
    /**
     * @brief 灏?RVA 杞崲涓烘枃浠跺亸绉?
     * @param rva 鐩稿铏氭嫙鍦板潃
     * @return 鏂囦欢鍋忕Щ锛屽鏋滆浆鎹㈠け璐ヨ繑鍥?0
     *
     * 閫氳繃閬嶅巻鑺傝〃灏?RVA 杞崲涓烘枃浠跺亸绉汇€?
     */
    DWord RvaToFileOffset(DWord rva) const;

    /**
     * @brief 瑙ｆ瀽鍗曚釜瀵煎叆鎻忚堪绗?
     * @param pImportDesc 鎸囧悜瀵煎叆鎻忚堪绗︾殑鎸囬拡
     * @param importInfo 杈撳嚭鍙傛暟锛屽～鍏呭鍏?DLL 淇℃伅
     * @return true 瑙ｆ瀽鎴愬姛
     */
    bool ParseImportDescriptor(const IMAGE_IMPORT_DESCRIPTOR* pImportDesc,
                               ImportDllInfo& importInfo);

    /**
     * @brief 瑙ｆ瀽瀵煎叆鍑芥暟 (閫氳繃 OriginalFirstThunk)
     * @param originalFirstThunkRVA OriginalFirstThunk 鐨?RVA
     * @param functions 杈撳嚭鍙傛暟锛屽～鍏呭鍏ュ嚱鏁板垪琛?
     * @return true 瑙ｆ瀽鎴愬姛
     */
    bool ParseImportFunctions(DWord originalFirstThunkRVA,
                              std::vector<ImportFunctionInfo>& functions);

    /**
     * @brief 瑙ｆ瀽寤惰繜鍔犺浇瀵煎叆琛?
     * @return true 瑙ｆ瀽鎴愬姛 (鎴栨病鏈夊欢杩熷姞杞藉鍏?
     */
    bool ParseDelayLoadImports();

    const uint8_t*  m_pFileData;            ///< 鏂囦欢鏁版嵁鍩哄潃
    size_t          m_fileSize;             ///< 鏂囦欢澶у皬
    DWord           m_dataDirectoryRVA;     ///< 瀵煎叆琛ㄦ暟鎹洰褰?RVA
    DWord           m_dataDirectorySize;    ///< 瀵煎叆琛ㄦ暟鎹洰褰曞ぇ灏?
    bool            m_isPE32Plus;           ///< 鏄惁涓?PE32+
    QWord           m_imageBase;            ///< 闀滃儚鍩哄潃
    bool            m_hasNtHeadersInfo;     ///< 鏄惁宸茶缃?NT 澶翠俊鎭?

    std::vector<ImportDllInfo> m_imports;   ///< 瑙ｆ瀽缁撴灉
    EErrorCode      m_lastError;            ///< 鏈€鍚庝竴娆￠敊璇爜
    bool            m_isInitialized;        ///< 鏄惁宸插垵濮嬪寲
    bool            m_isParsed;             ///< 鏄惁宸茶В鏋?
};

} // namespace PE
