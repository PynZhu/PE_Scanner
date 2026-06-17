/**
 * @file PEAnalyzer.h
 * @brief PE闈欐€佸畨鍏ㄥ垎鏋愬櫒鏍稿績鎺у埗绫诲０鏄?
 * @date 2026-06-17
 *
 * CPEAnalyzer 鏄暣涓垎鏋愬櫒鐨勬牳蹇冩帶鍒剁被锛?
 * 鍗忚皟鏂囦欢鍔犺浇銆佽В鏋愬櫒鎵ц銆佸垎鏋愬櫒鎵ц绛夊畬鏁存祦绋嬨€?
 */

#pragma once

#include "Core/Types.h"
#include "Core/ErrorCodes.h"
#include "Core/Logger.h"
#include "Interfaces/IParser.h"
#include "Interfaces/IAnalyzer.h"
#include "Analyzers/AnalyzerManager.h"
#include "Utils/FileMapper.h"
#include "Signatures/ScriptManager.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <string>

namespace PE {

/**
 * @brief PE 鍒嗘瀽鍣ㄦ牳蹇冩帶鍒剁被
 *
 * 璐熻矗鍗忚皟鏁翠釜 PE 鍒嗘瀽娴佺▼锛?
 * 1. 鍔犺浇 PE 鏂囦欢 (閫氳繃 CFileMapper)
 * 2. 娉ㄥ唽骞舵墽琛岃В鏋愬櫒 (IParser)
 * 3. 娉ㄥ唽骞舵墽琛屽垎鏋愬櫒 (IAnalyzer)
 * 4. 瀵煎嚭鍒嗘瀽缁撴灉 (JSON/Markdown)
 *
 * 浣跨敤绀轰緥锛?
 * @code
 * CPEAnalyzer analyzer;
 * if (analyzer.RunFullAnalysis(L"test.exe"))
 * {
 *     std::string json = analyzer.ExportJSON();
 *     std::cout << json << std::endl;
 * }
 * @endcode
 */
class CPEAnalyzer
{
public:
    CPEAnalyzer();
    ~CPEAnalyzer();

    // 绂佹鎷疯礉
    CPEAnalyzer(const CPEAnalyzer&) = delete;
    CPEAnalyzer& operator=(const CPEAnalyzer&) = delete;

    // ========================================================================
    // 鏍稿績娴佺▼
    // ========================================================================

    /**
     * @brief 鍔犺浇 PE 鏂囦欢鍒板唴瀛?
     * @param filePath 鏂囦欢璺緞
     * @return true 鍔犺浇鎴愬姛锛宖alse 鍔犺浇澶辫触
     *
     * 浣跨敤鍐呭瓨鏄犲皠鏂囦欢鏂瑰紡鍔犺浇锛屾敮鎸佸ぇ鏂囦欢楂樻晥澶勭悊銆?
     */
    bool LoadFile(const std::wstring& filePath);

    /**
     * @brief 鎵ц瀹屾暣瑙ｆ瀽 (璋冪敤鎵€鏈夊凡娉ㄥ唽鐨勮В鏋愬櫒)
     * @return true 鎵€鏈夎В鏋愬櫒鎵ц鎴愬姛锛宖alse 鏈夎В鏋愬櫒鎵ц澶辫触
     */
    bool ParseAll();

    /**
     * @brief 鎵ц瀹夊叏鍒嗘瀽 (璋冪敤鎵€鏈夊凡娉ㄥ唽鐨勫垎鏋愬櫒)
     * @return true 鎵€鏈夊垎鏋愬櫒鎵ц鎴愬姛锛宖alse 鏈夊垎鏋愬櫒鎵ц澶辫触
     */
    bool AnalyzeAll();

    /**
     * @brief 涓€閿墽琛岋細LoadFile + ParseAll + AnalyzeAll
     * @param filePath 鏂囦欢璺緞
     * @return true 瀹屾暣娴佺▼鎴愬姛锛宖alse 浠绘剰姝ラ澶辫触
     */
    bool RunFullAnalysis(const std::wstring& filePath);

    // ========================================================================
    // 瑙ｆ瀽鍣ㄧ鐞?
    // ========================================================================

    /**
     * @brief 娉ㄥ唽瑙ｆ瀽鍣?(鎻掍欢)
     * @param parser 瑙ｆ瀽鍣ㄥ敮涓€鎸囬拡
     *
     * 瑙ｆ瀽鍣ㄤ互鍚嶇О娉ㄥ唽锛屽悕绉扮敱瑙ｆ瀽鍣ㄧ被鍐冲畾銆?
     * 濡傛灉鍚屽悕瑙ｆ瀽鍣ㄥ凡瀛樺湪锛屼細瑕嗙洊鏃цВ鏋愬櫒銆?
     */
    void RegisterParser(std::unique_ptr<IParser> parser);

    /**
     * @brief 鑾峰彇鐗瑰畾绫诲瀷鐨勮В鏋愬櫒
     * @tparam T 瑙ｆ瀽鍣ㄧ被鍨?
     * @return 鎸囧悜瑙ｆ瀽鍣ㄧ殑鎸囬拡锛屾湭鎵惧埌鏃惰繑鍥?nullptr
     */
    template<typename T>
    T* GetParser() const
    {
        // 閫氳繃 RTTI 鑾峰彇绫诲瀷鍚嶇О浣滀负閿?
        const char* typeName = typeid(T).name();
        auto it = m_parsers.find(typeName);
        if (it != m_parsers.end())
        {
            return dynamic_cast<T*>(it->second.get());
        }
        return nullptr;
    }

    /**
     * @brief 鑾峰彇鎵€鏈夎В鏋愬櫒鐨勮В鏋愮粨鏋?
     * @return 瑙ｆ瀽鍣ㄥ悕绉板埌 JSON 缁撴灉鐨勬槧灏?
     */
    std::unordered_map<std::string, std::string> GetAllParserResults() const;

    // ========================================================================
    // 鍒嗘瀽鍣ㄧ鐞?
    // ========================================================================

    /**
     * @brief 娉ㄥ唽鍒嗘瀽鍣?(鎻掍欢)
     * @param analyzer 鍒嗘瀽鍣ㄥ敮涓€鎸囬拡
     */
    void RegisterAnalyzer(std::unique_ptr<IAnalyzer> analyzer);

    /**
     * @brief 鑾峰彇鍒嗘瀽鍣ㄧ鐞嗗櫒寮曠敤
     * @return CAnalyzerManager& 鍒嗘瀽鍣ㄧ鐞嗗櫒寮曠敤
     */
    CAnalyzerManager& GetAnalyzerManager();

    // ========================================================================
    // Script 绠＄悊
    // ========================================================================

    /**
     * @brief 鑾峰彇 Script 绠＄悊鍣ㄥ紩鐢?
     * @return CScriptManager& Script 绠＄悊鍣ㄥ紩鐢?
     */
    CScriptManager& GetScriptManager();

    /**
     * @brief 鎵ц鎵€鏈夎杞戒簡鐨勮剼鏈繘琛屽垎鏋?
     * @return std::vector<ScriptResult> 鑴氭湰鎵ц缁撴灉
     */
    std::vector<ScriptResult> RunScripts();

    /**
     * @brief 妫€鏌ユ槸鍚﹀凡鍔犺浇鑴氭湰
     * @return true 濡傛灉宸插姞杞借剼鏈?
     */
    bool HasScripts() const;

    // ========================================================================
    // 鐘舵€佹煡璇?
    // ========================================================================

    bool IsLoaded() const   { return m_isLoaded; }     ///< 鏂囦欢鏄惁宸插姞杞?
    bool IsParsed() const   { return m_isParsed; }     ///< 鏄惁宸茶В鏋?
    bool IsAnalyzed() const { return m_isAnalyzed; }   ///< 鏄惁宸插垎鏋?
    EErrorCode GetLastError() const { return m_lastError; }  ///< 鑾峰彇閿欒鐮?

    /**
     * @brief 鑾峰彇閿欒鎻忚堪
     * @return 閿欒鎻忚堪瀛楃涓?
     */
    std::string GetErrorDescription() const;

    /**
     * @brief 鑾峰彇 PE 淇℃伅
     * @return 甯搁噺寮曠敤鍒?PEInfo
     */
    const PEInfo& GetPEInfo() const { return m_peInfo; }

    // ========================================================================
    // 瀵煎嚭
    // ========================================================================

    /**
     * @brief 瀵煎嚭鍒嗘瀽缁撴灉涓?JSON 鏍煎紡
     * @return JSON 瀛楃涓?
     */
    std::string ExportJSON() const;

    /**
     * @brief 瀵煎嚭鍒嗘瀽缁撴灉涓?Markdown 鎶ュ憡
     * @return Markdown 瀛楃涓?
     */
    std::string ExportMarkdown() const;

private:
    /**
     * @brief 鍒濆鍖栨牳蹇冪粍浠?
     * @return true 鍒濆鍖栨垚鍔?
     */
    bool InitializeCore();

    /**
     * @brief 娓呯悊鎵€鏈夌姸鎬?
     */
    void Clear();

    std::unique_ptr<CFileMapper>                    m_fileMapper;       ///< 鏂囦欢鏄犲皠鍣?
    PEInfo                                          m_peInfo;           ///< PE 鏂囦欢淇℃伅

    // 瑙ｆ瀽鍣ㄦ敞鍐岃〃 (浣跨敤 RTTI 绫诲瀷鍚嶄綔涓洪敭)
    std::unordered_map<std::string, std::unique_ptr<IParser>> m_parsers;

    // 鍒嗘瀽鍣ㄧ鐞嗗櫒
    std::unique_ptr<CAnalyzerManager>               m_analyzerManager;  ///< 鍒嗘瀽鍣ㄧ鐞嗗櫒

    // Script 绠＄悊鍣?
    std::unique_ptr<CScriptManager>                 m_scriptManager;    ///< Script 绠＄悊鍣?

    // 鐘舵€佹爣蹇?
    bool        m_isLoaded;         ///< 鏂囦欢鏄惁宸插姞杞?
    bool        m_isParsed;         ///< 鏄惁宸茶В鏋?
    bool        m_isAnalyzed;       ///< 鏄惁宸插垎鏋?
    EErrorCode  m_lastError;        ///< 鏈€鍚庝竴娆￠敊璇爜
    std::string m_errorDescription; ///< 閿欒鎻忚堪
};

} // namespace PE
