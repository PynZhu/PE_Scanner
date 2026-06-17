/**
 * @file AnalyzerManager.h
 * @brief 鍒嗘瀽鍣ㄧ鐞嗗櫒澹版槑
 * @date 2026-06-17
 *
 * 鍒嗘瀽鍣ㄧ鐞嗗櫒璐熻矗绠＄悊鎵€鏈夊凡娉ㄥ唽鐨勫畨鍏ㄥ垎鏋愬櫒锛?
 * 鍗忚皟鍒嗘瀽鍣ㄧ殑鎵ц椤哄簭锛屽苟姹囨€诲垎鏋愮粨鏋溿€?
 */

#pragma once

#include "../Interfaces/IAnalyzer.h"
#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <memory>
#include <vector>
#include <unordered_map>

namespace PE {

/**
 * @brief 鍒嗘瀽鍣ㄧ鐞嗗櫒
 *
 * 璐熻矗锛?
 * - 娉ㄥ唽/娉ㄩ攢鍒嗘瀽鍣?
 * - 鎸変緷璧栧叧绯绘帓搴忔墽琛屽垎鏋愬櫒
 * - 姹囨€绘墍鏈夊垎鏋愮粨鏋?
 * - 妫€鏌ュ垎鏋愬櫒渚濊禆鐨勮В鏋愬櫒鏄惁鍙敤
 */
class CAnalyzerManager
{
public:
    CAnalyzerManager();
    ~CAnalyzerManager();

    // 绂佺敤鎷疯礉
    CAnalyzerManager(const CAnalyzerManager&) = delete;
    CAnalyzerManager& operator=(const CAnalyzerManager&) = delete;

    /**
     * @brief 娉ㄥ唽鍒嗘瀽鍣?
     * @param analyzer 鍒嗘瀽鍣ㄥ敮涓€鎸囬拡
     */
    void RegisterAnalyzer(std::unique_ptr<IAnalyzer> analyzer);

    /**
     * @brief 鎵ц鎵€鏈夊凡娉ㄥ唽鐨勫垎鏋愬櫒
     * @param peInfo 宸茶В鏋愮殑 PE 鏂囦欢淇℃伅
     * @return true 鎵€鏈夊垎鏋愬櫒鎵ц鎴愬姛锛宖alse 鏈夊垎鏋愬櫒鎵ц澶辫触
     */
    bool RunAllAnalyzers(const PEInfo& peInfo);

    /**
     * @brief 鑾峰彇鎵€鏈夊垎鏋愮粨鏋?
     * @return 鎵€鏈夊垎鏋愮粨鏋滅殑鍚戦噺
     */
    const std::vector<AnalysisResult>& GetAllResults() const;

    /**
     * @brief 鑾峰彇宸叉敞鍐岀殑鍒嗘瀽鍣ㄦ暟閲?
     * @return 鍒嗘瀽鍣ㄦ暟閲?
     */
    size_t GetAnalyzerCount() const;

    /**
     * @brief 娓呯┖鎵€鏈夊垎鏋愬櫒
     */
    void Clear();

    /**
     * @brief 鑾峰彇鏈€鍚庝竴娆￠敊璇爜
     * @return 閿欒鐮?
     */
    EErrorCode GetLastError() const;

private:
    /**
     * @brief 妫€鏌ュ垎鏋愬櫒鐨勪緷璧栨槸鍚︽弧瓒?
     * @param analyzer 瑕佹鏌ョ殑鍒嗘瀽鍣?
     * @param availableParsers 鍙敤鐨勮В鏋愬櫒鍚嶇О鍒楄〃
     * @return true 渚濊禆婊¤冻
     */
    bool CheckDependencies(const IAnalyzer* analyzer,
                           const std::vector<std::string>& availableParsers) const;

    // 浣跨敤鍚嶇О浣滀负閿殑鍒嗘瀽鍣ㄦ槧灏勮〃
    std::unordered_map<std::string, std::unique_ptr<IAnalyzer>> m_analyzers;

    std::vector<AnalysisResult> m_results;  ///< 鍒嗘瀽缁撴灉姹囨€?
    EErrorCode                  m_lastError; ///< 鏈€鍚庝竴娆￠敊璇爜
};

} // namespace PE
