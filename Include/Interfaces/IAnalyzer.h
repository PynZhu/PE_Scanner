/**
 * @file IAnalyzer.h
 * @brief PE闈欐€佸畨鍏ㄥ垎鏋愬櫒鍒嗘瀽鍣ㄦ帴鍙ｅ畾涔?
 * @date 2026-06-17
 *
 * 鏈枃浠跺畾涔変簡鎵€鏈夊畨鍏ㄥ垎鏋愬櫒蹇呴』瀹炵幇鐨勬帴鍙?IAnalyzer銆?
 * 鍒嗘瀽鍣ㄥ熀浜庤В鏋愬櫒鎻愪緵鐨?PE 缁撴瀯淇℃伅杩涜瀹夊叏鍒嗘瀽銆?
 */

#pragma once

#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>
#include <vector>

namespace PE {

/**
 * @brief 鍒嗘瀽缁撴灉缁撴瀯浣?
 *
 * 姣忎釜鍒嗘瀽鍣ㄥ彲浠ヤ骇鐢熷涓垎鏋愮粨鏋滐紝
 * 姣忎釜缁撴灉鍖呭惈鍚嶇О銆佹弿杩般€侀闄╃瓑绾у拰璇︾粏淇℃伅銆?
 */
struct AnalysisResult
{
    std::string name;                   ///< 鍒嗘瀽鍣ㄥ悕绉?
    std::string description;            ///< 鍒嗘瀽缁撴灉鎻忚堪
    ERiskLevel  riskLevel;              ///< 椋庨櫓绛夌骇
    std::vector<std::string> details;   ///< 璇︾粏淇℃伅鍒楄〃
};

/**
 * @brief 鍒嗘瀽鍣ㄦ帴鍙?- 鎵€鏈夊畨鍏ㄥ垎鏋愬櫒蹇呴』瀹炵幇姝ゆ帴鍙?
 *
 * 鍒嗘瀽鍣ㄨ礋璐ｅ宸茶В鏋愮殑 PE 淇℃伅杩涜瀹夊叏鍒嗘瀽锛?
 * 妫€娴嬫綔鍦ㄧ殑瀹夊叏椋庨櫓銆?
 *
 * 浣跨敤娴佺▼锛?
 * 1. Analyze() - 浼犲叆宸茶В鏋愮殑 PEInfo
 * 2. GetResults() - 鑾峰彇鍒嗘瀽缁撴灉鍒楄〃
 */
class IAnalyzer
{
public:
    virtual ~IAnalyzer() = default;

    /**
     * @brief 鑾峰彇鍒嗘瀽鍣ㄥ悕绉?
     * @return 鍒嗘瀽鍣ㄥ悕绉板瓧绗︿覆
     */
    virtual std::string GetName() const = 0;

    /**
     * @brief 鎵ц瀹夊叏鍒嗘瀽
     * @param peInfo 宸茶В鏋愮殑 PE 鏂囦欢淇℃伅
     * @return true 鍒嗘瀽鎴愬姛锛宖alse 鍒嗘瀽澶辫触
     */
    virtual bool Analyze(const PEInfo& peInfo) = 0;

    /**
     * @brief 鑾峰彇鍒嗘瀽缁撴灉鍒楄〃
     * @return 鍒嗘瀽缁撴灉鍚戦噺
     */
    virtual std::vector<AnalysisResult> GetResults() const = 0;

    /**
     * @brief 鑾峰彇姝ゅ垎鏋愬櫒渚濊禆鐨勮В鏋愬櫒鍒楄〃
     * @return 渚濊禆鐨勮В鏋愬櫒鍚嶇О鍒楄〃
     *
     * 渚嬪锛屽鍏ヨ〃鍒嗘瀽鍣ㄩ渶瑕佷緷璧?"NtHeadersParser" 鍜?"SectionParser"銆?
     * 鍒嗘瀽鍣ㄧ鐞嗗櫒浼氭牴鎹淇℃伅纭繚渚濊禆鐨勮В鏋愬櫒宸叉敞鍐屻€?
     */
    virtual std::vector<std::string> GetRequiredParsers() const = 0;
};

} // namespace PE
