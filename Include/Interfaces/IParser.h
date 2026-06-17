/**
 * @file IParser.h
 * @brief PE闈欐€佸畨鍏ㄥ垎鏋愬櫒瑙ｆ瀽鍣ㄦ帴鍙ｅ畾涔?
 * @date 2026-06-17
 *
 * 鏈枃浠跺畾涔変簡鎵€鏈夎В鏋愬櫒蹇呴』瀹炵幇鐨勬帴鍙?IParser銆?
 * 閲囩敤绾櫄鎺ュ彛璁捐锛屾墍鏈夎В鏋愬櫒閫氳繃姝ゆ帴鍙ｅ疄鐜板鎬佽皟鐢ㄣ€?
 */

#pragma once

#include "../Core/Types.h"
#include "../Core/ErrorCodes.h"
#include <string>

namespace PE {

/**
 * @brief 瑙ｆ瀽鍣ㄦ帴鍙?- 鎵€鏈夎В鏋愬櫒蹇呴』瀹炵幇姝ゆ帴鍙?
 *
 * 瑙ｆ瀽鍣ㄨ礋璐ｄ粠 PE 鏂囦欢鐨勪簩杩涘埗鏁版嵁涓彁鍙栫壒瀹氱粨鏋勭殑淇℃伅銆?
 * 姣忎釜瑙ｆ瀽鍣ㄤ笓娉ㄤ簬瑙ｆ瀽 PE 鏂囦欢鐨勪竴涓壒瀹氶儴鍒嗭紙濡?DOS澶淬€丯T澶寸瓑锛夈€?
 *
 * 浣跨敤娴佺▼锛?
 * 1. Initialize() - 浼犲叆鏄犲皠鍚庣殑鏂囦欢鏁版嵁
 * 2. Parse() - 鎵ц瑙ｆ瀽
 * 3. GetResult() - 鑾峰彇瑙ｆ瀽缁撴灉
 * 4. 濡傛湁閿欒锛岃皟鐢?GetLastError() / GetErrorDescription()
 */
class IParser
{
public:
    virtual ~IParser() = default;

    /**
     * @brief 鍒濆鍖栬В鏋愬櫒
     * @param pFileData 鏄犲皠鍚庣殑鏂囦欢鏁版嵁鍩哄潃
     * @param fileSize 鏂囦欢澶у皬
     * @return true 鍒濆鍖栨垚鍔燂紝false 鍒濆鍖栧け璐?
     */
    virtual bool Initialize(const uint8_t* pFileData, size_t fileSize) = 0;

    /**
     * @brief 鎵ц瑙ｆ瀽
     * @return true 瑙ｆ瀽鎴愬姛锛宖alse 瑙ｆ瀽澶辫触
     */
    virtual bool Parse() = 0;

    /**
     * @brief 鑾峰彇瑙ｆ瀽缁撴灉 (JSON鏍煎紡瀛楃涓?
     * @return JSON鏍煎紡鐨勮В鏋愮粨鏋滃瓧绗︿覆
     */
    virtual std::string GetResult() const = 0;

    /**
     * @brief 鑾峰彇閿欒鐮?
     * @return 鏈€鍚庝竴娆℃搷浣滅殑閿欒鐮?
     */
    virtual EErrorCode GetLastError() const = 0;

    /**
     * @brief 鑾峰彇閿欒鎻忚堪
     * @return 鏈€鍚庝竴娆℃搷浣滅殑閿欒鎻忚堪
     */
    virtual std::string GetErrorDescription() const = 0;
};

} // namespace PE
