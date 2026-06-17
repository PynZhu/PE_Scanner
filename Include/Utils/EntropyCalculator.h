/**
 * @file EntropyCalculator.h
 * @brief 棣欏啘鐔佃绠楀伐鍏峰０鏄?
 * @date 2026-06-17
 *
 * 鎻愪緵鍩轰簬棣欏啘鐔靛叕寮忕殑鏁版嵁鍧楃喌鍊艰绠楀姛鑳姐€?
 * 鐢ㄤ簬妫€娴婸E鏂囦欢涓彲鑳借鍘嬬缉鎴栧姞瀵嗙殑鑺傚尯銆?
 */

#pragma once

#include "../Core/Types.h"
#include <cstddef>

namespace PE {

/**
 * @brief 鐔靛€艰绠楀伐鍏?
 *
 * 瀹炵幇棣欏啘鐔?(Shannon Entropy) 璁＄畻锛?
 * H = -危(p_i * log2(p_i))
 *
 * 鍏朵腑 p_i 鏄 i 涓瓧鑺傚€煎嚭鐜扮殑姒傜巼銆?
 *
 * 鐔靛€艰寖鍥达細0.0 ~ 8.0
 * - 0.0 ~ 4.0: 浣庣喌 (鏅€氫唬鐮?鏁版嵁)
 * - 4.0 ~ 6.5: 涓喌 (娣峰悎鏁版嵁)
 * - 6.5 ~ 8.0: 楂樼喌 (鍙兘琚帇缂?鍔犲瘑)
 */
class CEntropyCalculator
{
public:
    CEntropyCalculator() = default;
    ~CEntropyCalculator() = default;

    // 绂佺敤鎷疯礉
    CEntropyCalculator(const CEntropyCalculator&) = delete;
    CEntropyCalculator& operator=(const CEntropyCalculator&) = delete;

    /**
     * @brief 璁＄畻鏁版嵁鍧楃殑棣欏啘鐔?
     * @param pData 鏁版嵁鍧楁寚閽?
     * @param dataSize 鏁版嵁鍧楀ぇ灏?
     * @return 鐔靛€?(0.0 ~ 8.0)
     *
     * 濡傛灉鏁版嵁涓虹┖鎴栧ぇ灏忎负0锛岃繑鍥?0.0銆?
     * 浣跨敤 256 瀛楄妭棰戠巼琛ㄧ粺璁℃瘡涓瓧鑺傚€肩殑鍑虹幇娆℃暟銆?
     */
    static float CalculateEntropy(const uint8_t* pData, size_t dataSize);

    /**
     * @brief 鍒ゆ柇鐔靛€兼槸鍚︿负楂樼喌
     * @param entropy 鐔靛€?
     * @return true 濡傛灉鐔靛€?> 6.5
     */
    static bool IsHighEntropy(float entropy);

    /**
     * @brief 鑾峰彇鐔靛€肩瓑绾ф弿杩?
     * @param entropy 鐔靛€?
     * @return 鎻忚堪瀛楃涓?("浣庣喌", "涓喌", "楂樼喌")
     */
    static const char* GetEntropyLevel(float entropy);
};

} // namespace PE
