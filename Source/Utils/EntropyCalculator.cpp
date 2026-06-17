/**
 * @file EntropyCalculator.cpp
 * @brief 棣欏啘鐔佃绠楀伐鍏峰疄鐜?
 * @date 2026-06-17
 *
 * 瀹炵幇鍩轰簬棣欏啘鐔靛叕寮忕殑鏁版嵁鍧楃喌鍊艰绠椼€?
 * 浣跨敤 256 瀛楄妭棰戠巼琛ㄨ繘琛岀粺璁°€?
 */

#include "../../Include/Utils/EntropyCalculator.h"
#include <cmath>
#include <cstring>

namespace PE {

// ============================================================================
// 甯搁噺瀹氫箟
// ============================================================================

constexpr size_t BYTE_VALUE_COUNT = 256;   ///< 瀛楄妭鍊兼€绘暟 (0-255)
constexpr float  HIGH_ENTROPY_THRESHOLD = 6.5f;  ///< 楂樼喌闃堝€?

// ============================================================================
// 鐔靛€艰绠?
// ============================================================================

float CEntropyCalculator::CalculateEntropy(const uint8_t* pData, size_t dataSize)
{
    // 绌烘暟鎹鏌?
    if (pData == nullptr || dataSize == 0)
    {
        return 0.0f;
    }

    // 缁熻姣忎釜瀛楄妭鍊肩殑鍑虹幇棰戠巼
    uint32_t frequency[BYTE_VALUE_COUNT];
    std::memset(frequency, 0, sizeof(frequency));

    for (size_t i = 0; i < dataSize; ++i)
    {
        frequency[pData[i]]++;
    }

    // 璁＄畻棣欏啘鐔?
    // H = -危(p_i * log2(p_i))
    // 鍏朵腑 p_i = frequency[i] / dataSize
    double entropy = 0.0;
    const double sizeInv = 1.0 / static_cast<double>(dataSize);

    for (size_t i = 0; i < BYTE_VALUE_COUNT; ++i)
    {
        if (frequency[i] > 0)
        {
            double probability = static_cast<double>(frequency[i]) * sizeInv;
            entropy -= probability * std::log2(probability);
        }
    }

    return static_cast<float>(entropy);
}

// ============================================================================
// 鐔靛€煎垽鏂?
// ============================================================================

bool CEntropyCalculator::IsHighEntropy(float entropy)
{
    return entropy > HIGH_ENTROPY_THRESHOLD;
}

const char* CEntropyCalculator::GetEntropyLevel(float entropy)
{
    if (entropy <= 4.0f)
    {
        return "浣庣喌";
    }
    else if (entropy <= HIGH_ENTROPY_THRESHOLD)
    {
        return "涓喌";
    }
    else
    {
        return "楂樼喌";
    }
}

} // namespace PE
