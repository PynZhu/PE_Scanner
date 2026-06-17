/**
 * @file AnalyzerManager.cpp
 * @brief 鍒嗘瀽鍣ㄧ鐞嗗櫒瀹炵幇
 * @date 2026-06-17
 *
 * 绠＄悊鎵€鏈夊凡娉ㄥ唽鐨勫垎鏋愬櫒锛屽崗璋冨垎鏋愭祦绋嬨€?
 */

#include "../../Include/Analyzers/AnalyzerManager.h"
#include "../../Include/Core/Logger.h"

namespace PE {

// ============================================================================
// 鏋勯€犲嚱鏁?/ 鏋愭瀯鍑芥暟
// ============================================================================

CAnalyzerManager::CAnalyzerManager()
    : m_lastError(EErrorCode::Success)
{
}

CAnalyzerManager::~CAnalyzerManager()
{
    Clear();
}

// ============================================================================
// 鍒嗘瀽鍣ㄧ鐞?
// ============================================================================

void CAnalyzerManager::RegisterAnalyzer(std::unique_ptr<IAnalyzer> analyzer)
{
    if (analyzer == nullptr)
    {
        LOG_ERROR("CAnalyzerManager::RegisterAnalyzer: null analyzer pointer");
        return;
    }

    std::string name = analyzer->GetName();
    m_analyzers[name] = std::move(analyzer);
    LOG_DEBUG_F("CAnalyzerManager::RegisterAnalyzer: 娉ㄥ唽鍒嗘瀽鍣?'%s'", name.c_str());
}

bool CAnalyzerManager::RunAllAnalyzers(const PEInfo& peInfo)
{
    if (m_analyzers.empty())
    {
        LOG_WARNING("CAnalyzerManager::RunAllAnalyzers: 鏈敞鍐屼换浣曞垎鏋愬櫒");
        return true; // 娌℃湁鍒嗘瀽鍣ㄤ笉绠楅敊璇?
    }

    m_results.clear();
    bool allSuccess = true;

    for (auto& [name, analyzer] : m_analyzers)
    {
        LOG_INFO_F("CAnalyzerManager::RunAllAnalyzers: 鎵ц鍒嗘瀽鍣?'%s'", name.c_str());

        if (!analyzer->Analyze(peInfo))
        {
            LOG_ERROR_F("CAnalyzerManager::RunAllAnalyzers: 鍒嗘瀽鍣?'%s' 鎵ц澶辫触", name.c_str());
            allSuccess = false;
            continue;
        }

        // 鏀堕泦鍒嗘瀽缁撴灉
        auto results = analyzer->GetResults();
        m_results.insert(m_results.end(), results.begin(), results.end());

        LOG_INFO_F("CAnalyzerManager::RunAllAnalyzers: 鍒嗘瀽鍣?'%s' 瀹屾垚 (%zu 鏉＄粨鏋?",
                   name.c_str(), results.size());
    }

    m_lastError = allSuccess ? EErrorCode::Success : EErrorCode::AnalysisFailed;
    return allSuccess;
}

void CAnalyzerManager::Clear()
{
    m_analyzers.clear();
    m_results.clear();
    m_lastError = EErrorCode::Success;
}

// ============================================================================
// 缁撴灉鑾峰彇
// ============================================================================

const std::vector<AnalysisResult>& CAnalyzerManager::GetAllResults() const
{
    return m_results;
}

EErrorCode CAnalyzerManager::GetLastError() const
{
    return m_lastError;
}

size_t CAnalyzerManager::GetAnalyzerCount() const
{
    return m_analyzers.size();
}

} // namespace PE
