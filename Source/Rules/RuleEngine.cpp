/**
 * @file RuleEngine.cpp
 * @brief Rule engine implementation
 * @date 2026-06-17
 */

#include "../../Include/Rules/RuleEngine.h"
#include "../../Include/Rules/DangerousAPIs.h"
#include "../../Include/Utils/EntropyCalculator.h"
#include "../../Include/Core/Logger.h"
#include <algorithm>
#include <sstream>

namespace PE {

CRuleEngine::CRuleEngine()
{
    LOG_DEBUG("CRuleEngine: Created");
}

void CRuleEngine::RegisterRule(const SecurityRule& rule)
{
    m_rules.push_back(rule);
    LOG_DEBUG_F("CRuleEngine: Registered rule '%s'", rule.name.c_str());
}

std::vector<RuleFinding> CRuleEngine::ExecuteAll(const PEInfo& peInfo) const
{
    std::vector<RuleFinding> allFindings;

    for (const auto& rule : m_rules)
    {
        try
        {
            auto findings = rule.checkFunc(peInfo);
            allFindings.insert(allFindings.end(),
                               findings.begin(),
                               findings.end());
        }
        catch (const std::exception& e)
        {
            LOG_ERROR_F("CRuleEngine: Rule '%s' threw exception: %s",
                        rule.name.c_str(), e.what());
        }
    }

    return allFindings;
}

const std::vector<SecurityRule>& CRuleEngine::GetRules() const
{
    return m_rules;
}

void CRuleEngine::Clear()
{
    m_rules.clear();
    LOG_DEBUG("CRuleEngine: Cleared all rules");
}

size_t CRuleEngine::GetRuleCount() const
{
    return m_rules.size();
}

} // namespace PE
