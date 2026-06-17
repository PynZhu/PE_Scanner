/**
 * @file RuleEngine.h
 * @brief Rule engine for PE security analysis
 * @date 2026-06-17
 *
 * The rule engine loads security rules and executes them against
 * parsed PE information. Each rule checks for specific security
 * indicators and returns findings with risk levels.
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include "../Core/Types.h"
#include "../Core/RiskLevel.h"
#include "../Core/Logger.h"

namespace PE {

/**
 * @brief Security rule finding
 *
 * Represents a single finding from a rule check.
 * Contains the rule name, description, risk level, and details.
 */
struct RuleFinding
{
    std::string              ruleName;       ///< Name of the rule that triggered
    std::string              description;    ///< Human-readable description
    ERiskLevel               riskLevel;      ///< Risk level of this finding
    std::vector<std::string> details;        ///< Additional details/evidence
};

/**
 * @brief Rule function type
 *
 * Each rule is a function that takes PEInfo and returns findings.
 */
using RuleFunction = std::function<std::vector<RuleFinding>(const PEInfo&)>;

/**
 * @brief Security rule descriptor
 */
struct SecurityRule
{
    std::string  name;         ///< Rule name
    std::string  description;  ///< Rule description
    ERiskLevel   riskLevel;    ///< Default risk level
    RuleFunction checkFunc;    ///< The check function
};

/**
 * @brief Rule engine class
 *
 * Manages and executes security rules against PE file information.
 * Rules can be registered dynamically and executed in order.
 */
class CRuleEngine
{
public:
    CRuleEngine();
    ~CRuleEngine() = default;

    /**
     * @brief Register a new security rule
     * @param rule The rule to register
     */
    void RegisterRule(const SecurityRule& rule);

    /**
     * @brief Execute all registered rules against PE info
     * @param peInfo The parsed PE file information
     * @return std::vector<RuleFinding> All findings from all rules
     */
    std::vector<RuleFinding> ExecuteAll(const PEInfo& peInfo) const;

    /**
     * @brief Get all registered rules
     * @return const std::vector<SecurityRule>& List of registered rules
     */
    const std::vector<SecurityRule>& GetRules() const;

    /**
     * @brief Clear all registered rules
     */
    void Clear();

    /**
     * @brief Get the number of registered rules
     * @return size_t Rule count
     */
    size_t GetRuleCount() const;

private:
    std::vector<SecurityRule> m_rules;  ///< Registered rules
};

} // namespace PE
