/**
 * @file RiskAnalyzer.h
 * @brief Risk analyzer for PE security assessment
 * @date 2026-06-17
 *
 * Implements the IAnalyzer interface to perform comprehensive
 * security risk analysis on PE files. Checks for dangerous APIs,
 * high entropy sections, packing indicators, and more.
 */

#pragma once

#include "../Interfaces/IAnalyzer.h"
#include "../Core/Types.h"
#include "../Core/RiskLevel.h"
#include "../Rules/RuleEngine.h"
#include "../Rules/DangerousAPIs.h"
#include <memory>
#include <vector>

namespace PE {

/**
 * @brief Risk analyzer class
 *
 * Performs security analysis on parsed PE files by:
 * - Scanning import tables for dangerous APIs
 * - Checking section entropy values
 * - Detecting packing indicators
 * - Evaluating overall risk level
 */
class CRiskAnalyzer : public IAnalyzer
{
public:
    CRiskAnalyzer();
    virtual ~CRiskAnalyzer() = default;

    // IAnalyzer interface implementation
    virtual std::string GetName() const override;
    virtual bool Analyze(const PEInfo& peInfo) override;
    virtual std::vector<AnalysisResult> GetResults() const override;
    virtual std::vector<std::string> GetRequiredParsers() const override;

    /**
     * @brief Get the overall risk level
     * @return ERiskLevel The highest risk level found
     */
    ERiskLevel GetOverallRiskLevel() const;

    /**
     * @brief Get the security report as a formatted string
     * @return std::string Formatted security report
     */
    std::string GetSecurityReport() const;

private:
    /**
     * @brief Check import table for dangerous APIs
     * @param peInfo Parsed PE information
     */
    void CheckDangerousAPIs(const PEInfo& peInfo);

    /**
     * @brief Check section entropy for anomalies
     * @param peInfo Parsed PE information
     */
    void CheckSectionEntropy(const PEInfo& peInfo);

    /**
     * @brief Check for packing indicators
     * @param peInfo Parsed PE information
     */
    void CheckPackingIndicators(const PEInfo& peInfo);

    /**
     * @brief Check for suspicious section names
     * @param peInfo Parsed PE information
     */
    void CheckSuspiciousSections(const PEInfo& peInfo);

    /**
     * @brief Evaluate the overall risk level
     */
    void EvaluateOverallRisk();

    /**
     * @brief Add a finding to the results
     * @param name Finding name
     * @param description Finding description
     * @param riskLevel Risk level
     * @param details Additional details
     */
    void AddFinding(const std::string& name,
                    const std::string& description,
                    ERiskLevel riskLevel,
                    const std::vector<std::string>& details = {});

    std::vector<AnalysisResult> m_results;     ///< Analysis results
    ERiskLevel m_overallRisk;                   ///< Overall risk level
    std::vector<RuleFinding> m_findings;        ///< Detailed findings
    std::unique_ptr<CRuleEngine> m_ruleEngine;  ///< Rule engine instance
};

} // namespace PE
