/**
 * @file RiskAnalyzer.cpp
 * @brief Risk analyzer implementation
 * @date 2026-06-17
 *
 * Implements comprehensive security risk analysis for PE files.
 * Checks for dangerous APIs, high entropy, packing indicators, etc.
 */

#include "../../Include/Analyzers/RiskAnalyzer.h"
#include "../../Include/Core/Logger.h"
#include "../../Include/Core/Localization.h"
#include "../../Include/Utils/EntropyCalculator.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>

namespace PE {

CRiskAnalyzer::CRiskAnalyzer()
    : m_overallRisk(ERiskLevel::None)
    , m_ruleEngine(std::make_unique<CRuleEngine>())
{
    LOG_DEBUG("CRiskAnalyzer: Created");
}

std::string CRiskAnalyzer::GetName() const
{
    return "RiskAnalyzer";
}

std::vector<std::string> CRiskAnalyzer::GetRequiredParsers() const
{
    return {"ImportTableParser", "SectionParser"};
}

bool CRiskAnalyzer::Analyze(const PEInfo& peInfo)
{
    LOG_INFO("CRiskAnalyzer: Starting security analysis");

    // Clear previous results
    m_results.clear();
    m_findings.clear();
    m_overallRisk = ERiskLevel::None;

    // Run all checks
    CheckDangerousAPIs(peInfo);
    CheckSectionEntropy(peInfo);
    CheckPackingIndicators(peInfo);
    CheckSuspiciousSections(peInfo);

    // Evaluate overall risk
    EvaluateOverallRisk();

    LOG_INFO_F("CRiskAnalyzer: Analysis complete, overall risk=%s",
               RiskLevelToString(m_overallRisk).c_str());

    return true;
}

void CRiskAnalyzer::CheckDangerousAPIs(const PEInfo& peInfo)
{
    LOG_DEBUG("CRiskAnalyzer: Checking dangerous APIs");

    auto& apiDB = CDangerousAPIs::GetInstance();
    std::unordered_map<std::string, std::vector<std::string>> dangerousByDll;
    std::set<std::string> foundCategories;

    for (const auto& dll : peInfo.imports)
    {
        for (const auto& func : dll.functions)
        {
            if (func.isOrdinal)
            {
                continue; // Skip ordinal imports (no name to match)
            }

            const DangerousApiInfo* pApiInfo = apiDB.FindApi(func.name);
            if (pApiInfo != nullptr)
            {
                dangerousByDll[dll.dllName].push_back(func.name);
                foundCategories.insert(CDangerousAPIs::CategoryToString(pApiInfo->category));

                // Add finding for each dangerous API
                std::string detail = dll.dllName + ": " + func.name;
                AddFinding(
                    "Dangerous API: " + func.name,
                    pApiInfo->description,
                    pApiInfo->riskLevel,
                    {detail});
            }
        }
    }

    // Log summary
    if (!dangerousByDll.empty())
    {
        std::ostringstream summary;
        summary << "Found dangerous APIs in " << dangerousByDll.size() << " DLLs";
        LOG_INFO_F("CRiskAnalyzer: %s", summary.str().c_str());

        for (const auto& [dll, apis] : dangerousByDll)
        {
            std::ostringstream dllInfo;
            dllInfo << "  " << dll << ": ";
            for (size_t i = 0; i < apis.size(); ++i)
            {
                if (i > 0) dllInfo << ", ";
                dllInfo << apis[i];
            }
            LOG_INFO_F("CRiskAnalyzer: %s", dllInfo.str().c_str());
        }
    }
}

void CRiskAnalyzer::CheckSectionEntropy(const PEInfo& peInfo)
{
    LOG_DEBUG("CRiskAnalyzer: Checking section entropy");

    for (const auto& section : peInfo.sections)
    {
        if (section.entropy > 7.0f)
        {
            std::ostringstream detail;
            detail << section.name << " section entropy = "
                   << std::fixed << std::setprecision(2) << section.entropy
                   << " (highly suspicious)";

            AddFinding(
                "High entropy section: " + section.name,
                "Section has very high entropy, possible packed/encrypted code",
                ERiskLevel::High,
                {detail.str()});
        }
        else if (section.entropy > 6.5f)
        {
            std::ostringstream detail;
            detail << section.name << " section entropy = "
                   << std::fixed << std::setprecision(2) << section.entropy;

            AddFinding(
                "Elevated entropy section: " + section.name,
                "Section has elevated entropy, may be packed",
                ERiskLevel::Medium,
                {detail.str()});
        }
    }
}

void CRiskAnalyzer::CheckPackingIndicators(const PEInfo& peInfo)
{
    LOG_DEBUG("CRiskAnalyzer: Checking packing indicators");

    // Known packer section names
    static const std::vector<std::pair<std::string, std::string>> packerSections = {
        {"UPX0",     "UPX"},
        {"UPX1",     "UPX"},
        {"UPX2",     "UPX"},
        {".UPX",     "UPX"},
        {"UPX!",     "UPX"},
        {".packed",  "Generic Packer"},
        {".pack",    "Generic Packer"},
        {"PACK",     "Generic Packer"},
        {".themida", "Themida"},
        {"themida",  "Themida"},
        {".vmp0",    "VMProtect"},
        {".vmp1",    "VMProtect"},
        {".vmp2",    "VMProtect"},
        {".vmp",     "VMProtect"},
        {".aspack",  "ASPack"},
        {"ASPack",   "ASPack"},
        {".petite",  "Petite"},
        {".MPRESS",  "MPRESS"},
        {".enigma",  "Enigma Protector"},
        {".nsp0",    "NSPack"},
        {".nsp1",    "NSPack"},
        {".nsp2",    "NSPack"},
    };

    for (const auto& section : peInfo.sections)
    {
        for (const auto& [secName, packer] : packerSections)
        {
            if (section.name.find(secName) != std::string::npos)
            {
                AddFinding(
                    "Packer detected: " + packer,
                    "File appears to be packed with " + packer,
                    ERiskLevel::Medium,
                    {"Section: " + section.name + " matches packer pattern: " + packer});
            }
        }
    }

    // Check for single section with high entropy (common in packed files)
    if (peInfo.sections.size() <= 2 && !peInfo.sections.empty())
    {
        for (const auto& section : peInfo.sections)
        {
            if (section.entropy > 6.5f)
            {
                AddFinding(
                    "Suspicious file structure",
                    "File has few sections with high entropy, possible packed file",
                    ERiskLevel::Medium,
                    {std::to_string(peInfo.sections.size()) + " sections, highest entropy: " +
                     std::to_string(section.entropy)});
            }
        }
    }
}

void CRiskAnalyzer::CheckSuspiciousSections(const PEInfo& peInfo)
{
    LOG_DEBUG("CRiskAnalyzer: Checking suspicious sections");

    // Check for writable + executable sections (common in packed/malicious files)
    for (const auto& section : peInfo.sections)
    {
        if (section.isWritable && section.isExecutable)
        {
            AddFinding(
                "Writable and executable section: " + section.name,
                "Section is both writable and executable (W^X violation)",
                ERiskLevel::High,
                {section.name + " has both write and execute permissions"});
        }
    }

    // Check for suspicious section names
    static const std::vector<std::string> knownNames = {
        ".data", ".rdata", ".text", ".bss", ".idata", ".edata",
        ".rsrc", ".reloc", ".tls", ".CRT"
    };

    for (const auto& section : peInfo.sections)
    {
        // Check if section name is unusual (not in the known list)
        bool isKnown = false;
        for (const auto& known : knownNames)
        {
            if (section.name == known)
            {
                isKnown = true;
                break;
            }
        }

        // Sections with unusual characters
        if (!section.name.empty() && !isKnown)
        {
            // Check if it looks like a random/generated name
            bool hasNonPrintable = false;
            for (char c : section.name)
            {
                if (c < 32 || c > 126)
                {
                    hasNonPrintable = true;
                    break;
                }
            }

            if (hasNonPrintable)
            {
                AddFinding(
                    "Suspicious section name: " + section.name,
                    "Section name contains non-printable characters",
                    ERiskLevel::Medium,
                    {"Section name may be intentionally obfuscated"});
            }
        }
    }
}

void CRiskAnalyzer::EvaluateOverallRisk()
{
    m_overallRisk = ERiskLevel::None;

    bool hasCritical = false;
    bool hasHigh = false;
    bool hasMedium = false;
    bool hasLow = false;

    for (const auto& result : m_results)
    {
        switch (result.riskLevel)
        {
            case ERiskLevel::Critical: hasCritical = true; break;
            case ERiskLevel::High:     hasHigh = true; break;
            case ERiskLevel::Medium:   hasMedium = true; break;
            case ERiskLevel::Low:      hasLow = true; break;
            default: break;
        }
    }

    // Determine overall risk based on highest severity
    if (hasCritical)
    {
        m_overallRisk = ERiskLevel::Critical;
    }
    else if (hasHigh)
    {
        m_overallRisk = ERiskLevel::High;
    }
    else if (hasMedium)
    {
        m_overallRisk = ERiskLevel::Medium;
    }
    else if (hasLow)
    {
        m_overallRisk = ERiskLevel::Low;
    }
    else
    {
        m_overallRisk = ERiskLevel::None;
    }

    // Apply scoring logic from requirements
    // Check for specific combinations that elevate risk
    bool hasInjectionAPI = false;
    bool hasNetworkAPI = false;
    bool hasProcessAPI = false;
    bool hasHighEntropy = false;

    for (const auto& result : m_results)
    {
        if (result.name.find("CreateRemoteThread") != std::string::npos ||
            result.name.find("VirtualAllocEx") != std::string::npos ||
            result.name.find("WriteProcessMemory") != std::string::npos)
        {
            hasInjectionAPI = true;
        }
        if (result.name.find("Internet") != std::string::npos ||
            result.name.find("URLDownload") != std::string::npos)
        {
            hasNetworkAPI = true;
        }
        if (result.name.find("CreateProcess") != std::string::npos ||
            result.name.find("ShellExecute") != std::string::npos)
        {
            hasProcessAPI = true;
        }
        if (result.name.find("entropy") != std::string::npos)
        {
            hasHighEntropy = true;
        }
    }

    // Critical: High entropy + injection APIs
    if (hasHighEntropy && hasInjectionAPI)
    {
        m_overallRisk = ERiskLevel::Critical;
    }
    // High: Injection APIs alone
    else if (hasInjectionAPI)
    {
        if (m_overallRisk < ERiskLevel::High)
            m_overallRisk = ERiskLevel::High;
    }
    // High: High entropy + network APIs
    else if (hasHighEntropy && hasNetworkAPI)
    {
        if (m_overallRisk < ERiskLevel::High)
            m_overallRisk = ERiskLevel::High;
    }
    // Medium: High entropy + process APIs
    else if (hasHighEntropy && hasProcessAPI)
    {
        if (m_overallRisk < ERiskLevel::Medium)
            m_overallRisk = ERiskLevel::Medium;
    }
}

void CRiskAnalyzer::AddFinding(const std::string& name,
                                const std::string& description,
                                ERiskLevel riskLevel,
                                const std::vector<std::string>& details)
{
    AnalysisResult result;
    result.name = name;
    result.description = description;
    result.riskLevel = riskLevel;
    result.details = details;
    m_results.push_back(result);

    // Also add to findings
    RuleFinding finding;
    finding.ruleName = name;
    finding.description = description;
    finding.riskLevel = riskLevel;
    finding.details = details;
    m_findings.push_back(finding);
}

std::vector<AnalysisResult> CRiskAnalyzer::GetResults() const
{
    return m_results;
}

ERiskLevel CRiskAnalyzer::GetOverallRiskLevel() const
{
    return m_overallRisk;
}

std::string CRiskAnalyzer::GetSecurityReport() const
{
    std::ostringstream report;

    report << "\n========== Security Analysis Report ==========\n\n";

    // Overall risk level
    report << "Overall Risk Level: ";
    switch (m_overallRisk)
    {
        case ERiskLevel::None:     report << "[SAFE]"; break;
        case ERiskLevel::Low:      report << "[LOW]"; break;
        case ERiskLevel::Medium:   report << "[MEDIUM]"; break;
        case ERiskLevel::High:     report << "[HIGH]"; break;
        case ERiskLevel::Critical: report << "[CRITICAL]"; break;
    }
    report << "\n\n";

    if (m_results.empty())
    {
        report << "No security issues detected.\n";
        report << "\n============================================\n";
        return report.str();
    }

    // Detected issues
    report << "Detected issues (" << m_results.size() << "):\n\n";

    int index = 1;
    for (const auto& result : m_results)
    {
        report << "  " << index << ". ";
        switch (result.riskLevel)
        {
            case ERiskLevel::Critical: report << "[CRITICAL] "; break;
            case ERiskLevel::High:     report << "[HIGH] ";     break;
            case ERiskLevel::Medium:   report << "[MEDIUM] ";   break;
            case ERiskLevel::Low:      report << "[LOW] ";      break;
            default:                   report << "[INFO] ";     break;
        }
        report << result.name << "\n";
        report << "     " << result.description << "\n";

        for (const auto& detail : result.details)
        {
            report << "     - " << detail << "\n";
        }
        report << "\n";
        ++index;
    }

    // Recommendations
    report << "Recommendations:\n";
    if (m_overallRisk >= ERiskLevel::High)
    {
        report << "  - This file may contain malicious code\n";
        report << "  - Run in an isolated environment only\n";
        report << "  - Do not execute on production systems\n";
    }
    else if (m_overallRisk >= ERiskLevel::Medium)
    {
        report << "  - This file shows suspicious characteristics\n";
        report << "  - Consider further analysis before execution\n";
    }
    else
    {
        report << "  - No immediate security concerns\n";
    }

    report << "\n============================================\n";

    return report.str();
}

} // namespace PE
