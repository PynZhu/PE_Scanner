/**
 * @file PE_Scanner.cpp
 * @brief PE闈欐€佸畨鍏ㄥ垎鏋愬櫒涓诲叆鍙?
 * @date 2026-06-17
 *
 * 鍛戒护琛屽伐鍏蜂富鍏ュ彛锛屽鐞嗗懡浠よ鍙傛暟锛?
 * 璋冪敤 CPEAnalyzer 鎵ц PE 鏂囦欢鍒嗘瀽銆?
 */

#include "../Include/PEAnalyzer.h"
#include "../Include/Core/Logger.h"
#include "../Include/Core/Localization.h"
#include "../Include/Core/RiskLevel.h"
#include "../Include/Parsers/DosHeaderParser.h"
#include "../Include/Parsers/NtHeadersParser.h"
#include "../Include/Parsers/SectionParser.h"
#include "../Include/Parsers/ImportTableParser.h"
#include "../Include/Parsers/ExportTableParser.h"
#include "../Include/Analyzers/RiskAnalyzer.h"
#include "../Include/Utils/EntropyCalculator.h"
#include <iostream>
#include <string>
#include <iomanip>
#include <vector>


// ============================================================================
// 甯姪淇℃伅
// ============================================================================

/**
 * @brief 鎵撳嵃甯姪淇℃伅
 */
void PrintHelp()
{
    std::cout << R"(
鈺斺晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晽
鈺?           PE Static Sentinel - PE闈欐€佸畨鍏ㄥ垎鏋愬櫒             鈺?
鈺?                    Version 0.1.0                           鈺?
鈺氣晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨晲鈺愨暆

鐢ㄦ硶: PE_Scanner.exe [閫夐」] <PE鏂囦欢璺緞>

閫夐」:
  -h, --help         鏄剧ず姝ゅ府鍔╀俊鎭?
  -v, --version      鏄剧ず鐗堟湰淇℃伅
  -j, --json         浠?JSON 鏍煎紡杈撳嚭缁撴灉
  -m, --markdown     浠?Markdown 鏍煎紡杈撳嚭鎶ュ憡
  -d, --debug        鍚敤璋冭瘯鏃ュ織杈撳嚭

绀轰緥:
  PE_Scanner.exe test.exe             鍒嗘瀽 test.exe
  PE_Scanner.exe -j test.exe          浠?JSON 鏍煎紡杈撳嚭
  PE_Scanner.exe -m test.exe          鐢熸垚 Markdown 鎶ュ憡
  PE_Scanner.exe -d test.exe          鍚敤璋冭瘯鏃ュ織

)";
}

/**
 * @brief 鎵撳嵃鐗堟湰淇℃伅
 */
void PrintVersion()
{
    std::cout << "PE Static Sentinel v0.1.0" << std::endl;
    std::cout << "PE闈欐€佸畨鍏ㄥ垎鏋愬櫒" << std::endl;
    std::cout << "Built: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "Compiler: ";
#if defined(_MSC_VER)
    std::cout << "MSVC " << _MSC_VER;
#elif defined(__GNUC__)
    std::cout << "GCC " << __GNUC__ << "." << __GNUC_MINOR__;
#else
    std::cout << "Unknown";
#endif
    std::cout << std::endl;
}

// ============================================================================
// 涓诲嚱鏁?
// ============================================================================

/**
 * @brief 绋嬪簭鍏ュ彛鐐?
 * @param argc 鍙傛暟鏁伴噺
 * @param argv 鍙傛暟鏁扮粍
 * @return 0 鎴愬姛锛岄潪0 澶辫触
 */
int wmain(int argc, wchar_t* argv[])
{
    // 瑙ｆ瀽鍛戒护琛屽弬鏁?
    bool useJson     = false;
    bool useMarkdown = false;
    bool debugMode   = false;
    std::wstring filePath;

    if (argc < 2)
    {
        PrintHelp();
        return 1;
    }

    for (int i = 1; i < argc; ++i)
    {
        std::wstring arg = argv[i];

        if (arg == L"-h" || arg == L"--help" || arg == L"/?" || arg == L"-?" || arg == L"/h")
        {
            PrintHelp();
            return 0;
        }
        else if (arg == L"-v" || arg == L"--version")
        {
            PrintVersion();
            return 0;
        }
        else if (arg == L"-j" || arg == L"--json")
        {
            useJson = true;
        }
        else if (arg == L"-m" || arg == L"--markdown")
        {
            useMarkdown = true;
        }
        else if (arg == L"-d" || arg == L"--debug")
        {
            debugMode = true;
        }
        else if (arg[0] == L'-')
        {
            std::wcerr << L"鏈煡閫夐」: " << arg << std::endl;
            PrintHelp();
            return 1;
        }
        else
        {
            filePath = arg;
        }
    }

    // 妫€鏌ユ槸鍚︽彁渚涗簡鏂囦欢璺緞
    if (filePath.empty())
    {
        std::wcerr << L"閿欒: 鏈寚瀹?PE 鏂囦欢璺緞" << std::endl;
        PrintHelp();
        return 1;
    }

    // 璁剧疆鏃ュ織绾у埆
    if (debugMode)
    {
        PE::CLogger::GetInstance().SetLevel(PE::ELogLevel::Debug);
        LOG_DEBUG("Debug mode enabled");
    }

    // 鍒涘缓鏍稿績鍒嗘瀽鍣?
    PE::CPEAnalyzer analyzer;

    // 娉ㄥ唽瑙ｆ瀽鍣?
    analyzer.RegisterParser(std::make_unique<PE::CDosHeaderParser>());
    analyzer.RegisterParser(std::make_unique<PE::CNtHeadersParser>());
    analyzer.RegisterParser(std::make_unique<PE::CSectionParser>());
    analyzer.RegisterParser(std::make_unique<PE::CImportTableParser>());
    analyzer.RegisterParser(std::make_unique<PE::CExportTableParser>());

    // 娉ㄥ唽鍒嗘瀽鍣?
    analyzer.RegisterAnalyzer(std::make_unique<PE::CRiskAnalyzer>());

    // 鍒濆鍖?Script 绠＄悊鍣ㄥ苟鍔犺浇鑴氭湰
    auto& scriptManager = analyzer.GetScriptManager();
    if (scriptManager.Initialize())
    {
        // 鍔犺浇鍐呯疆鑴氭湰
        scriptManager.LoadScriptsFromDirectory("signatures/builtin");
        LOG_INFO_F("ScriptManager: Loaded %d scripts", scriptManager.GetScriptCount());
    }
    else
    {
        LOG_WARNING("ScriptManager: Failed to initialize, continuing without scripts");
    }

    LOG_INFO_F("寮€濮嬪垎鏋愭枃浠? %ls", filePath.c_str());


    // 鎵ц瀹屾暣鍒嗘瀽
    if (!analyzer.RunFullAnalysis(filePath))
    {
        LOG_ERROR_F("鍒嗘瀽澶辫触: %s", analyzer.GetErrorDescription().c_str());
        return 1;
    }

    // 杈撳嚭缁撴灉
    if (useJson)
    {
        std::cout << analyzer.ExportJSON() << std::endl;
    }
    else if (useMarkdown)
    {
        std::cout << analyzer.ExportMarkdown() << std::endl;
    }
    else
    {
        // 榛樿杈撳嚭鏍煎紡鍖栫殑鏂囨湰缁撴灉
        const PE::PEInfo& peInfo = analyzer.GetPEInfo();

        std::cout << "\n========== PE 鏂囦欢鍒嗘瀽缁撴灉 ==========\n";
        std::cout << "鏂囦欢璺緞: ";
        std::wcout << peInfo.filePath << std::endl;
        std::cout << "鏂囦欢澶у皬: " << peInfo.fileSize << " 瀛楄妭\n";
        std::cout << "PE 绫诲瀷: " << (peInfo.isPE32Plus ? "PE32+" : "PE32") << "\n";

        std::cout << "\n--- DOS 澶?---\n";
        std::cout << "e_magic:  0x" << std::hex << std::uppercase
                  << std::setw(4) << std::setfill('0') << peInfo.dosHeader.e_magic
                  << " (" << (peInfo.dosHeader.isValid ? "鏈夋晥" : "鏃犳晥") << ")\n";
        std::cout << "e_lfanew: " << std::dec << peInfo.dosHeader.e_lfanew << "\n";

        std::cout << "\n--- NT 澶?---\n";
        std::cout << "绛惧悕:     0x" << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0') << peInfo.ntHeaders.signature
                  << " (" << (peInfo.ntHeaders.isValid ? "鏈夋晥" : "鏃犳晥") << ")\n";

        std::cout << "\n--- 鏂囦欢澶?---\n";
        std::cout << "Machine:          0x" << std::hex << std::uppercase
                  << std::setw(4) << std::setfill('0')
                  << peInfo.ntHeaders.fileHeader.machine << "\n";
        std::cout << "鑺傚尯鏁伴噺:         " << std::dec
                  << peInfo.ntHeaders.fileHeader.numberOfSections << "\n";
        std::cout << "鍙€夊ご澶у皬:       "
                  << peInfo.ntHeaders.fileHeader.sizeOfOptionalHeader << "\n";
        std::cout << "Characteristics:  0x" << std::hex << std::uppercase
                  << std::setw(4) << std::setfill('0')
                  << peInfo.ntHeaders.fileHeader.characteristics << "\n";

        std::cout << "\n--- 鍙€夊ご ---\n";
        std::cout << "Magic:            0x" << std::hex << std::uppercase
                  << std::setw(4) << std::setfill('0')
                  << peInfo.ntHeaders.optionalHeader.magic << "\n";
        std::cout << "鍏ュ彛鐐?           0x" << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0')
                  << peInfo.ntHeaders.optionalHeader.addressOfEntryPoint << "\n";
        std::cout << "闀滃儚鍩哄潃:         0x" << std::hex << std::uppercase
                  << peInfo.ntHeaders.optionalHeader.imageBase << "\n";
        std::cout << "闀滃儚澶у皬:         " << std::dec
                  << peInfo.ntHeaders.optionalHeader.sizeOfImage << "\n";
        std::cout << "澶村ぇ灏?           "
                  << peInfo.ntHeaders.optionalHeader.sizeOfHeaders << "\n";
        std::cout << "鏍￠獙鍜?           0x" << std::hex << std::uppercase
                  << std::setw(8) << std::setfill('0')
                  << peInfo.ntHeaders.optionalHeader.checkSum << "\n";
        std::cout << "瀛愮郴缁?           "
                  << peInfo.ntHeaders.optionalHeader.subsystem << "\n";

        // 鏄剧ず鑺傝〃淇℃伅
        if (!peInfo.sections.empty())
        {
            std::cout << "\n--- 鑺傝〃 ---\n";
            std::cout << std::left
                      << std::setw(10) << "鍚嶇О"
                      << std::setw(12) << "铏氭嫙鍦板潃"
                      << std::setw(10) << "铏氭嫙澶у皬"
                      << std::setw(10) << "鍘熷澶у皬"
                      << std::setw(8) << "Entropy"
                      << std::setw(6) << "R"
                      << std::setw(6) << "W"
                      << std::setw(6) << "X"
                      << "\n";
            std::cout << std::string(68, '-') << "\n";

            for (const auto& sec : peInfo.sections)
            {
                std::cout << std::left
                          << std::setw(10) << sec.name
                          << "0x" << std::hex << std::uppercase
                          << std::setw(8) << std::setfill('0') << sec.virtualAddress
                          << std::dec << std::setfill(' ')
                          << std::setw(12) << sec.virtualSize
                          << std::setw(10) << sec.sizeOfRawData
                          << std::fixed << std::setprecision(2)
                          << std::setw(8) << sec.entropy
                          << std::setw(6) << (sec.isReadable ? "Y" : "N")
                          << std::setw(6) << (sec.isWritable ? "Y" : "N")
                          << std::setw(6) << (sec.isExecutable ? "Y" : "N")
                          << "\n";
            }
        }

        // 鏄剧ず瀵煎叆琛ㄤ俊鎭?
        if (!peInfo.imports.empty())
        {
            std::cout << "\n--- 瀵煎叆琛?---\n";
            for (const auto& dll : peInfo.imports)
            {
                std::cout << "DLL: " << dll.dllName
                          << " (" << dll.functions.size() << " 涓嚱鏁?\n";
                for (const auto& func : dll.functions)
                {
                    std::cout << "  - ";
                    if (func.isOrdinal)
                    {
                        std::cout << "[搴忓彿] " << func.ordinal;
                    }
                    else
                    {
                        std::cout << func.name;
                    }
                    std::cout << "\n";
                }
            }
        }

        // 鏄剧ず瀵煎嚭琛ㄤ俊鎭?
        if (!peInfo.exports.empty())
        {
            std::cout << "\n--- 瀵煎嚭琛?---\n";
            for (const auto& exp : peInfo.exports)
            {
                std::cout << "  " << exp.name
                          << " (搴忓彿: " << exp.ordinal
                          << ", 鍦板潃: 0x" << std::hex << std::uppercase
                          << std::setw(8) << std::setfill('0') << exp.address
                          << std::dec << std::setfill(' ') << ")";
                if (exp.isForwarder)
                {
                    std::cout << " -> " << exp.forwarderName;
                }
                std::cout << "\n";
            }
        }

        std::cout << "\n========================================\n";

        // 杈撳嚭瀹夊叏鍒嗘瀽鎶ュ憡
        if (analyzer.IsAnalyzed())
        {
            auto& analyzerManager = analyzer.GetAnalyzerManager();
            auto results = analyzerManager.GetAllResults();
            if (!results.empty())
            {
                std::cout << "\n========== Security Analysis Report ==========\n\n";

                // 鏄剧ず鎵€鏈夊垎鏋愬櫒缁撴灉
                for (const auto& result : results)
                {
                    std::cout << "Analyzer: " << result.name << "\n";
                    std::cout << "Risk Level: " << PE::RiskLevelToSymbol(result.riskLevel) << "\n";
                    std::cout << result.description << "\n\n";

                    for (const auto& detail : result.details)
                    {
                        std::cout << "  - " << detail << "\n";
                    }
                    std::cout << "\n";
                }

                std::cout << "============================================\n";
            }
        }

        // 杈撳嚭 Script 鍒嗘瀽缁撴灉
        if (analyzer.HasScripts())
        {
            auto scriptResults = analyzer.RunScripts();
            if (!scriptResults.empty())
            {
                std::cout << "\n========== Script Analysis Results ==========\n\n";

                for (const auto& result : scriptResults)
                {
                    std::cout << "Script: " << result.scriptName << "\n";
                    std::cout << "Status: " << (result.success ? "SUCCESS" : "FAILED") << "\n";

                    if (result.success)
                    {
                        std::cout << "Risk Level: " << PE::RiskLevelToSymbol(result.riskLevel) << "\n";
                        std::cout << result.description << "\n\n";

                        for (const auto& detail : result.details)
                        {
                            std::cout << "  - " << detail << "\n";
                        }
                    }
                    else
                    {
                        std::cout << "Error: " << result.errorMessage << "\n";
                    }
                    std::cout << "\n";
                }

                std::cout << "============================================\n";
            }
        }

    }

    LOG_INFO("鍒嗘瀽瀹屾垚");
    return 0;
}
