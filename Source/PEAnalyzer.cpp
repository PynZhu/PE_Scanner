/**
 * @file PEAnalyzer.cpp
 * @brief PE闈欐€佸畨鍏ㄥ垎鏋愬櫒鏍稿績鎺у埗绫诲疄鐜?
 * @date 2026-06-17
 */

#include "../Include/PEAnalyzer.h"
#include "../Include/Parsers/DosHeaderParser.h"
#include "../Include/Parsers/NtHeadersParser.h"
#include "../Include/Parsers/SectionParser.h"
#include "../Include/Parsers/ImportTableParser.h"
#include "../Include/Parsers/ExportTableParser.h"
#include "../Include/Analyzers/RiskAnalyzer.h"
#include "../Include/Core/RiskLevel.h"
#include <sstream>
#include <iomanip>
#include <algorithm>


namespace PE {

// ============================================================================
// 鏋勯€犲嚱鏁?/ 鏋愭瀯鍑芥暟
// ============================================================================

CPEAnalyzer::CPEAnalyzer()
    : m_fileMapper(std::make_unique<CFileMapper>())
    , m_analyzerManager(std::make_unique<CAnalyzerManager>())
    , m_isLoaded(false)
    , m_isParsed(false)
    , m_isAnalyzed(false)
    , m_lastError(EErrorCode::Success)
{
    // 鍒濆鍖?PE 淇℃伅
    m_peInfo.filePath   = L"";
    m_peInfo.fileSize   = 0;
    m_peInfo.isPE32Plus = false;
}

CPEAnalyzer::~CPEAnalyzer()
{
    Clear();
}

// ============================================================================
// 鏍稿績娴佺▼
// ============================================================================

bool CPEAnalyzer::LoadFile(const std::wstring& filePath)
{
    // 娓呯悊涔嬪墠鐨勭姸鎬?
    Clear();

    // 鏄犲皠鏂囦欢
    if (!m_fileMapper->MapFile(filePath))
    {
        m_lastError = m_fileMapper->GetLastError();
        m_errorDescription = PE::GetErrorDescription(m_lastError);
        LOG_ERROR_F("CPEAnalyzer::LoadFile: 鏂囦欢鍔犺浇澶辫触 '%ls'", filePath.c_str());
        return false;
    }

    // 濉厖 PE 淇℃伅
    m_peInfo.filePath = filePath;
    m_peInfo.fileSize = m_fileMapper->GetSize();
    m_isLoaded = true;
    m_lastError = EErrorCode::Success;

    LOG_INFO_F("CPEAnalyzer::LoadFile: 鏂囦欢鍔犺浇鎴愬姛 (%zu 瀛楄妭)", m_peInfo.fileSize);
    return true;
}

bool CPEAnalyzer::ParseAll()
{
    if (!m_isLoaded)
    {
        m_lastError = EErrorCode::InvalidState;
        m_errorDescription = "鏂囦欢鏈姞杞斤紝璇峰厛璋冪敤 LoadFile()";
        LOG_ERROR("CPEAnalyzer::ParseAll: file not loaded");
        return false;
    }

    if (m_parsers.empty())
    {
        m_lastError = EErrorCode::InvalidState;
        m_errorDescription = "鏈敞鍐屼换浣曡В鏋愬櫒";
        LOG_ERROR("CPEAnalyzer::ParseAll: 鏈敞鍐岃В鏋愬櫒");
        return false;
    }

    const uint8_t* pFileData = m_fileMapper->GetData();
    size_t fileSize = m_fileMapper->GetSize();

    // 鍏堝垵濮嬪寲鎵€鏈夎В鏋愬櫒
    for (auto& [name, parser] : m_parsers)
    {
        if (!parser->Initialize(pFileData, fileSize))
        {
            m_lastError = parser->GetLastError();
            m_errorDescription = "瑙ｆ瀽鍣ㄥ垵濮嬪寲澶辫触: " + parser->GetErrorDescription();
            LOG_ERROR_F("CPEAnalyzer::ParseAll: parser '%s' init failed", name.c_str());
            return false;
        }
    }

    // 鍏堟墽琛?DOS 澶磋В鏋愬櫒 (闇€瑕佸厛鑾峰彇 e_lfanew)
    auto* pDosParser = GetParser<CDosHeaderParser>();
    if (pDosParser != nullptr)
    {
        if (!pDosParser->Parse())
        {
            m_lastError = pDosParser->GetLastError();
            m_errorDescription = "DOS澶磋В鏋愬け璐? " + pDosParser->GetErrorDescription();
            LOG_ERROR("CPEAnalyzer::ParseAll: DOS header parse failed");
            return false;
        }
        LOG_INFO("CPEAnalyzer::ParseAll: DOS header parse success");

        // 灏?e_lfanew 浼犻€掔粰 NT 澶磋В鏋愬櫒
        auto* pNtParser = GetParser<CNtHeadersParser>();
        if (pNtParser != nullptr)
        {
            pNtParser->SetELfanew(pDosParser->GetDosHeaderInfo().e_lfanew);
        }
    }

    // 鎵ц鍏朵綑瑙ｆ瀽鍣?
    for (auto& [name, parser] : m_parsers)
    {
        // 璺宠繃宸叉墽琛岀殑 DOS 澶磋В鏋愬櫒
        if (dynamic_cast<CDosHeaderParser*>(parser.get()) != nullptr)
        {
            continue;
        }

        if (!parser->Parse())
        {
            m_lastError = parser->GetLastError();
            m_errorDescription = "瑙ｆ瀽澶辫触: " + parser->GetErrorDescription();
            LOG_ERROR_F("CPEAnalyzer::ParseAll: 瑙ｆ瀽鍣?'%s' 瑙ｆ瀽澶辫触", name.c_str());
            return false;
        }

        LOG_INFO_F("CPEAnalyzer::ParseAll: 瑙ｆ瀽鍣?'%s' 鎵ц鎴愬姛", name.c_str());
    }

    // 浠庤В鏋愬櫒鎻愬彇 PE 淇℃伅
    // 鑾峰彇 DOS 澶翠俊鎭?(pDosParser 宸插湪涓婇潰澹版槑)
    if (pDosParser != nullptr)
    {
        m_peInfo.dosHeader = pDosParser->GetDosHeaderInfo();
    }

    // 鑾峰彇 NT 澶翠俊鎭?
    auto* pNtParser2 = GetParser<CNtHeadersParser>();
    if (pNtParser2 != nullptr)
    {
        m_peInfo.ntHeaders = pNtParser2->GetNtHeadersInfo();

        // 灏?NT 澶翠俊鎭紶閫掔粰渚濊禆鐨勮В鏋愬櫒
        const auto& ntHeaders = m_peInfo.ntHeaders;

        // 璁剧疆鑺傝〃瑙ｆ瀽鍣ㄧ殑 NT 澶翠俊鎭?
        auto* pSectionParser = GetParser<CSectionParser>();
        if (pSectionParser != nullptr)
        {
            pSectionParser->SetNtHeadersInfo(
                ntHeaders.fileHeader.numberOfSections,
                ntHeaders.fileHeader.sizeOfOptionalHeader,
                ntHeaders.optionalHeader.sectionAlignment);
        }

        // 璁剧疆瀵煎叆琛ㄨВ鏋愬櫒鐨?NT 澶翠俊鎭?
        // 瀵煎叆琛ㄦ暟鎹洰褰曠储寮曚负 1 (IMAGE_DIRECTORY_ENTRY_IMPORT)
        // 鐢变簬鎴戜滑娌℃湁鐩存帴瀛樺偍鏁版嵁鐩綍鏁扮粍锛岄渶瑕佷粠鍙€夊ご涓幏鍙?
        // 杩欓噷绠€鍖栧鐞嗭紝閫氳繃 NT 澶磋В鏋愬櫒鑾峰彇
        auto* pImportParser = GetParser<CImportTableParser>();
        if (pImportParser != nullptr)
        {
            // 浠?NT 澶磋В鏋愬櫒鑾峰彇瀵煎叆琛ㄦ暟鎹洰褰曚俊鎭?
            // 娉ㄦ剰锛氳繖閲岄渶瑕?NT 澶磋В鏋愬櫒鎻愪緵鏁版嵁鐩綍淇℃伅
            // 鐩墠绠€鍖栧鐞嗭紝浣跨敤 NT 澶磋В鏋愬櫒涓殑淇℃伅
            DWord importRVA = 0;
            DWord importSize = 0;

            // 閫氳繃 NT 澶磋В鏋愬櫒鑾峰彇瀵煎叆琛ㄦ暟鎹洰褰?
            // 鐢变簬鎴戜滑娌℃湁鍦?NtHeadersInfo 涓瓨鍌ㄦ暟鎹洰褰曟暟缁勶紝
            // 杩欓噷閫氳繃 NT 澶磋В鏋愬櫒鐨勫唴閮ㄦ柟娉曡幏鍙?
            // 绠€鍖栵細浠庢枃浠舵暟鎹腑鐩存帴璇诲彇
            const uint8_t* pFileData = m_fileMapper->GetData();
            size_t fileSize = m_fileMapper->GetSize();

            if (pFileData != nullptr && fileSize >= sizeof(IMAGE_DOS_HEADER))
            {
                const IMAGE_DOS_HEADER* pDosHdr =
                    reinterpret_cast<const IMAGE_DOS_HEADER*>(pFileData);
                DWord e_lfanew = pDosHdr->e_lfanew;

                if (e_lfanew + sizeof(DWord) + sizeof(IMAGE_FILE_HEADER) <= fileSize)
                {
                    const uint8_t* pNtHdr = pFileData + e_lfanew;
                    const IMAGE_FILE_HEADER* pFileHdr =
                        reinterpret_cast<const IMAGE_FILE_HEADER*>(pNtHdr + sizeof(DWord));

                    // 瀹氫綅鍒板彲閫夊ご涓殑鏁版嵁鐩綍
                    // PE32: 鍙€夊ご鍋忕Щ 96 澶勬槸鏁版嵁鐩綍
                    // PE32+: 鍙€夊ご鍋忕Щ 112 澶勬槸鏁版嵁鐩綍
                    const uint8_t* pOptHdr = reinterpret_cast<const uint8_t*>(pFileHdr + 1);
                    Word magic = *reinterpret_cast<const Word*>(pOptHdr);

                    // 鏁版嵁鐩綍鍦ㄥ彲閫夊ご涓殑鍋忕Щ
                    DWord dataDirOffset = 0;
                    if (magic == 0x20B) // PE32+
                    {
                        // PE32+ 鍙€夊ご涓紝鏁版嵁鐩綍鍦ㄥ亸绉?112 澶?
                        dataDirOffset = 112;
                    }
                    else // PE32
                    {
                        // PE32 鍙€夊ご涓紝鏁版嵁鐩綍鍦ㄥ亸绉?96 澶?
                        dataDirOffset = 96;
                    }

                    if (pOptHdr + dataDirOffset + sizeof(IMAGE_DATA_DIRECTORY) * 2 <= pFileData + fileSize)
                    {
                        const IMAGE_DATA_DIRECTORY* pDataDir =
                            reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(pOptHdr + dataDirOffset);

                        // 绱㈠紩 1 = IMAGE_DIRECTORY_ENTRY_IMPORT
                        importRVA  = pDataDir[1].VirtualAddress;
                        importSize = pDataDir[1].Size;

                        pImportParser->SetNtHeadersInfo(
                            importRVA, importSize,
                            m_peInfo.isPE32Plus,
                            ntHeaders.optionalHeader.imageBase);
                    }
                }
            }
        }

        // 璁剧疆瀵煎嚭琛ㄨВ鏋愬櫒鐨?NT 澶翠俊鎭?
        auto* pExportParser = GetParser<CExportTableParser>();
        if (pExportParser != nullptr)
        {
            DWord exportRVA = 0;
            DWord exportSize = 0;

            const uint8_t* pFileData = m_fileMapper->GetData();
            size_t fileSize = m_fileMapper->GetSize();

            if (pFileData != nullptr && fileSize >= sizeof(IMAGE_DOS_HEADER))
            {
                const IMAGE_DOS_HEADER* pDosHdr =
                    reinterpret_cast<const IMAGE_DOS_HEADER*>(pFileData);
                DWord e_lfanew = pDosHdr->e_lfanew;

                if (e_lfanew + sizeof(DWord) + sizeof(IMAGE_FILE_HEADER) <= fileSize)
                {
                    const uint8_t* pNtHdr = pFileData + e_lfanew;
                    const IMAGE_FILE_HEADER* pFileHdr =
                        reinterpret_cast<const IMAGE_FILE_HEADER*>(pNtHdr + sizeof(DWord));
                    const uint8_t* pOptHdr = reinterpret_cast<const uint8_t*>(pFileHdr + 1);
                    Word magic = *reinterpret_cast<const Word*>(pOptHdr);

                    DWord dataDirOffset = (magic == 0x20B) ? 112 : 96;

                    if (pOptHdr + dataDirOffset + sizeof(IMAGE_DATA_DIRECTORY) * 2 <= pFileData + fileSize)
                    {
                        const IMAGE_DATA_DIRECTORY* pDataDir =
                            reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(pOptHdr + dataDirOffset);

                        // 绱㈠紩 0 = IMAGE_DIRECTORY_ENTRY_EXPORT
                        exportRVA  = pDataDir[0].VirtualAddress;
                        exportSize = pDataDir[0].Size;

                        pExportParser->SetNtHeadersInfo(exportRVA, exportSize);
                    }
                }
            }
        }
    }

    // 浠庤妭琛ㄨВ鏋愬櫒鑾峰彇鑺傝〃淇℃伅
    auto* pSectionParser2 = GetParser<CSectionParser>();
    if (pSectionParser2 != nullptr)
    {
        m_peInfo.sections = pSectionParser2->GetSections();
    }

    // 浠庡鍏ヨ〃瑙ｆ瀽鍣ㄨ幏鍙栧鍏ヨ〃淇℃伅
    auto* pImportParser2 = GetParser<CImportTableParser>();
    if (pImportParser2 != nullptr)
    {
        m_peInfo.imports = pImportParser2->GetImportDlls();
    }

    // 浠庡鍑鸿〃瑙ｆ瀽鍣ㄨ幏鍙栧鍑鸿〃淇℃伅
    auto* pExportParser2 = GetParser<CExportTableParser>();
    if (pExportParser2 != nullptr)
    {
        m_peInfo.exports = pExportParser2->GetExports();
    }

    m_isParsed = true;
    m_lastError = EErrorCode::Success;
    LOG_INFO("CPEAnalyzer::ParseAll: 鎵€鏈夎В鏋愬櫒鎵ц瀹屾垚");
    return true;

}

bool CPEAnalyzer::AnalyzeAll()
{
    if (!m_isParsed)
    {
        m_lastError = EErrorCode::InvalidState;
        m_errorDescription = "鏂囦欢鏈В鏋愶紝璇峰厛璋冪敤 ParseAll()";
        LOG_ERROR("CPEAnalyzer::AnalyzeAll: file not parsed");
        return false;
    }

    if (!m_analyzerManager->RunAllAnalyzers(m_peInfo))
    {
        m_lastError = m_analyzerManager->GetLastError();
        m_errorDescription = "鍒嗘瀽鎵ц澶辫触";
        LOG_ERROR("CPEAnalyzer::AnalyzeAll: 鍒嗘瀽鎵ц澶辫触");
        return false;
    }

    m_isAnalyzed = true;
    m_lastError = EErrorCode::Success;
    LOG_INFO("CPEAnalyzer::AnalyzeAll: 鎵€鏈夊垎鏋愬櫒鎵ц瀹屾垚");
    return true;
}

bool CPEAnalyzer::RunFullAnalysis(const std::wstring& filePath)
{
    LOG_INFO_F("CPEAnalyzer::RunFullAnalysis: 寮€濮嬪畬鏁村垎鏋?'%ls'", filePath.c_str());

    if (!LoadFile(filePath))
    {
        return false;
    }

    if (!ParseAll())
    {
        return false;
    }

    if (!AnalyzeAll())
    {
        return false;
    }

    LOG_INFO("CPEAnalyzer::RunFullAnalysis: 瀹屾暣鍒嗘瀽鎴愬姛");
    return true;
}

// ============================================================================
// 瑙ｆ瀽鍣ㄧ鐞?
// ============================================================================

void CPEAnalyzer::RegisterParser(std::unique_ptr<IParser> parser)
{
    if (parser == nullptr)
    {
        LOG_ERROR("CPEAnalyzer::RegisterParser: null parser pointer");
        return;
    }

    // 浣跨敤 RTTI 绫诲瀷鍚嶄綔涓洪敭
    const char* typeName = typeid(*parser).name();
    m_parsers[typeName] = std::move(parser);

    LOG_DEBUG_F("CPEAnalyzer::RegisterParser: 娉ㄥ唽瑙ｆ瀽鍣?'%s'", typeName);
}

std::unordered_map<std::string, std::string> CPEAnalyzer::GetAllParserResults() const
{
    std::unordered_map<std::string, std::string> results;
    for (const auto& [name, parser] : m_parsers)
    {
        results[name] = parser->GetResult();
    }
    return results;
}

// ============================================================================
// 鍒嗘瀽鍣ㄧ鐞?
// ============================================================================

void CPEAnalyzer::RegisterAnalyzer(std::unique_ptr<IAnalyzer> analyzer)
{
    if (analyzer == nullptr)
    {
        LOG_ERROR("CPEAnalyzer::RegisterAnalyzer: null analyzer pointer");
        return;
    }

    m_analyzerManager->RegisterAnalyzer(std::move(analyzer));
}

CAnalyzerManager& CPEAnalyzer::GetAnalyzerManager()
{
    return *m_analyzerManager;
}

// ============================================================================
// Script 绠＄悊
// ============================================================================

CScriptManager& CPEAnalyzer::GetScriptManager()
{
    if (m_scriptManager == nullptr)
    {
        m_scriptManager = std::make_unique<CScriptManager>();
    }
    return *m_scriptManager;
}

std::vector<ScriptResult> CPEAnalyzer::RunScripts()
{
    if (m_scriptManager == nullptr)
    {
        LOG_ERROR("CPEAnalyzer::RunScripts: ScriptManager not initialized");
        return {};
    }

    if (!m_isParsed)
    {
        LOG_ERROR("CPEAnalyzer::RunScripts: file not parsed yet");
        return {};
    }

    // Set PE data for script execution
    const uint8_t* pFileData = (m_fileMapper != nullptr) ? m_fileMapper->GetData() : nullptr;
    size_t fileSize = (m_fileMapper != nullptr) ? m_fileMapper->GetSize() : 0;
    m_scriptManager->SetPEData(pFileData, fileSize, m_peInfo);

    return m_scriptManager->ExecuteAll();
}

bool CPEAnalyzer::HasScripts() const
{
    return m_scriptManager != nullptr && m_scriptManager->IsInitialized();
}

// ============================================================================
// 鐘舵€佹煡璇?
// ============================================================================

std::string CPEAnalyzer::GetErrorDescription() const
{
    if (!m_errorDescription.empty())
    {
        return m_errorDescription;
    }
    return PE::GetErrorDescription(m_lastError);
}

// ============================================================================
// 瀵煎嚭
// ============================================================================

std::string CPEAnalyzer::ExportJSON() const
{
    std::ostringstream json;
    json << "{\n"
         << "\"filePath\":\"";
    // 瀹藉瓧绗﹁浆 UTF-8 (绠€鍖栧鐞?
    std::string filePath(m_peInfo.filePath.begin(), m_peInfo.filePath.end());
    json << filePath << "\",\n"
         << "\"fileSize\":" << m_peInfo.fileSize << ",\n"
         << "\"isPE32Plus\":" << (m_peInfo.isPE32Plus ? "true" : "false") << ",\n"
         << "\"parserResults\":[\n";

    // 娣诲姞瑙ｆ瀽鍣ㄧ粨鏋?
    bool first = true;
    for (const auto& [name, parser] : m_parsers)
    {
        if (!first)
        {
            json << ",\n";
        }
        json << parser->GetResult();
        first = false;
    }

    json << "\n],\n"
         << "\"analyzerResults\":[\n";

    // 娣诲姞鍒嗘瀽鍣ㄧ粨鏋?(鏈潵鎵╁睍)
    json << "\n]\n"
         << "}";

    return json.str();
}

std::string CPEAnalyzer::ExportMarkdown() const
{
    std::ostringstream md;
    md << "# PE 闈欐€佸畨鍏ㄥ垎鏋愭姤鍛奬n\n";
    md << "## 鍩烘湰淇℃伅\n\n";
    md << "- **鏂囦欢璺緞**: ";
    std::string filePath(m_peInfo.filePath.begin(), m_peInfo.filePath.end());
    md << filePath << "\n";
    md << "- **鏂囦欢澶у皬**: " << m_peInfo.fileSize << " 瀛楄妭\n";
    md << "- **PE 绫诲瀷**: " << (m_peInfo.isPE32Plus ? "PE32+" : "PE32") << "\n\n";

    md << "## DOS 澶碶n\n";
    md << "| 瀛楁 | 鍊?|\n";
    md << "|------|-----|\n";
    md << "| e_magic | 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
       << m_peInfo.dosHeader.e_magic << " |\n";
    md << "| e_lfanew | " << std::dec << m_peInfo.dosHeader.e_lfanew << " |\n";
    md << "| 鐘舵€?| " << (m_peInfo.dosHeader.isValid ? "鉁?鏈夋晥" : "鉂?鏃犳晥") << " |\n\n";

    md << "## NT 澶碶n\n";
    md << "### 鏂囦欢澶碶n\n";
    md << "| 瀛楁 | 鍊?|\n";
    md << "|------|-----|\n";
    md << "| Machine | 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
       << m_peInfo.ntHeaders.fileHeader.machine << " |\n";
    md << "| 鑺傚尯鏁伴噺 | " << std::dec << m_peInfo.ntHeaders.fileHeader.numberOfSections << " |\n";
    md << "| 鍙€夊ご澶у皬 | " << m_peInfo.ntHeaders.fileHeader.sizeOfOptionalHeader << " |\n";
    md << "| Characteristics | 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
       << m_peInfo.ntHeaders.fileHeader.characteristics << " |\n\n";

    md << "### 鍙€夊ご\n\n";
    md << "| 瀛楁 | 鍊?|\n";
    md << "|------|-----|\n";
    md << "| Magic | 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
       << m_peInfo.ntHeaders.optionalHeader.magic << " |\n";
    md << "| 鍏ュ彛鐐?| 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
       << m_peInfo.ntHeaders.optionalHeader.addressOfEntryPoint << " |\n";
    md << "| 闀滃儚鍩哄潃 | 0x" << std::hex << std::uppercase
       << m_peInfo.ntHeaders.optionalHeader.imageBase << " |\n";
    md << "| 闀滃儚澶у皬 | " << std::dec << m_peInfo.ntHeaders.optionalHeader.sizeOfImage << " |\n";
    md << "| 澶村ぇ灏?| " << m_peInfo.ntHeaders.optionalHeader.sizeOfHeaders << " |\n";
    md << "| 鏍￠獙鍜?| 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
       << m_peInfo.ntHeaders.optionalHeader.checkSum << " |\n";
    md << "| 瀛愮郴缁?| " << m_peInfo.ntHeaders.optionalHeader.subsystem << " |\n\n";

    md << "---\n\n";
    md << "*鎶ュ憡鐢?PE Static Sentinel v0.1.0 鐢熸垚*\n";

    return md.str();
}

// ============================================================================
// 鍐呴儴鏂规硶
// ============================================================================

bool CPEAnalyzer::InitializeCore()
{
    m_fileMapper = std::make_unique<CFileMapper>();
    m_analyzerManager = std::make_unique<CAnalyzerManager>();
    return true;
}

void CPEAnalyzer::Clear()
{
    m_fileMapper->Unmap();
    m_analyzerManager->Clear();
    m_peInfo = PEInfo{};
    m_isLoaded = false;
    m_isParsed = false;
    m_isAnalyzed = false;
    m_lastError = EErrorCode::Success;
    m_errorDescription.clear();
}

} // namespace PE
