/**
 * @file Localization.cpp
 * @brief Localization system implementation
 * @date 2026-06-17
 */

#include "../../Include/Core/Localization.h"
#include "../../Include/Core/Logger.h"
#include <cstdlib>

namespace PE {

std::string CLocalization::m_currentLanguage = "en_US";

void CLocalization::Init()
{
    // Set the locale to system default
    setlocale(LC_ALL, "");

    // Detect system language
    std::string lang = DetectSystemLanguage();
    SetLanguage(lang);

    // Initialize gettext
#ifdef ENABLE_NLS
    // Set the locale for message translation
    setlocale(LC_MESSAGES, lang.c_str());

    // Set the path to the message catalogs
    bindtextdomain("pe_scanner", "locale");

    // Set the default text domain
    textdomain("pe_scanner");
#endif

    LOG_INFO_F("Localization initialized: language=%s", lang.c_str());
}

void CLocalization::SetLanguage(const std::string& languageCode)
{
    m_currentLanguage = languageCode;

    // Update the locale
    setlocale(LC_ALL, languageCode.c_str());

#ifdef ENABLE_NLS
    setlocale(LC_MESSAGES, languageCode.c_str());
#endif

    LOG_INFO_F("Language set to: %s", languageCode.c_str());
}

std::string CLocalization::GetLanguage()
{
    return m_currentLanguage;
}

std::string CLocalization::DetectSystemLanguage()
{
    // Use Windows API to detect system UI language
    LANGID langId = GetUserDefaultUILanguage();

    // Convert LANGID to language code string
    wchar_t localeName[LOCALE_NAME_MAX_LENGTH];
    if (LCIDToLocaleName(MAKELCID(langId, SORT_DEFAULT),
                         localeName,
                         LOCALE_NAME_MAX_LENGTH,
                         0) > 0)
    {
        // Convert wide string to narrow string
        char narrowName[LOCALE_NAME_MAX_LENGTH];
        WideCharToMultiByte(CP_UTF8, 0, localeName, -1,
                            narrowName, LOCALE_NAME_MAX_LENGTH,
                            nullptr, nullptr);
        std::string result(narrowName);

        // Check if it's a Chinese locale
        if (result.find("zh") == 0)
        {
            return "zh_CN";
        }
        // Default to English for all other locales
        return "en_US";
    }

    // Fallback to English
    return "en_US";
}

} // namespace PE
