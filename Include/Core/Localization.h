/**
 * @file Localization.h
 * @brief Localization system using gettext
 * @date 2026-06-17
 *
 * Wraps gettext functions for i18n support.
 * Provides _(msg) macro for marking translatable strings.
 * Supports automatic system language detection.
 */

#pragma once

#include <string>
#include <locale>
#include <windows.h>

namespace PE {

/**
 * @brief Localization manager class
 *
 * Initializes gettext and provides language switching functionality.
 * Automatically detects system language on initialization.
 */
class CLocalization
{
public:
    /**
     * @brief Initialize the localization system
     *
     * Calls setlocale, bindtextdomain, and textdomain.
     * Should be called once at program startup.
     */
    static void Init();

    /**
     * @brief Set the language
     * @param languageCode Language code string (e.g. "zh_CN", "en_US")
     *
     * Sets the language for gettext translations.
     */
    static void SetLanguage(const std::string& languageCode);

    /**
     * @brief Get the current language code
     * @return std::string Current language code
     */
    static std::string GetLanguage();

    /**
     * @brief Detect system language automatically
     * @return std::string Detected language code
     *
     * Uses Windows GetUserDefaultUILanguage to detect system language.
     */
    static std::string DetectSystemLanguage();

private:
    static std::string m_currentLanguage;  ///< Current language code
};

} // namespace PE

// ============================================================================
// Gettext wrapper macros
// ============================================================================

/**
 * @def _(msg)
 * @brief Mark a string for translation
 * @param msg The string to translate
 * @return const char* Translated string (or original if no translation found)
 *
 * Usage: LOG_INFO(_("File loaded successfully"));
 */
#ifdef ENABLE_NLS
    #include <libintl.h>
    #define _(msg) gettext(msg)
#else
    #define _(msg) msg
#endif
