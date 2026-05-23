// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// RtlHelper.h
//
// Thin wrapper around the Windows locale database for right-to-left
// (RTL) language detection. The OS already ships an authoritative
// classifier for every BCP-47 tag it knows about
// (`Windows.Globalization.Language.LayoutDirection`), so we delegate
// to it instead of maintaining our own subtag list. That has three
// benefits:
//
//   1. New / less common RTL scripts (e.g. N'Ko `nqo`, Sindhi in
//      Arabic script) get correct treatment without code changes.
//   2. Tests don't have to hardcode "what counts as RTL" — there is
//      no list to drift out of sync.
//   3. The FRE and the wta TUI agree on classification because both
//      stacks call the same OS API (wta uses Win32
//      `GetLocaleInfoEx(LOCALE_IREADINGLAYOUT)`).

#pragma once

#include <string_view>

#include <winrt/Windows.Globalization.h>

namespace Microsoft::Terminal::RtlHelper
{
    // Returns true if `language` is a BCP-47 tag whose preferred
    // reading layout is right-to-left, as reported by
    // `Windows::Globalization::Language::LayoutDirection()`. Empty
    // strings, malformed tags, and unknown languages all yield false
    // (the safe LTR default — the WinRT `Language` constructor throws
    // for ill-formed tags).
    //
    // Pseudo-locales: `qps-plocm` is the pseudo-mirrored pseudo-locale
    // Microsoft ships for RTL validation. The OS classifies it as RTL,
    // so we get that for free without a special case.
    [[nodiscard]] inline bool IsRtlLocale(std::wstring_view language) noexcept
    {
        if (language.empty())
        {
            return false;
        }
        try
        {
            const winrt::Windows::Globalization::Language lang{ winrt::hstring{ language } };
            return lang.LayoutDirection() == winrt::Windows::Globalization::LanguageLayoutDirection::Rtl;
        }
        catch (...)
        {
            return false;
        }
    }
}
