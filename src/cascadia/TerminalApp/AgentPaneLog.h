// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Shared diagnostic logger for the agent-pane code paths spread across
// TerminalPage.cpp / TabManagement.cpp / AppActionHandlers.cpp. Three
// near-identical copies of this function used to live in those TUs; that
// drifted whenever one of them was tweaked. Centralized here so the
// timestamp format, log path, and error-handling semantics stay in lock-
// step.
//
// Output: the WTA log directory + `wta-agent-pane.log`, one ISO8601 UTC line
// per call with millisecond precision so timestamps correlate with
// `wta-main_*.log` down to the millisecond. The log directory is resolved by
// `_intelligentTerminalLogDir()` below to match wta's Rust
// `runtime_paths::intelligent_terminal_local_root()`.
//
// Header-only `inline` so each translation unit that includes this picks
// up its own copy of the symbol without ODR conflicts.

#pragma once

#include <windows.h>
#include <appmodel.h>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <string>
#include <system_error>

namespace winrt::TerminalApp::implementation
{
    // Resolve the WTA log directory. Mirrors wta's
    // `runtime_paths::intelligent_terminal_local_root()` exactly so the C++
    // and Rust sides write into the same folder:
    //
    //   * Packaged:   %LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\IntelligentTerminal\logs
    //   * Unpackaged: %LOCALAPPDATA%\IntelligentTerminal\logs
    //
    // Logs are transient cache, hence `LocalCache\Local` (not `LocalState`,
    // which holds persistent state like the agent-pane session index).
    // Returns an empty path when `%LOCALAPPDATA%` is unavailable.
    inline std::filesystem::path _intelligentTerminalLogDir()
    {
        wchar_t localAppData[MAX_PATH];
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) == 0)
        {
            return {};
        }
        // Build a `filesystem::path` from the raw wstring. `std::ofstream`'s
        // wstring overload is a MSVC extension; the standard ctor only
        // accepts `const char*`, `std::string`, and `std::filesystem::path`.
        // Going via `path` keeps the code portable.
        std::filesystem::path base{ std::wstring(localAppData) };

        // Two-call pattern: query the family-name length first. A packaged
        // process returns ERROR_INSUFFICIENT_BUFFER and fills `length`; an
        // unpackaged one returns APPMODEL_ERROR_NO_PACKAGE.
        UINT32 length = 0;
        if (GetCurrentPackageFamilyName(&length, nullptr) == ERROR_INSUFFICIENT_BUFFER && length != 0)
        {
            std::wstring family(length, L'\0');
            if (GetCurrentPackageFamilyName(&length, family.data()) == ERROR_SUCCESS)
            {
                family.resize(::wcslen(family.c_str())); // drop trailing NUL(s)
                return base / L"Packages" / family / L"LocalCache" / L"Local" / L"IntelligentTerminal" / L"logs";
            }
        }
        return base / L"IntelligentTerminal" / L"logs";
    }

    inline void _agentPaneLog(const std::string& msg)
    {
        std::filesystem::path logDir = _intelligentTerminalLogDir();
        if (logDir.empty())
        {
            return;
        }

        // No-throw overload — this is a diagnostic logger; we never want
        // a filesystem hiccup (race with a concurrent rmdir, permission
        // change, disk full) to bubble out as an exception that kills the
        // caller. On failure we silently drop the log line.
        std::error_code ec;
        std::filesystem::create_directories(logDir, ec);
        if (ec)
        {
            return;
        }

        const auto logPath = logDir / L"wta-agent-pane.log";
        std::ofstream f{ logPath, std::ios::app };
        if (!f)
        {
            return;
        }

        const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
        const auto secs = static_cast<std::time_t>(nowMs / 1000);
        const int ms = static_cast<int>(nowMs % 1000);
        std::tm tmUtc{};
        ::gmtime_s(&tmUtc, &secs);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmUtc);
        f << '[' << ts << '.' << std::setw(3) << std::setfill('0') << ms
          << "Z] " << msg << '\n';
    }
}
