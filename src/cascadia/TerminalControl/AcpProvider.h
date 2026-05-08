// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Module Name:
// - AcpProvider.h
//
// Abstract:
// - An inline suggestion provider that launches an ACP (Agent Client Protocol)
//   subprocess and sends completion requests over newline-delimited JSON-RPC 2.0.
//   Supports copilot, gemini, and custom agents.

#pragma once

#include "IInlineSuggestionProvider.h"

#include <Windows.h>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace winrt::Microsoft::Terminal::Control::implementation
{
    class AcpProvider final : public IInlineSuggestionProvider
    {
    public:
        // agentCommand: full command to launch, e.g. "copilot --acp --stdio"
        explicit AcpProvider(std::wstring agentCommand);
        ~AcpProvider() override;

        AcpProvider(const AcpProvider&) = delete;
        AcpProvider& operator=(const AcpProvider&) = delete;

        std::future<SuggestionResult> SuggestAsync(SuggestionRequest request) override;
        bool IsAvailable() const noexcept override;

    private:
        // Lifecycle
        bool _ensureConnected();
        void _launchSubprocess();
        void _shutdown();

        // JSON-RPC helpers
        std::string _sendRequest(const std::string& method, const std::string& paramsJson);
        std::string _readLine();
        void _writeLine(const std::string& line);
        int64_t _nextId();

        // ACP handshake
        bool _initialize();
        bool _createSession();

        // Build the completion prompt
        static std::string _buildCompletionPrompt(const std::wstring& prefix, const std::wstring& cwd, const std::wstring& shell);
        static std::string _extractAgentText(const std::string& responseJson);
        static std::string _wideToUtf8(std::wstring_view wide);
        static std::wstring _utf8ToWide(std::string_view utf8);
        static std::string _escapeJsonString(const std::string& s);

        std::wstring _agentCommand;

        // Subprocess handles
        HANDLE _processHandle = INVALID_HANDLE_VALUE;
        HANDLE _stdinWrite = INVALID_HANDLE_VALUE;
        HANDLE _stdoutRead = INVALID_HANDLE_VALUE;

        // State
        std::mutex _mutex;
        std::atomic<bool> _connected{ false };
        std::atomic<int64_t> _requestId{ 0 };
        std::string _sessionId;

        // Read buffer for efficient line reading
        std::string _readBuffer;
    };
}
