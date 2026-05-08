// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Module Name:
// - AcpProvider.cpp
//
// Abstract:
// - ACP-based inline suggestion provider. Spawns an ACP agent subprocess
//   (e.g., copilot --acp --stdio) and communicates via newline-delimited
//   JSON-RPC 2.0 to get command completion suggestions.

#include "pch.h"
#include "AcpProvider.h"

#include <sstream>

namespace winrt::Microsoft::Terminal::Control::implementation
{
    AcpProvider::AcpProvider(std::wstring agentCommand) :
        _agentCommand{ std::move(agentCommand) }
    {
    }

    AcpProvider::~AcpProvider()
    {
        _shutdown();
    }

    bool AcpProvider::IsAvailable() const noexcept
    {
        return !_agentCommand.empty();
    }

    std::future<SuggestionResult> AcpProvider::SuggestAsync(SuggestionRequest request)
    {
        return std::async(std::launch::async, [this, req = std::move(request)]() -> SuggestionResult {
            try
            {
                std::lock_guard lock{ _mutex };

                if (!_ensureConnected())
                {
                    return SuggestionResult{ SuggestionKind::None, L"", req.generationId };
                }

                // Build and send the completion prompt
                auto promptText = _buildCompletionPrompt(req.cursorPrefix, req.cwd, req.shell);
                auto promptJson = std::string{ R"({"sessionId":")" } + _escapeJsonString(_sessionId) +
                                  R"(","prompt":[{"type":"text","text":")" + _escapeJsonString(promptText) + R"("}]})" ;

                auto responseJson = _sendRequest("session/prompt", promptJson);
                if (responseJson.empty())
                {
                    return SuggestionResult{ SuggestionKind::None, L"", req.generationId };
                }

                auto suggestion = _extractAgentText(responseJson);
                if (suggestion.empty())
                {
                    return SuggestionResult{ SuggestionKind::None, L"", req.generationId };
                }

                auto wideSuggestion = _utf8ToWide(suggestion);
                return SuggestionResult{ SuggestionKind::Suffix, std::move(wideSuggestion), req.generationId };
            }
            catch (...)
            {
                return SuggestionResult{ SuggestionKind::None, L"", req.generationId };
            }
        });
    }

    bool AcpProvider::_ensureConnected()
    {
        if (_connected.load())
        {
            // Check if process is still alive
            if (_processHandle != INVALID_HANDLE_VALUE)
            {
                DWORD exitCode = 0;
                if (GetExitCodeProcess(_processHandle, &exitCode) && exitCode != STILL_ACTIVE)
                {
                    _shutdown();
                }
            }
        }

        if (!_connected.load())
        {
            _launchSubprocess();
            if (_processHandle == INVALID_HANDLE_VALUE)
                return false;

            if (!_initialize())
            {
                _shutdown();
                return false;
            }

            if (!_createSession())
            {
                _shutdown();
                return false;
            }

            _connected.store(true);
        }

        return true;
    }

    void AcpProvider::_launchSubprocess()
    {
        // Create pipes for stdin/stdout
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE stdinRead = INVALID_HANDLE_VALUE;
        HANDLE stdoutWrite = INVALID_HANDLE_VALUE;

        if (!CreatePipe(&stdinRead, &_stdinWrite, &sa, 0))
            return;
        if (!CreatePipe(&_stdoutRead, &stdoutWrite, &sa, 0))
        {
            CloseHandle(stdinRead);
            CloseHandle(_stdinWrite);
            _stdinWrite = INVALID_HANDLE_VALUE;
            return;
        }

        // Don't let the child inherit the write end of stdin or read end of stdout
        SetHandleInformation(_stdinWrite, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(_stdoutRead, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = stdinRead;
        si.hStdOutput = stdoutWrite;
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

        PROCESS_INFORMATION pi{};

        // Build command line: "cmd /c <agentCommand>" for .cmd scripts
        auto cmdLine = std::wstring{ L"cmd /c " } + _agentCommand;

        auto success = CreateProcessW(
            nullptr,
            cmdLine.data(),
            nullptr,
            nullptr,
            TRUE, // inherit handles
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi);

        // Close child-side handles
        CloseHandle(stdinRead);
        CloseHandle(stdoutWrite);

        if (!success)
        {
            CloseHandle(_stdinWrite);
            CloseHandle(_stdoutRead);
            _stdinWrite = INVALID_HANDLE_VALUE;
            _stdoutRead = INVALID_HANDLE_VALUE;
            return;
        }

        _processHandle = pi.hProcess;
        CloseHandle(pi.hThread);
    }

    void AcpProvider::_shutdown()
    {
        _connected.store(false);
        _sessionId.clear();
        _readBuffer.clear();

        if (_stdinWrite != INVALID_HANDLE_VALUE)
        {
            CloseHandle(_stdinWrite);
            _stdinWrite = INVALID_HANDLE_VALUE;
        }
        if (_stdoutRead != INVALID_HANDLE_VALUE)
        {
            CloseHandle(_stdoutRead);
            _stdoutRead = INVALID_HANDLE_VALUE;
        }
        if (_processHandle != INVALID_HANDLE_VALUE)
        {
            TerminateProcess(_processHandle, 0);
            CloseHandle(_processHandle);
            _processHandle = INVALID_HANDLE_VALUE;
        }
    }

    int64_t AcpProvider::_nextId()
    {
        return ++_requestId;
    }

    void AcpProvider::_writeLine(const std::string& line)
    {
        if (_stdinWrite == INVALID_HANDLE_VALUE)
            return;

        auto data = line + "\n";
        DWORD written = 0;
        WriteFile(_stdinWrite, data.c_str(), static_cast<DWORD>(data.size()), &written, nullptr);
    }

    std::string AcpProvider::_readLine()
    {
        if (_stdoutRead == INVALID_HANDLE_VALUE)
            return {};

        // Read until we find a newline
        while (true)
        {
            auto nlPos = _readBuffer.find('\n');
            if (nlPos != std::string::npos)
            {
                auto line = _readBuffer.substr(0, nlPos);
                _readBuffer.erase(0, nlPos + 1);
                // Trim \r if present
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                return line;
            }

            char buf[4096];
            DWORD bytesRead = 0;
            if (!ReadFile(_stdoutRead, buf, sizeof(buf), &bytesRead, nullptr) || bytesRead == 0)
            {
                return {};
            }
            _readBuffer.append(buf, bytesRead);
        }
    }

    std::string AcpProvider::_sendRequest(const std::string& method, const std::string& paramsJson)
    {
        auto id = _nextId();
        std::ostringstream oss;
        oss << R"({"jsonrpc":"2.0","id":)" << id
            << R"(,"method":")" << method
            << R"(","params":)" << paramsJson << "}";

        _writeLine(oss.str());

        // Read lines until we get the response with our id.
        // We may receive notifications (no "id" field) along the way —
        // we collect agent message text from those.
        std::string collectedText;

        while (true)
        {
            auto line = _readLine();
            if (line.empty())
                return {}; // pipe closed

            // Quick check: does this line contain our response id?
            auto idStr = std::to_string(id);
            auto idPattern = std::string{ R"("id":)" } + idStr;

            if (line.find(idPattern) != std::string::npos && line.find("\"result\"") != std::string::npos)
            {
                // This is the final response — return collected text if any, or the response
                if (!collectedText.empty())
                    return collectedText;
                return line;
            }

            // Check if this is a session notification with agent message text
            // Look for "agentMessageChunk" with text content
            if (line.find("\"agentMessageChunk\"") != std::string::npos ||
                line.find("\"agent_message_chunk\"") != std::string::npos)
            {
                // Extract text from the notification
                auto extracted = _extractAgentText(line);
                if (!extracted.empty())
                {
                    collectedText += extracted;
                }
            }

            // If it's a request from the agent (e.g., permission request, terminal create),
            // we need to handle it minimally
            if (line.find("\"method\"") != std::string::npos &&
                line.find("\"id\"") != std::string::npos &&
                line.find("\"result\"") == std::string::npos)
            {
                // It's a request from the agent — send a minimal error response
                // to tell it we don't support that method
                auto reqIdPos = line.find("\"id\":");
                if (reqIdPos != std::string::npos)
                {
                    // Extract request id — find the value after "id":
                    auto valStart = reqIdPos + 5;
                    while (valStart < line.size() && (line[valStart] == ' ' || line[valStart] == '\t'))
                        valStart++;
                    auto valEnd = valStart;
                    // id can be number or string
                    if (valEnd < line.size() && line[valEnd] == '"')
                    {
                        valEnd++;
                        while (valEnd < line.size() && line[valEnd] != '"')
                            valEnd++;
                        valEnd++;
                    }
                    else
                    {
                        while (valEnd < line.size() && line[valEnd] != ',' && line[valEnd] != '}')
                            valEnd++;
                    }
                    auto reqIdValue = line.substr(valStart, valEnd - valStart);

                    // For permission requests, auto-approve
                    if (line.find("request_permission") != std::string::npos)
                    {
                        auto resp = std::string{ R"({"jsonrpc":"2.0","id":)" } + reqIdValue +
                                    R"(,"result":{"outcome":{"type":"selected","option":{"id":"allow","description":"Allow"}}}})" ;
                        _writeLine(resp);
                    }
                    else
                    {
                        // Send error for unsupported methods
                        auto resp = std::string{ R"({"jsonrpc":"2.0","id":)" } + reqIdValue +
                                    R"(,"error":{"code":-32601,"message":"Method not supported in inline mode"}})" ;
                        _writeLine(resp);
                    }
                }
            }
        }
    }

    bool AcpProvider::_initialize()
    {
        auto params = R"({"protocolVersion":"1","clientCapabilities":{"terminal":true},"clientInfo":{"name":"wt-inline","version":"1.0.0","title":"Windows Terminal Inline Suggestions"}})";
        auto resp = _sendRequest("initialize", params);
        // Just check we got a non-empty response
        return !resp.empty();
    }

    bool AcpProvider::_createSession()
    {
        // Get current working directory
        wchar_t cwdBuf[MAX_PATH]{};
        GetCurrentDirectoryW(MAX_PATH, cwdBuf);
        auto cwdUtf8 = _wideToUtf8(cwdBuf);

        auto params = std::string{ R"({"cwd":")" } + _escapeJsonString(cwdUtf8) + R"("})";
        auto resp = _sendRequest("session/new", params);

        if (resp.empty())
            return false;

        // Extract sessionId from response
        // Look for "sessionId":"<value>"
        auto key = std::string{ R"("sessionId":")" };
        auto pos = resp.find(key);
        if (pos == std::string::npos)
        {
            // Try snake_case variant
            key = R"("session_id":")";
            pos = resp.find(key);
        }
        if (pos == std::string::npos)
            return false;

        auto valStart = pos + key.size();
        auto valEnd = resp.find('"', valStart);
        if (valEnd == std::string::npos)
            return false;

        _sessionId = resp.substr(valStart, valEnd - valStart);
        return !_sessionId.empty();
    }

    std::string AcpProvider::_buildCompletionPrompt(const std::wstring& prefix, const std::wstring& cwd, const std::wstring& shell)
    {
        auto prefixUtf8 = _wideToUtf8(prefix);
        auto cwdUtf8 = _wideToUtf8(cwd);
        auto shellUtf8 = _wideToUtf8(shell);

        std::ostringstream oss;
        oss << "Complete this shell command. Output ONLY the remaining characters to complete the command. "
               "Do NOT include what is already typed. Do NOT explain. Do NOT use markdown. "
               "Output nothing if there is no good completion.\n\n"
               "Shell: " << (shellUtf8.empty() ? "powershell" : shellUtf8) << "\n";
        if (!cwdUtf8.empty())
            oss << "Working directory: " << cwdUtf8 << "\n";
        oss << "Command so far: " << prefixUtf8;

        return oss.str();
    }

    std::string AcpProvider::_extractAgentText(const std::string& json)
    {
        // Minimal JSON text extraction — find "text":"<value>" patterns
        // within content blocks. This handles:
        //   {"type":"text","text":"completion text"}
        //   or nested in session notification params
        std::string result;

        // Find all "text":"..." patterns that are likely content
        size_t searchStart = 0;
        while (true)
        {
            auto key = std::string{ R"("text":")" };
            auto pos = json.find(key, searchStart);
            if (pos == std::string::npos)
                break;

            auto valStart = pos + key.size();
            // Parse the JSON string value (handle escapes)
            std::string value;
            for (size_t i = valStart; i < json.size(); i++)
            {
                if (json[i] == '\\' && i + 1 < json.size())
                {
                    i++;
                    switch (json[i])
                    {
                    case '"': value += '"'; break;
                    case '\\': value += '\\'; break;
                    case 'n': value += '\n'; break;
                    case 'r': value += '\r'; break;
                    case 't': value += '\t'; break;
                    case '/': value += '/'; break;
                    default: value += '\\'; value += json[i]; break;
                    }
                }
                else if (json[i] == '"')
                {
                    break;
                }
                else
                {
                    value += json[i];
                }
            }

            if (!value.empty())
            {
                result += value;
            }
            searchStart = valStart;
        }

        // Trim whitespace from start/end
        auto start = result.find_first_not_of(" \t\r\n");
        auto end = result.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos)
            return result.substr(start, end - start + 1);

        return {};
    }

    std::string AcpProvider::_wideToUtf8(std::wstring_view wide)
    {
        if (wide.empty())
            return {};
        auto size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
        std::string result(size, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), result.data(), size, nullptr, nullptr);
        return result;
    }

    std::wstring AcpProvider::_utf8ToWide(std::string_view utf8)
    {
        if (utf8.empty())
            return {};
        auto size = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
        std::wstring result(size, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), result.data(), size);
        return result;
    }

    std::string AcpProvider::_escapeJsonString(const std::string& s)
    {
        std::string result;
        result.reserve(s.size() + 8);
        for (char c : s)
        {
            switch (c)
            {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                }
                else
                {
                    result += c;
                }
                break;
            }
        }
        return result;
    }
}
