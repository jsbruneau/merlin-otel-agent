#pragma once

// Based in part on otel-embedded-cpp (https://github.com/proffalken/otel-embedded-cpp)
// Copyright (c) 2023 Matt Jarvis (MIT License)
// Adapted for pure POSIX/Linux C++17 by merlin-otel-agent contributors.

#include <map>
#include <string>
#include "OtelDefaults.h"
#include "OtelProtoEncoder.h"

namespace OTel {

inline int severityNumberFromText(const std::string& s) {
    if (s == "TRACE") return 1;
    if (s == "DEBUG") return 5;
    if (s == "INFO" || s == "NOTICE") return 9;
    if (s == "WARN" || s == "WARNING") return 13;
    if (s == "ERROR" || s == "ERR") return 17;
    if (s == "FATAL" || s == "CRIT" || s == "ALERT" || s == "EMERG") return 21;
    return 9;
}

class Logger {
public:
    static void begin(const std::string& scopeName = "merlin-router",
                      const std::string& scopeVersion = MOTEL_VERSION);

    static void startBatch();
    static void flushBatch();
    static void clearBatch();
    static const Proto::LogBatch& activeBatch() { return s_activeBatch; }

    static void log(const std::string& severity, const std::string& message,
                    const std::map<std::string, std::string>& labels = {},
                    uint64_t timeNano = 0,
                    const std::string& traceId = "", const std::string& spanId = "");

    static void logInfo(const std::string& msg, const std::map<std::string, std::string>& l = {}) { log("INFO", msg, l); }

private:
    static std::string s_scopeName;
    static std::string s_scopeVersion;
    static bool s_batchMode;
    static Proto::LogBatch s_activeBatch;
};

} // namespace OTel
