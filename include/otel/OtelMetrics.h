#pragma once

// Based in part on otel-embedded-cpp (https://github.com/proffalken/otel-embedded-cpp)
// Copyright (c) 2023 Matt Jarvis (MIT License)
// Adapted for pure POSIX/Linux C++17 by merlin-otel-agent contributors.

#include <map>
#include <string>
#include "OtelDefaults.h"
#include "OtelProtoEncoder.h"

namespace OTel {

class Metrics {
public:
    static void begin(const std::string& scopeName = "merlin-router",
                      const std::string& scopeVersion = MOTEL_VERSION);

    static void startBatch();
    static void flushBatch();
    static void clearBatch();
    static const Proto::MetricBatch& activeBatch() { return s_activeBatch; }

    static void gauge(const std::string& name, double value,
                      const std::string& unit = "1",
                      const std::map<std::string, std::string>& labels = {});

    static void gaugeInt(const std::string& name, int64_t value,
                         const std::string& unit = "1",
                         const std::map<std::string, std::string>& labels = {});

    static void sum(const std::string& name, double value,
                    bool isMonotonic = true,
                    Proto::Temporality temporality = Proto::Temporality::CUMULATIVE,
                    const std::string& unit = "1",
                    const std::map<std::string, std::string>& labels = {});

    static void sumInt(const std::string& name, int64_t value,
                       bool isMonotonic = true,
                       Proto::Temporality temporality = Proto::Temporality::CUMULATIVE,
                       const std::string& unit = "1",
                       const std::map<std::string, std::string>& labels = {});

private:
    static void emit(Proto::MetricPoint&& pt);

    static std::string s_scopeName;
    static std::string s_scopeVersion;
    static bool s_batchMode;
    static Proto::MetricBatch s_activeBatch;
};

} // namespace OTel
