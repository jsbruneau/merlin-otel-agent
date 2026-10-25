#pragma once

// Based in part on otel-embedded-cpp (https://github.com/proffalken/otel-embedded-cpp)
// Copyright (c) 2023 Matt Jarvis (MIT License)
// Adapted for pure POSIX/Linux C++17 by merlin-otel-agent contributors.

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include "OtelDefaults.h"

namespace OTel {
namespace Proto {

// OTLP Temporality
enum class Temporality : int {
    UNSPECIFIED = 0,
    DELTA = 1,
    CUMULATIVE = 2
};

struct MetricPoint {
    std::string name;
    std::string unit;
    bool isGauge = true;
    bool isMonotonic = false;
    Temporality temporality = Temporality::CUMULATIVE;
    bool isInt = false;
    int64_t intValue = 0;
    double doubleValue = 0.0;
    uint64_t startTimestampNano = 0;
    uint64_t timestampNano = 0;
    std::map<std::string, std::string> attributes;
};

struct LogRecordPoint {
    uint64_t timestampNano = 0;
    int severityNumber = 9; // INFO
    std::string severityText = "INFO";
    std::string body;
    std::map<std::string, std::string> attributes;
    std::string traceId; // Optional 16-byte hex
    std::string spanId;  // Optional 8-byte hex
};

class MetricBatch {
public:
    void addPoint(MetricPoint&& pt);

    void addGauge(const std::string& name, double value, const std::string& unit = "1",
                  const std::map<std::string, std::string>& attrs = {}, uint64_t timeNano = 0);

    void addGaugeInt(const std::string& name, int64_t value, const std::string& unit = "1",
                     const std::map<std::string, std::string>& attrs = {}, uint64_t timeNano = 0);

    void addSum(const std::string& name, double value, bool isMonotonic = true,
                Temporality temporality = Temporality::CUMULATIVE, const std::string& unit = "1",
                const std::map<std::string, std::string>& attrs = {}, uint64_t timeNano = 0,
                uint64_t startTimeNano = 0);

    void addSumInt(const std::string& name, int64_t value, bool isMonotonic = true,
                   Temporality temporality = Temporality::CUMULATIVE, const std::string& unit = "1",
                   const std::map<std::string, std::string>& attrs = {}, uint64_t timeNano = 0,
                   uint64_t startTimeNano = 0);

    void clear() { m_points.clear(); }
    bool empty() const { return m_points.empty(); }
    size_t size() const { return m_points.size(); }
    const std::vector<MetricPoint>& points() const { return m_points; }

    std::vector<uint8_t> encode(const OTelResourceConfig& res,
                                const std::string& scopeName = "merlin-otel-agent",
                                const std::string& scopeVersion = MOTEL_VERSION) const;

private:
    std::vector<MetricPoint> m_points;
};

class LogBatch {
public:
    void addRecord(const std::string& severity, int severityNum, const std::string& body,
                   const std::map<std::string, std::string>& attrs = {},
                   uint64_t timeNano = 0,
                   const std::string& traceId = "", const std::string& spanId = "");

    void clear() { m_records.clear(); }
    bool empty() const { return m_records.empty(); }
    size_t size() const { return m_records.size(); }
    const std::vector<LogRecordPoint>& records() const { return m_records; }

    std::vector<uint8_t> encode(const OTelResourceConfig& res,
                                const std::string& scopeName = "merlin-otel-agent",
                                const std::string& scopeVersion = MOTEL_VERSION) const;

private:
    std::vector<LogRecordPoint> m_records;
};

// Low-level Protobuf wire serialization helpers
void writeVarint(std::vector<uint8_t>& buf, uint64_t val);
void writeTag(std::vector<uint8_t>& buf, uint32_t fieldNumber, uint8_t wireType);
void writeFixed64(std::vector<uint8_t>& buf, uint64_t val);
void writeString(std::vector<uint8_t>& buf, uint32_t fieldNumber, const std::string& str);
void writeBytes(std::vector<uint8_t>& buf, uint32_t fieldNumber, const uint8_t* data, size_t len);
void writeSubmessage(std::vector<uint8_t>& buf, uint32_t fieldNumber, const std::vector<uint8_t>& sub);
void writeKeyValue(std::vector<uint8_t>& buf, uint32_t fieldNumber, const std::string& key, const std::string& val);

} // namespace Proto
} // namespace OTel
