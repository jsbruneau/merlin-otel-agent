#include "otel/OtelProtoEncoder.h"
#include <cstring>

namespace OTel {
namespace Proto {

static size_t varintSize(uint64_t val) {
    size_t n = 1;
    while (val >= 0x80) {
        val >>= 7;
        ++n;
    }
    return n;
}

void writeVarint(std::vector<uint8_t>& buf, uint64_t val) {
    while (val >= 0x80) {
        buf.push_back(static_cast<uint8_t>((val & 0x7F) | 0x80));
        val >>= 7;
    }
    buf.push_back(static_cast<uint8_t>(val & 0x7F));
}

void writeTag(std::vector<uint8_t>& buf, uint32_t fieldNumber, uint8_t wireType) {
    writeVarint(buf, (static_cast<uint64_t>(fieldNumber) << 3) | (wireType & 0x07));
}

void writeFixed64(std::vector<uint8_t>& buf, uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>(val & 0xFF));
        val >>= 8;
    }
}

void writeString(std::vector<uint8_t>& buf, uint32_t fieldNumber, const std::string& str) {
    if (str.empty()) return;
    writeTag(buf, fieldNumber, 2);
    writeVarint(buf, str.size());
    buf.insert(buf.end(), str.begin(), str.end());
}

void writeBytes(std::vector<uint8_t>& buf, uint32_t fieldNumber, const uint8_t* data, size_t len) {
    if (len == 0) return;
    writeTag(buf, fieldNumber, 2);
    writeVarint(buf, len);
    buf.insert(buf.end(), data, data + len);
}

void writeSubmessage(std::vector<uint8_t>& buf, uint32_t fieldNumber, const std::vector<uint8_t>& sub) {
    if (sub.empty()) return;
    writeTag(buf, fieldNumber, 2);
    writeVarint(buf, sub.size());
    buf.insert(buf.end(), sub.begin(), sub.end());
}

// In-place KeyValue wire encoding without intermediate temporary std::vector allocations
void writeKeyValue(std::vector<uint8_t>& buf, uint32_t fieldNumber, const std::string& key, const std::string& val) {
    // AnyValue: string_value (field 1, wireType 2 -> 1-byte tag 0x0A)
    const size_t anyValLen = val.empty() ? 0 : (1 + varintSize(val.size()) + val.size());
    const size_t keyFieldLen = key.empty() ? 0 : (1 + varintSize(key.size()) + key.size());
    const size_t valFieldLen = (anyValLen == 0) ? 0 : (1 + varintSize(anyValLen) + anyValLen);
    const size_t kvLen = keyFieldLen + valFieldLen;
    if (kvLen == 0) return;

    writeTag(buf, fieldNumber, 2);
    writeVarint(buf, kvLen);

    if (!key.empty()) {
        writeString(buf, 1, key);
    }
    if (anyValLen > 0) {
        writeTag(buf, 2, 2); // KeyValue.value = 2
        writeVarint(buf, anyValLen);
        writeString(buf, 1, val); // AnyValue.string_value = 1
    }
}

static std::vector<uint8_t> encodeResource(const OTelResourceConfig& res) {
    std::vector<uint8_t> resource;
    writeKeyValue(resource, 1, "service.name", res.serviceName);
    writeKeyValue(resource, 1, "service.instance.id", res.serviceInstanceId);
    writeKeyValue(resource, 1, "host.name", res.hostName);
    for (const auto& attr : res.attributes) {
        writeKeyValue(resource, 1, attr.first, attr.second);
    }
    return resource;
}

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        auto val = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        bytes.push_back(static_cast<uint8_t>((val(hex[i]) << 4) | val(hex[i + 1])));
    }
    return bytes;
}

// -----------------------------------------------------------------------------
// MetricBatch
// -----------------------------------------------------------------------------

void MetricBatch::addPoint(MetricPoint&& pt) {
    if (pt.timestampNano == 0) {
        pt.timestampNano = nowUnixNano();
    }
    if (!pt.isGauge && pt.temporality == Temporality::CUMULATIVE && pt.startTimestampNano == 0) {
        pt.startTimestampNano = processStartUnixNano();
    }
    m_points.push_back(std::move(pt));
}

void MetricBatch::addGauge(const std::string& name, double value, const std::string& unit,
                           const std::map<std::string, std::string>& attrs, uint64_t timeNano) {
    MetricPoint p;
    p.name = name;
    p.unit = unit;
    p.isGauge = true;
    p.isInt = false;
    p.doubleValue = value;
    p.timestampNano = timeNano;
    p.attributes = attrs;
    addPoint(std::move(p));
}

void MetricBatch::addGaugeInt(const std::string& name, int64_t value, const std::string& unit,
                              const std::map<std::string, std::string>& attrs, uint64_t timeNano) {
    MetricPoint p;
    p.name = name;
    p.unit = unit;
    p.isGauge = true;
    p.isInt = true;
    p.intValue = value;
    p.timestampNano = timeNano;
    p.attributes = attrs;
    addPoint(std::move(p));
}

void MetricBatch::addSum(const std::string& name, double value, bool isMonotonic,
                         Temporality temporality, const std::string& unit,
                         const std::map<std::string, std::string>& attrs, uint64_t timeNano,
                         uint64_t startTimeNano) {
    MetricPoint p;
    p.name = name;
    p.unit = unit;
    p.isGauge = false;
    p.isMonotonic = isMonotonic;
    p.temporality = temporality;
    p.isInt = false;
    p.doubleValue = value;
    p.startTimestampNano = startTimeNano;
    p.timestampNano = timeNano;
    p.attributes = attrs;
    addPoint(std::move(p));
}

void MetricBatch::addSumInt(const std::string& name, int64_t value, bool isMonotonic,
                            Temporality temporality, const std::string& unit,
                            const std::map<std::string, std::string>& attrs, uint64_t timeNano,
                            uint64_t startTimeNano) {
    MetricPoint p;
    p.name = name;
    p.unit = unit;
    p.isGauge = false;
    p.isMonotonic = isMonotonic;
    p.temporality = temporality;
    p.isInt = true;
    p.intValue = value;
    p.startTimestampNano = startTimeNano;
    p.timestampNano = timeNano;
    p.attributes = attrs;
    addPoint(std::move(p));
}

std::vector<uint8_t> MetricBatch::encode(const OTelResourceConfig& res,
                                         const std::string& scopeName,
                                         const std::string& scopeVersion) const {
    if (m_points.empty()) return {};

    std::vector<uint8_t> scopeBytes;
    writeString(scopeBytes, 1, scopeName);
    writeString(scopeBytes, 2, scopeVersion);

    std::vector<uint8_t> scopeMetrics;
    writeSubmessage(scopeMetrics, 1, scopeBytes); // field 1: scope

    struct MetricGroupKey {
        std::string name;
        std::string unit;
        bool isGauge;
        bool isMonotonic;
        Temporality temporality;

        bool operator<(const MetricGroupKey& o) const {
            if (name != o.name) return name < o.name;
            if (unit != o.unit) return unit < o.unit;
            if (isGauge != o.isGauge) return isGauge < o.isGauge;
            if (isMonotonic != o.isMonotonic) return isMonotonic < o.isMonotonic;
            return temporality < o.temporality;
        }
    };

    std::vector<MetricGroupKey> keyOrder;
    std::map<MetricGroupKey, std::vector<size_t>> groups;
    for (size_t i = 0; i < m_points.size(); ++i) {
        const auto& pt = m_points[i];
        MetricGroupKey key{pt.name, pt.unit, pt.isGauge, pt.isMonotonic, pt.temporality};
        if (groups.find(key) == groups.end()) {
            keyOrder.push_back(key);
        }
        groups[key].push_back(i);
    }

    for (const auto& key : keyOrder) {
        std::vector<uint8_t> dps;
        for (size_t idx : groups[key]) {
            const auto& pt = m_points[idx];
            std::vector<uint8_t> dp;

            // NumberDataPoint attributes is field 7 in OTel Protobuf specification
            for (const auto& attr : pt.attributes) {
                writeKeyValue(dp, 7, attr.first, attr.second);
            }

            // field 2: start_time_unix_nano (fixed64) for cumulative sums
            if (!pt.isGauge && pt.startTimestampNano > 0) {
                writeTag(dp, 2, 1);
                writeFixed64(dp, pt.startTimestampNano);
            }

            // field 3: time_unix_nano (fixed64)
            writeTag(dp, 3, 1);
            writeFixed64(dp, pt.timestampNano);

            if (pt.isInt) {
                // field 6: as_int (sfixed64)
                writeTag(dp, 6, 1);
                writeFixed64(dp, static_cast<uint64_t>(pt.intValue));
            } else {
                // field 4: as_double (double)
                writeTag(dp, 4, 1);
                uint64_t bits = 0;
                std::memcpy(&bits, &pt.doubleValue, sizeof(bits));
                writeFixed64(dp, bits);
            }

            writeSubmessage(dps, 1, dp);
        }

        std::vector<uint8_t> metric;
        writeString(metric, 1, key.name);
        writeString(metric, 3, key.unit);

        if (key.isGauge) {
            writeSubmessage(metric, 5, dps); // Gauge: field 5
        } else {
            writeTag(dps, 2, 0); // field 2: aggregation_temporality
            writeVarint(dps, static_cast<uint64_t>(key.temporality));
            writeTag(dps, 3, 0); // field 3: is_monotonic
            writeVarint(dps, key.isMonotonic ? 1 : 0);
            writeSubmessage(metric, 7, dps); // Sum: field 7
        }

        writeSubmessage(scopeMetrics, 2, metric);
    }

    std::vector<uint8_t> resource = encodeResource(res);

    std::vector<uint8_t> resourceMetrics;
    writeSubmessage(resourceMetrics, 1, resource);
    writeSubmessage(resourceMetrics, 2, scopeMetrics);

    std::vector<uint8_t> request;
    writeSubmessage(request, 1, resourceMetrics);
    return request;
}

// -----------------------------------------------------------------------------
// LogBatch
// -----------------------------------------------------------------------------

void LogBatch::addRecord(const std::string& severity, int severityNum, const std::string& body,
                         const std::map<std::string, std::string>& attrs,
                         uint64_t timeNano,
                         const std::string& traceId, const std::string& spanId) {
    LogRecordPoint p;
    p.severityText = severity;
    p.severityNumber = severityNum;
    p.body = body;
    p.attributes = attrs;
    p.timestampNano = (timeNano != 0) ? timeNano : nowUnixNano();
    p.traceId = traceId;
    p.spanId = spanId;
    m_records.push_back(std::move(p));
}

std::vector<uint8_t> LogBatch::encode(const OTelResourceConfig& res,
                                      const std::string& scopeName,
                                      const std::string& scopeVersion) const {
    if (m_records.empty()) return {};

    std::vector<uint8_t> scopeBytes;
    writeString(scopeBytes, 1, scopeName);
    writeString(scopeBytes, 2, scopeVersion);

    std::vector<uint8_t> scopeLogs;
    writeSubmessage(scopeLogs, 1, scopeBytes);

    for (const auto& rec : m_records) {
        std::vector<uint8_t> lr;
        writeTag(lr, 1, 1); // field 1: time_unix_nano (fixed64)
        writeFixed64(lr, rec.timestampNano);

        writeTag(lr, 2, 0); // field 2: severity_number (varint)
        writeVarint(lr, static_cast<uint64_t>(rec.severityNumber));

        writeString(lr, 3, rec.severityText); // field 3: severity_text

        std::vector<uint8_t> bodyVal;
        writeString(bodyVal, 1, rec.body);
        writeSubmessage(lr, 5, bodyVal);

        for (const auto& attr : rec.attributes) {
            writeKeyValue(lr, 6, attr.first, attr.second);
        }

        if (!rec.traceId.empty()) {
            auto tBytes = hexToBytes(rec.traceId);
            if (tBytes.size() == 16) {
                writeBytes(lr, 9, tBytes.data(), 16);
            }
        }
        if (!rec.spanId.empty()) {
            auto sBytes = hexToBytes(rec.spanId);
            if (sBytes.size() == 8) {
                writeBytes(lr, 10, sBytes.data(), 8);
            }
        }

        writeSubmessage(scopeLogs, 2, lr);
    }

    std::vector<uint8_t> resource = encodeResource(res);

    std::vector<uint8_t> resourceLogs;
    writeSubmessage(resourceLogs, 1, resource);
    writeSubmessage(resourceLogs, 2, scopeLogs);

    std::vector<uint8_t> request;
    writeSubmessage(request, 1, resourceLogs);
    return request;
}

} // namespace Proto
} // namespace OTel
