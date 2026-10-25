#include "otel/OtelMetrics.h"
#include "otel/OtelSender.h"

namespace OTel {

std::string Metrics::s_scopeName = "merlin-router";
std::string Metrics::s_scopeVersion = MOTEL_VERSION;
bool Metrics::s_batchMode = false;
Proto::MetricBatch Metrics::s_activeBatch;

void Metrics::begin(const std::string& scopeName, const std::string& scopeVersion) {
    (void)processStartUnixNano();
    s_scopeName = scopeName;
    s_scopeVersion = scopeVersion;
}

void Metrics::startBatch() {
    s_activeBatch.clear();
    s_batchMode = true;
}

void Metrics::clearBatch() {
    s_activeBatch.clear();
    s_batchMode = false;
}

void Metrics::flushBatch() {
    if (s_activeBatch.empty()) {
        s_batchMode = false;
        return;
    }
    auto payload = s_activeBatch.encode(defaultResource(), s_scopeName, s_scopeVersion);
    if (!payload.empty()) {
        OTelSender::sendProto("/v1/metrics", std::move(payload));
    }
    s_activeBatch.clear();
    s_batchMode = false;
}

void Metrics::emit(Proto::MetricPoint&& pt) {
    if (s_batchMode) {
        s_activeBatch.addPoint(std::move(pt));
    } else {
        Proto::MetricBatch b;
        b.addPoint(std::move(pt));
        auto payload = b.encode(defaultResource(), s_scopeName, s_scopeVersion);
        OTelSender::sendProto("/v1/metrics", std::move(payload));
    }
}

void Metrics::gauge(const std::string& name, double value,
                    const std::string& unit,
                    const std::map<std::string, std::string>& labels) {
    Proto::MetricPoint pt;
    pt.name = name;
    pt.unit = unit;
    pt.isGauge = true;
    pt.isInt = false;
    pt.doubleValue = value;
    pt.attributes = labels;
    emit(std::move(pt));
}

void Metrics::gaugeInt(const std::string& name, int64_t value,
                       const std::string& unit,
                       const std::map<std::string, std::string>& labels) {
    Proto::MetricPoint pt;
    pt.name = name;
    pt.unit = unit;
    pt.isGauge = true;
    pt.isInt = true;
    pt.intValue = value;
    pt.attributes = labels;
    emit(std::move(pt));
}

void Metrics::sum(const std::string& name, double value,
                  bool isMonotonic, Proto::Temporality temporality,
                  const std::string& unit,
                  const std::map<std::string, std::string>& labels) {
    Proto::MetricPoint pt;
    pt.name = name;
    pt.unit = unit;
    pt.isGauge = false;
    pt.isMonotonic = isMonotonic;
    pt.temporality = temporality;
    pt.isInt = false;
    pt.doubleValue = value;
    pt.attributes = labels;
    emit(std::move(pt));
}

void Metrics::sumInt(const std::string& name, int64_t value,
                     bool isMonotonic, Proto::Temporality temporality,
                     const std::string& unit,
                     const std::map<std::string, std::string>& labels) {
    Proto::MetricPoint pt;
    pt.name = name;
    pt.unit = unit;
    pt.isGauge = false;
    pt.isMonotonic = isMonotonic;
    pt.temporality = temporality;
    pt.isInt = true;
    pt.intValue = value;
    pt.attributes = labels;
    emit(std::move(pt));
}

} // namespace OTel
