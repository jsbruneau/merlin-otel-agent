#include "otel/OtelLogger.h"
#include "otel/OtelSender.h"

namespace OTel {

std::string Logger::s_scopeName = "merlin-router";
std::string Logger::s_scopeVersion = MOTEL_VERSION;
bool Logger::s_batchMode = false;
Proto::LogBatch Logger::s_activeBatch;

void Logger::begin(const std::string& scopeName, const std::string& scopeVersion) {
    s_scopeName = scopeName;
    s_scopeVersion = scopeVersion;
}

void Logger::startBatch() {
    s_activeBatch.clear();
    s_batchMode = true;
}

void Logger::clearBatch() {
    s_activeBatch.clear();
    s_batchMode = false;
}

void Logger::flushBatch() {
    if (s_activeBatch.empty()) {
        s_batchMode = false;
        return;
    }
    auto payload = s_activeBatch.encode(defaultResource(), s_scopeName, s_scopeVersion);
    if (!payload.empty()) {
        OTelSender::sendProto("/v1/logs", std::move(payload));
    }
    s_activeBatch.clear();
    s_batchMode = false;
}

void Logger::log(const std::string& severity, const std::string& message,
                 const std::map<std::string, std::string>& labels,
                 uint64_t timeNano,
                 const std::string& traceId, const std::string& spanId) {
    int num = severityNumberFromText(severity);

    if (s_batchMode) {
        s_activeBatch.addRecord(severity, num, message, labels, timeNano, traceId, spanId);
        // Flush if batch gets large to bound RAM on the router
        if (s_activeBatch.size() >= 64) {
            flushBatch();
            s_batchMode = true;
        }
    } else {
        Proto::LogBatch b;
        b.addRecord(severity, num, message, labels, timeNano, traceId, spanId);
        auto payload = b.encode(defaultResource(), s_scopeName, s_scopeVersion);
        OTelSender::sendProto("/v1/logs", std::move(payload));
    }
}

} // namespace OTel
