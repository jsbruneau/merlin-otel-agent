#pragma once

// Based in part on otel-embedded-cpp (https://github.com/proffalken/otel-embedded-cpp)
// Copyright (c) 2023 Matt Jarvis (MIT License)
// Adapted for pure POSIX/Linux C++17 by merlin-otel-agent contributors.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace OTel {

struct OTelQueuedItem {
    std::string path;        // "/v1/metrics" or "/v1/logs"
    std::string contentType; // "application/x-protobuf"
    std::vector<uint8_t> payload;
};

class OTelSender {
public:
    struct ParsedUrl {
        std::string scheme = "http";
        std::string host = "127.0.0.1";
        std::string port = "4318";
        std::string basePath; // e.g. "/api/default"
    };

    static void init(const std::string& endpoint,
                     const std::string& headers = "",
                     size_t queueCapacity = 128,
                     int timeoutSec = 5,
                     bool verbose = false);

    static void shutdown();

    static void sendProto(const std::string& path, std::vector<uint8_t>&& payload);

    static uint64_t droppedCount();
    static uint64_t sentCount();
    static uint64_t failedCount();

    // URL and header parsing helpers (exposed for unit testing)
    static ParsedUrl parseUrl(const std::string& rawUrl);
    static std::string buildSignalUrl(const std::string& endpoint, const std::string& signalPath);
    static std::string buildSignalPath(const std::string& endpoint, const std::string& signalPath);
    static std::vector<std::string> parseHttpHeaders(const std::string& rawHeaders);

private:
    OTelSender() = default;
    ~OTelSender();

    static OTelSender& instance();
    void enqueue(OTelQueuedItem&& item);
    void workerLoop();
    bool postHttp(const OTelQueuedItem& item);

    std::string m_endpoint = "http://127.0.0.1:4318";
    std::string m_headers;
    size_t m_capacity = 32;
    int m_timeoutSec = 3;
    bool m_verbose = false;

    std::vector<OTelQueuedItem> m_queue;
    size_t m_head = 0;
    size_t m_tail = 0;
    size_t m_count = 0;

    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_worker;
    std::atomic<bool> m_running{false};

    std::atomic<uint64_t> m_dropped{0};
    std::atomic<uint64_t> m_sent{0};
    std::atomic<uint64_t> m_failed{0};
    std::atomic<uint32_t> m_consecutiveFailures{0};
};

} // namespace OTel
