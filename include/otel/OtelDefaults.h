#pragma once

// Based in part on otel-embedded-cpp (https://github.com/proffalken/otel-embedded-cpp)
// Copyright (c) 2023 Matt Jarvis (MIT License)
// Adapted for pure POSIX/Linux C++17 by merlin-otel-agent contributors.

#include <cstdint>
#include <ctime>
#include <map>
#include <string>
#include <sys/time.h>
#include <unistd.h>

#ifndef MOTEL_VERSION
#define MOTEL_VERSION "0.1.0"
#endif

namespace OTel {

/** Return current UNIX timestamp in nanoseconds */
inline uint64_t nowUnixNano() {
    struct timespec ts{};
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
    }
    struct timeval tv{};
    gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * 1000000000ULL + static_cast<uint64_t>(tv.tv_usec) * 1000ULL;
}

/** Return process start UNIX timestamp in nanoseconds (used for cumulative sum start_time_unix_nano) */
inline uint64_t processStartUnixNano() {
    static const uint64_t s_startNano = nowUnixNano();
    return s_startNano;
}

/** Return monotonic clock in milliseconds */
inline uint64_t monotonicMillis() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
}

struct OTelResourceConfig {
    std::string serviceName = "merlin-router";
    std::string serviceInstanceId = "rt-be92u";
    std::string hostName = "router";
    std::map<std::string, std::string> attributes;

    void set(const std::string& k, const std::string& v) {
        if (k == "service.name") {
            serviceName = v;
        } else if (k == "service.instance.id") {
            serviceInstanceId = v;
        } else if (k == "host.name") {
            hostName = v;
        } else {
            attributes[k] = v;
        }
    }
};

inline OTelResourceConfig& defaultResource() {
    static OTelResourceConfig rc;
    return rc;
}

} // namespace OTel
