#pragma once

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string>

namespace Platform {

inline std::string trimWhitespace(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

inline std::string trimAndUnquote(const std::string& s) {
    std::string res = trimWhitespace(s);
    if (res.size() >= 2) {
        if ((res.front() == '"' && res.back() == '"') ||
            (res.front() == '\'' && res.back() == '\'')) {
            res = res.substr(1, res.size() - 2);
        }
    }
    return res;
}

inline bool parseInt64(const std::string& s, int64_t& out) {
    std::string trimmed = trimWhitespace(s);
    if (trimmed.empty()) return false;

    errno = 0;
    char* endPtr = nullptr;
    long long val = std::strtoll(trimmed.c_str(), &endPtr, 10);
    if (errno == ERANGE || endPtr == trimmed.c_str() || *endPtr != '\0') {
        return false;
    }
    out = static_cast<int64_t>(val);
    return true;
}

inline bool parseUint64(const std::string& s, uint64_t& out) {
    std::string trimmed = trimWhitespace(s);
    if (trimmed.empty() || trimmed.front() == '-') return false;

    errno = 0;
    char* endPtr = nullptr;
    unsigned long long val = std::strtoull(trimmed.c_str(), &endPtr, 10);
    if (errno == ERANGE || endPtr == trimmed.c_str() || *endPtr != '\0') {
        return false;
    }
    out = static_cast<uint64_t>(val);
    return true;
}

inline bool parseDouble(const std::string& s, double& out) {
    std::string trimmed = trimWhitespace(s);
    if (trimmed.empty()) return false;

    errno = 0;
    char* endPtr = nullptr;
    double val = std::strtod(trimmed.c_str(), &endPtr);
    if (errno == ERANGE || endPtr == trimmed.c_str() || *endPtr != '\0' || !std::isfinite(val)) {
        return false;
    }
    out = val;
    return true;
}

} // namespace Platform
