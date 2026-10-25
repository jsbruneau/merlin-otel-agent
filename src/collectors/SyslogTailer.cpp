#include "collectors/SyslogTailer.h"
#include "otel/OtelLogger.h"
#include "otel/OtelMetrics.h"
#include "platform/StringUtils.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace Collectors {

SyslogTailer::~SyslogTailer() {
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
}

bool SyslogTailer::init(const Config& cfg) {
    m_path = cfg.syslogFile;
    m_fromBeginning = cfg.syslogFromBeginning;
    m_refillRate = cfg.syslogRateLimit;
    m_maxTokens = cfg.syslogBurstLimit;
    m_tokens = m_maxTokens;
    m_lastRefillMs = OTel::monotonicMillis();
    return openFile(!m_fromBeginning);
}

void SyslogTailer::reloadConfig(const Config& cfg) {
    m_refillRate = cfg.syslogRateLimit;
    m_maxTokens = cfg.syslogBurstLimit;
    if (m_tokens > m_maxTokens) {
        m_tokens = m_maxTokens;
    }
}

bool SyslogTailer::allowLog() {
    if (m_refillRate <= 0.0) return true; // 0 = disabled / unlimited

    uint64_t nowMs = OTel::monotonicMillis();
    double elapsedSec = static_cast<double>(nowMs - m_lastRefillMs) / 1000.0;
    m_lastRefillMs = nowMs;

    m_tokens = std::min(m_maxTokens, m_tokens + elapsedSec * m_refillRate);

    if (m_tokens >= 1.0) {
        m_tokens -= 1.0;
        return true;
    }

    ++m_droppedBurstLines;
    OTel::Metrics::sumInt("otel.collector.syslog.dropped_burst_lines", 1, true, OTel::Proto::Temporality::CUMULATIVE, "{lines}");
    return false;
}

bool SyslogTailer::openFile(bool seekToEnd) {
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }

    m_fd = open(m_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (m_fd < 0) return false;

    struct stat st{};
    if (fstat(m_fd, &st) == 0) {
        m_currentInode = st.st_ino;
        if (seekToEnd) {
            lseek(m_fd, 0, SEEK_END);
            m_lastOffset = st.st_size;
        } else {
            lseek(m_fd, 0, SEEK_SET);
            m_lastOffset = 0;
        }
    }
    return true;
}

void SyslogTailer::checkRotation() {
    struct stat st{};
    if (stat(m_path.c_str(), &st) != 0) return;

    if (m_fd < 0 || st.st_ino != m_currentInode || st.st_size < m_lastOffset) {
        // File rotated or truncated
        if (m_fd >= 0) {
            // Read any final bytes
            std::array<char, 2048> buf{};
            ssize_t n = 0;
            while ((n = read(m_fd, buf.data(), buf.size())) > 0) {
                processBuffer(buf.data(), static_cast<size_t>(n));
            }
            close(m_fd);
            m_fd = -1;
        }
        openFile(false); // Read from beginning of new file
        OTel::Metrics::sumInt("otel.collector.syslog.rotations", 1, true, OTel::Proto::Temporality::CUMULATIVE, "{rotations}");
    }
}

void SyslogTailer::collectFast() {
    checkRotation();
    if (m_fd < 0) return;

    std::array<char, 4096> buf{};
    ssize_t n = 0;
    while ((n = read(m_fd, buf.data(), buf.size())) > 0) {
        m_lastOffset += n;
        processBuffer(buf.data(), static_cast<size_t>(n));
    }
}

void SyslogTailer::processBuffer(const char* data, size_t len) {
    constexpr size_t kMaxLineBuffer = 65536;
    if (m_lineBuffer.size() > kMaxLineBuffer) {
        // Line buffer accumulated too much data without a newline delimiter;
        // reset to prevent memory exhaustion on embedded routers.
        m_lineBuffer.clear();
    }
    if (len > kMaxLineBuffer) {
        data += (len - kMaxLineBuffer);
        len = kMaxLineBuffer;
    }
    m_lineBuffer.append(data, len);

    size_t pos = 0;
    while ((pos = m_lineBuffer.find('\n')) != std::string::npos) {
        std::string line = m_lineBuffer.substr(0, pos);
        m_lineBuffer.erase(0, pos + 1);

        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        if (!allowLog()) continue; // Drop spam before parsing & allocations

        std::string app, pid, severity, body;
        uint64_t timeNano = 0;
        if (parseLine(line, app, pid, severity, body, timeNano)) {
            std::map<std::string, std::string> attrs;
            if (!app.empty()) attrs["syslog.app"] = app;
            if (!pid.empty()) attrs["syslog.pid"] = pid;

            OTel::Logger::log(severity, body, attrs, timeNano);
        }
    }
}

static int monthToInt(const std::string& m) {
    static constexpr const char* kMonths[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    for (int i = 0; i < 12; ++i) {
        if (m == kMonths[i]) return i;
    }
    return -1;
}

static bool parseHms(const std::string& s, int& hour, int& min, int& sec) {
    size_t c1 = s.find(':');
    if (c1 == std::string::npos) return false;
    size_t c2 = s.find(':', c1 + 1);
    if (c2 == std::string::npos || s.find(':', c2 + 1) != std::string::npos) return false;

    int64_t h = 0, m = 0, sc = 0;
    if (!Platform::parseInt64(s.substr(0, c1), h) ||
        !Platform::parseInt64(s.substr(c1 + 1, c2 - c1 - 1), m) ||
        !Platform::parseInt64(s.substr(c2 + 1), sc)) {
        return false;
    }
    if (h < 0 || h > 23 || m < 0 || m > 59 || sc < 0 || sc > 60) {
        return false;
    }
    hour = static_cast<int>(h);
    min = static_cast<int>(m);
    sec = static_cast<int>(sc);
    return true;
}

bool SyslogTailer::parseLine(const std::string& line, std::string& outApp, std::string& outPid,
                             std::string& outSeverity, std::string& outBody, uint64_t& outTimeNano) {
    outApp.clear();
    outPid.clear();
    outSeverity = "INFO";
    outBody.clear();
    outTimeNano = 0;

    if (line.empty()) return false;

    // Typical BSD syslog format:
    // "Oct 24 13:45:01 hostname app[pid]: message" or "Oct 24 13:45:01 app: message"
    std::istringstream ss(line);
    std::string month, day, timeStr;

    if (!(ss >> month >> day >> timeStr)) {
        outBody = line;
        return true;
    }

    int mon = monthToInt(month);
    int64_t dayVal = 0;
    int hour = 0, min = 0, sec = 0;

    if (mon >= 0 && Platform::parseInt64(day, dayVal) && dayVal >= 1 && dayVal <= 31 &&
        parseHms(timeStr, hour, min, sec)) {
        time_t now = time(nullptr);
        struct tm tmVal{};
        if (localtime_r(&now, &tmVal) != nullptr) {
            tmVal.tm_mon = mon;
            tmVal.tm_mday = static_cast<int>(dayVal);
            tmVal.tm_hour = hour;
            tmVal.tm_min = min;
            tmVal.tm_sec = sec;
            tmVal.tm_isdst = -1;
            time_t logSec = mktime(&tmVal);
            if (logSec > 0 && tmVal.tm_year > 100) { // Valid year > 2000
                outTimeNano = static_cast<uint64_t>(logSec) * 1000000000ULL;
            }
        }

        // Read remaining tokens: host (optional), app[pid]:, body
        std::string tagToken;
        ss >> tagToken;

        // If tagToken looks like a hostname (e.g. RT-BE92U), read next token as app
        if (tagToken.find(':') == std::string::npos && tagToken.find('[') == std::string::npos) {
            std::string nextTag;
            if (ss >> nextTag) {
                tagToken = nextTag;
            }
        }

        // Parse app and pid from tagToken (e.g., "dnsmasq[1234]:" or "kernel:")
        size_t colon = tagToken.find(':');
        if (colon != std::string::npos) tagToken.resize(colon);

        size_t lbracket = tagToken.find('[');
        size_t rbracket = tagToken.find(']');
        if (lbracket != std::string::npos && rbracket != std::string::npos && rbracket > lbracket) {
            outApp = tagToken.substr(0, lbracket);
            outPid = tagToken.substr(lbracket + 1, rbracket - (lbracket + 1));
        } else {
            outApp = tagToken;
        }

        // Remainder of line is message body
        std::string remaining;
        std::getline(ss, remaining);
        size_t start = remaining.find_first_not_of(" \t");
        if (start != std::string::npos) {
            outBody = remaining.substr(start);
        } else {
            outBody = remaining;
        }
    } else {
        // Not a standard BSD syslog header; treat entire line as body
        outBody = Platform::trimWhitespace(line);
    }

    // Infer severity from keywords
    std::string lowerBody = outBody;
    std::transform(lowerBody.begin(), lowerBody.end(), lowerBody.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lowerBody.find("panic") != std::string::npos ||
        lowerBody.find("oom-killer") != std::string::npos ||
        lowerBody.find("out of memory") != std::string::npos ||
        lowerBody.find("kernel crash") != std::string::npos) {
        outSeverity = "FATAL";
    } else if (lowerBody.find("error") != std::string::npos ||
               lowerBody.find("failed") != std::string::npos ||
               lowerBody.find("failure") != std::string::npos ||
               lowerBody.find("critical") != std::string::npos) {
        outSeverity = "ERROR";
    } else if (lowerBody.find("warn") != std::string::npos ||
               lowerBody.find("deauth") != std::string::npos ||
               lowerBody.find("drop") != std::string::npos) {
        outSeverity = "WARN";
    } else if (lowerBody.find("debug") != std::string::npos) {
        outSeverity = "DEBUG";
    } else {
        outSeverity = "INFO";
    }

    return true;
}

} // namespace Collectors
