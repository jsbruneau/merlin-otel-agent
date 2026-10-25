#pragma once

#include "Collector.h"
#include <cstdint>
#include <string>
#include <sys/types.h>

namespace Collectors {

class SyslogTailer : public Collector {
public:
    ~SyslogTailer() override;

    const char* name() const override { return "syslog"; }
    bool init(const Config& cfg) override;
    void reloadConfig(const Config& cfg) override;
    void collectFast() override; // Scans new log lines
    void collectSlow() override {}

    // Testable line parser
    bool parseLine(const std::string& line, std::string& outApp, std::string& outPid,
                   std::string& outSeverity, std::string& outBody, uint64_t& outTimeNano);

    void processBuffer(const char* data, size_t len);
    bool allowLog();

private:
    bool openFile(bool seekToEnd = false);
    void checkRotation();

    std::string m_path = "/tmp/syslog.log";
    bool m_fromBeginning = false;
    int m_fd = -1;
    ino_t m_currentInode = 0;
    off_t m_lastOffset = 0;
    std::string m_lineBuffer;

    // Token Bucket Rate Limiter
    double m_tokens = 50.0;
    double m_maxTokens = 100.0;
    double m_refillRate = 50.0;
    uint64_t m_lastRefillMs = 0;
    uint64_t m_droppedBurstLines = 0;
};

} // namespace Collectors
