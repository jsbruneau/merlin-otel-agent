#pragma once

#include "Collector.h"
#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace Collectors {

class HostMetricsCollector : public Collector {
public:
    const char* name() const override { return "host"; }
    bool init(const Config& cfg) override;
    void collectFast() override;
    void collectSlow() override;

    // Direct parser helpers (can be used with custom fixture paths for unit tests)
    void parseProcStat(const std::string& path = "/proc/stat");
    void parseProcMeminfo(const std::string& path = "/proc/meminfo");
    void parseProcLoadavg(const std::string& path = "/proc/loadavg");
    void parseProcUptime(const std::string& path = "/proc/uptime");
    void parseThermal(const std::string& basePath = "/sys/class/thermal");
    void parseFilesystems(const std::vector<std::string>& mountPoints = {"/", "/tmp", "/jffs"});
    void collectSelfMetrics();

private:
    struct CpuTimes {
        uint64_t user = 0;
        uint64_t nice = 0;
        uint64_t system = 0;
        uint64_t idle = 0;
        uint64_t iowait = 0;
        uint64_t irq = 0;
        uint64_t softirq = 0;
        uint64_t steal = 0;
    };
    std::map<std::string, CpuTimes> m_prevCpu;
    std::vector<std::string> m_mountPoints;
};

} // namespace Collectors
