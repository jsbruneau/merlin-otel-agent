#include "collectors/HostMetricsCollector.h"
#include "otel/OtelMetrics.h"
#include "otel/OtelSender.h"
#include "platform/StringUtils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <dirent.h>
#include <sys/statvfs.h>

namespace Collectors {

bool HostMetricsCollector::init(const Config& /*cfg*/) {
    m_mountPoints = {"/", "/tmp", "/jffs"};
    return true;
}

void HostMetricsCollector::collectFast() {
    parseProcStat();
    parseProcMeminfo();
    parseProcLoadavg();
    parseProcUptime();
    parseThermal();
    collectSelfMetrics();
}

void HostMetricsCollector::collectSlow() {
    parseFilesystems(m_mountPoints);
}

void HostMetricsCollector::parseProcStat(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    long ticksPerSec = sysconf(_SC_CLK_TCK);
    if (ticksPerSec <= 0) ticksPerSec = 100;

    std::string line;
    while (std::getline(file, line)) {
        if (line.compare(0, 3, "cpu") != 0) continue;

        std::istringstream ss(line);
        std::string cpu;
        uint64_t u = 0, n = 0, s = 0, id = 0, io = 0, ir = 0, si = 0, st = 0;
        ss >> cpu >> u >> n >> s >> id >> io >> ir >> si >> st;

        double userSec    = static_cast<double>(u) / ticksPerSec;
        double niceSec    = static_cast<double>(n) / ticksPerSec;
        double sysSec     = static_cast<double>(s) / ticksPerSec;
        double idleSec    = static_cast<double>(id) / ticksPerSec;
        double iowaitSec  = static_cast<double>(io) / ticksPerSec;
        double irqSec     = static_cast<double>(ir) / ticksPerSec;
        double softirqSec = static_cast<double>(si) / ticksPerSec;
        double stealSec   = static_cast<double>(st) / ticksPerSec;

        OTel::Metrics::sum("system.cpu.time", userSec,    true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "user"}});
        OTel::Metrics::sum("system.cpu.time", niceSec,    true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "nice"}});
        OTel::Metrics::sum("system.cpu.time", sysSec,     true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "system"}});
        OTel::Metrics::sum("system.cpu.time", idleSec,    true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "idle"}});
        OTel::Metrics::sum("system.cpu.time", iowaitSec,  true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "iowait"}});
        OTel::Metrics::sum("system.cpu.time", irqSec,     true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "irq"}});
        OTel::Metrics::sum("system.cpu.time", softirqSec, true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "softirq"}});
        OTel::Metrics::sum("system.cpu.time", stealSec,   true, OTel::Proto::Temporality::CUMULATIVE, "s", {{"cpu", cpu}, {"state", "steal"}});

        // Utilization calculation if previous measurement exists
        auto it = m_prevCpu.find(cpu);
        if (it != m_prevCpu.end()) {
            uint64_t prevActive = it->second.user + it->second.nice + it->second.system + it->second.irq + it->second.softirq + it->second.steal;
            uint64_t prevTotal = prevActive + it->second.idle + it->second.iowait;

            uint64_t curActive = u + n + s + ir + si + st;
            uint64_t curTotal = curActive + id + io;

            uint64_t dActive = curActive - prevActive;
            uint64_t dTotal = curTotal - prevTotal;

            if (dTotal > 0) {
                double util = static_cast<double>(dActive) / static_cast<double>(dTotal);
                OTel::Metrics::gauge("system.cpu.utilization", util, "1", {{"cpu", cpu}});
            }
        }
        m_prevCpu[cpu] = {u, n, s, id, io, ir, si, st};
    }
}

void HostMetricsCollector::parseProcMeminfo(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    int64_t total = 0, free = 0, avail = 0, buffers = 0, cached = 0, slab = 0, sReclaim = 0, sUnreclaim = 0;

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream ss(line);
        std::string key;
        int64_t val = 0;
        ss >> key >> val;

        if (key == "MemTotal:") total = val * 1024;
        else if (key == "MemFree:") free = val * 1024;
        else if (key == "MemAvailable:") avail = val * 1024;
        else if (key == "Buffers:") buffers = val * 1024;
        else if (key == "Cached:") cached = val * 1024;
        else if (key == "Slab:") slab = val * 1024;
        else if (key == "SReclaimable:") sReclaim = val * 1024;
        else if (key == "SUnreclaim:") sUnreclaim = val * 1024;
    }

    if (total > 0) {
        int64_t used = total - (avail > 0 ? avail : (free + buffers + cached));
        if (used < 0) used = 0;

        OTel::Metrics::gaugeInt("system.memory.usage", free,        "By", {{"state", "free"}});
        OTel::Metrics::gaugeInt("system.memory.usage", used,        "By", {{"state", "used"}});
        OTel::Metrics::gaugeInt("system.memory.usage", buffers,     "By", {{"state", "buffered"}});
        OTel::Metrics::gaugeInt("system.memory.usage", cached,      "By", {{"state", "cached"}});
        OTel::Metrics::gaugeInt("system.memory.usage", slab,        "By", {{"state", "slab"}});
        OTel::Metrics::gaugeInt("system.memory.usage", sReclaim,    "By", {{"state", "slab_reclaimable"}});
        OTel::Metrics::gaugeInt("system.memory.usage", sUnreclaim,  "By", {{"state", "slab_unreclaimable"}});

        double util = static_cast<double>(used) / static_cast<double>(total);
        OTel::Metrics::gauge("system.memory.utilization", util, "1");
    }
}

void HostMetricsCollector::parseProcLoadavg(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    double l1 = 0.0, l5 = 0.0, l15 = 0.0;
    std::string procs;
    file >> l1 >> l5 >> l15 >> procs;

    OTel::Metrics::gauge("system.cpu.load_average.1m",  l1,  "1");
    OTel::Metrics::gauge("system.cpu.load_average.5m",  l5,  "1");
    OTel::Metrics::gauge("system.cpu.load_average.15m", l15, "1");

    size_t slash = procs.find('/');
    if (slash != std::string::npos) {
        int64_t running = 0;
        int64_t total = 0;
        if (Platform::parseInt64(procs.substr(0, slash), running) &&
            Platform::parseInt64(procs.substr(slash + 1), total)) {
            OTel::Metrics::gaugeInt("system.processes.running", running, "1");
            OTel::Metrics::gaugeInt("system.processes.total",   total,   "1");
        }
    }
}

void HostMetricsCollector::parseProcUptime(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    double uptime = 0.0;
    file >> uptime;
    if (uptime > 0.0) {
        OTel::Metrics::sum("system.uptime", uptime, true, OTel::Proto::Temporality::CUMULATIVE, "s");
    }
}

void HostMetricsCollector::parseThermal(const std::string& basePath) {
    DIR* dir = opendir(basePath.c_str());
    if (!dir) return;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (std::strncmp(ent->d_name, "thermal_zone", 12) == 0) {
            std::string tempPath = basePath + "/" + ent->d_name + "/temp";
            std::string typePath = basePath + "/" + ent->d_name + "/type";

            std::ifstream typeFile(typePath);
            std::string sensorType = "cpu";
            if (typeFile.is_open()) {
                std::getline(typeFile, sensorType);
                if (sensorType.empty()) sensorType = "cpu";
            }

            std::ifstream tempFile(tempPath);
            double milliCel = 0;
            if (tempFile >> milliCel) {
                double cel = (milliCel > 1000.0) ? (milliCel / 1000.0) : milliCel;
                OTel::Metrics::gauge("hw.temperature", cel, "Cel", {{"sensor", sensorType}, {"zone", ent->d_name}});
            }
        }
    }
    closedir(dir);
}

void HostMetricsCollector::parseFilesystems(const std::vector<std::string>& mountPoints) {
    for (const auto& mp : mountPoints) {
        struct statvfs st;
        if (statvfs(mp.c_str(), &st) == 0) {
            uint64_t totalBytes = static_cast<uint64_t>(st.f_blocks) * st.f_frsize;
            uint64_t freeBytes  = static_cast<uint64_t>(st.f_bfree) * st.f_frsize;
            uint64_t usedBytes  = (totalBytes >= freeBytes) ? (totalBytes - freeBytes) : 0;

            OTel::Metrics::gaugeInt("system.filesystem.usage", static_cast<int64_t>(usedBytes), "By", {{"device", mp}, {"state", "used"}});
            OTel::Metrics::gaugeInt("system.filesystem.usage", static_cast<int64_t>(freeBytes), "By", {{"device", mp}, {"state", "free"}});

            if (totalBytes > 0) {
                double util = static_cast<double>(usedBytes) / static_cast<double>(totalBytes);
                OTel::Metrics::gauge("system.filesystem.utilization", util, "1", {{"device", mp}});
            }
        }
    }
}

void HostMetricsCollector::collectSelfMetrics() {
    std::ifstream file("/proc/self/statm");
    if (file.is_open()) {
        uint64_t sizePages = 0, residentPages = 0;
        file >> sizePages >> residentPages;
        long pageSize = sysconf(_SC_PAGESIZE);
        if (pageSize <= 0) pageSize = 4096;

        int64_t rssBytes = residentPages * pageSize;
        int64_t vmsBytes = sizePages * pageSize;
        OTel::Metrics::gaugeInt("otel.collector.rss_bytes", rssBytes, "By");
        OTel::Metrics::gaugeInt("otel.collector.vms_bytes", vmsBytes, "By");
    }

    OTel::Metrics::sumInt("otel.collector.dropped_payloads", static_cast<int64_t>(OTel::OTelSender::droppedCount()), true, OTel::Proto::Temporality::CUMULATIVE);
    OTel::Metrics::sumInt("otel.collector.sent_payloads",    static_cast<int64_t>(OTel::OTelSender::sentCount()),    true, OTel::Proto::Temporality::CUMULATIVE);
    OTel::Metrics::sumInt("otel.collector.failed_payloads",  static_cast<int64_t>(OTel::OTelSender::failedCount()),  true, OTel::Proto::Temporality::CUMULATIVE);
}

} // namespace Collectors
