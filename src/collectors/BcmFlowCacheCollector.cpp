#include "collectors/BcmFlowCacheCollector.h"
#include "otel/OtelMetrics.h"
#include "platform/StringUtils.h"
#include "platform/SubprocessRunner.h"
#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace Collectors {

bool BcmFlowCacheCollector::init(const Config& cfg) {
    reloadConfig(cfg);
    std::ifstream testFile("/proc/fcache/stats");
    m_hasFcacheProc = testFile.good();
    return true;
}

void BcmFlowCacheCollector::reloadConfig(const Config& cfg) {
    m_lanClassifier = cfg.lanClassifier;
    m_topClientFlows = cfg.topClientFlows;
}

void BcmFlowCacheCollector::collectFast() {
    if (m_hasFcacheProc) {
        parseProcFcacheStats();
        parseProcFcacheMisc();
    } else {
        auto res = Platform::SubprocessRunner::run({"fcctl", "status"}, 500);
        if (res.success()) {
            parseFcctlStatus(res.stdoutData);
        }
    }
    parseConntrack();
}

void BcmFlowCacheCollector::collectSlow() {
    if (m_hasFcacheProc) {
        parseProcFcacheNfList();
        parseProcFcacheBrList();
    }
}

void BcmFlowCacheCollector::parseProcFcacheStats(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = line.substr(0, colon);
        std::string valStr = line.substr(colon + 1);

        std::istringstream vss(valStr);
        int64_t val = 0;
        if (!(vss >> val)) continue;

        if (key.find("Hits (Pkts)") != std::string::npos || key.find("hits_pkts") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.fcache.hits.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Hits (Bytes)") != std::string::npos || key.find("hits_bytes") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.fcache.hits.bytes", val, true, OTel::Proto::Temporality::CUMULATIVE, "By");
        } else if (key.find("Misses") != std::string::npos || key.find("misses_pkts") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.fcache.misses.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Total Flows") != std::string::npos || key.find("active_flows") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.fcache.flows.active", val, "{flows}");
            char sep = '\0';
            int64_t maxVal = 0;
            if ((vss >> sep >> maxVal) && sep == '/' && maxVal > 0) {
                OTel::Metrics::gaugeInt("bcm.fcache.flows.max", maxVal, "{flows}");
            }
        } else if (key.find("Max Flows") != std::string::npos || key.find("max_flows") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.fcache.flows.max", val, "{flows}");
        } else if (key.find("Evictions") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.fcache.evictions", val, true, OTel::Proto::Temporality::CUMULATIVE, "{flows}");
        } else if (key.find("Alloc Failures") != std::string::npos || key.find("alloc_fail") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.fcache.alloc_failures", val, true, OTel::Proto::Temporality::CUMULATIVE, "{errors}");
        }
    }
}

void BcmFlowCacheCollector::parseProcFcacheMisc(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = line.substr(0, colon);
        std::string valStr = line.substr(colon + 1);

        std::istringstream vss(valStr);
        int64_t val = 0;
        if (!(vss >> val)) continue;

        if (key.find("TCP Flows") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.fcache.flows.by_protocol", val, "{flows}", {{"protocol", "tcp"}});
        } else if (key.find("UDP Flows") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.fcache.flows.by_protocol", val, "{flows}", {{"protocol", "udp"}});
        } else if (key.find("HW Accelerated") != std::string::npos || key.find("FHW") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.fcache.flows.by_tier", val, "{flows}", {{"tier", "hardware_archer"}});
        } else if (key.find("SW Accelerated") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.fcache.flows.by_tier", val, "{flows}", {{"tier", "software_fcache"}});
        }
    }
}

void BcmFlowCacheCollector::parseProcFcacheNfList(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::map<std::string, std::pair<uint64_t, uint64_t>> clientTraffic; // clientIP -> {bytes, pkts}
    uint64_t tcpCount = 0, udpCount = 0, hwCount = 0, swCount = 0;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#' || line[0] == '-') continue;

        std::istringstream ss(line);
        std::string token;
        std::vector<std::string> tokens;
        while (ss >> token) tokens.push_back(token);

        if (tokens.size() < 5) continue;

        bool isHw = false;
        uint64_t pkts = 0, bytes = 0;
        std::string srcIp, dstIp;

        for (const auto& t : tokens) {
            if (t == "TCP" || t == "tcp") {
                ++tcpCount;
            } else if (t == "UDP" || t == "udp") {
                ++udpCount;
            } else if (t.find("HW") != std::string::npos ||
                       t.find("FHW") != std::string::npos ||
                       t.find("ARCHER") != std::string::npos) {
                isHw = true;
            }

            // Parse IP:port or [IPv6]:port
            if (!t.empty() && t.front() == '[') {
                size_t rbracket = t.find(']');
                if (rbracket != std::string::npos && rbracket > 1) {
                    if (srcIp.empty()) srcIp = t.substr(1, rbracket - 1);
                    else if (dstIp.empty()) dstIp = t.substr(1, rbracket - 1);
                }
            } else {
                size_t colon = t.find(':');
                if (colon != std::string::npos && t.find('.') != std::string::npos) {
                    if (srcIp.empty()) srcIp = t.substr(0, colon);
                    else if (dstIp.empty()) dstIp = t.substr(0, colon);
                }
            }

            if (t.rfind("bytes=", 0) == 0 || t.rfind("b=", 0) == 0) {
                size_t eq = t.find('=');
                Platform::parseUint64(t.substr(eq + 1), bytes);
            } else if (t.rfind("pkts=", 0) == 0 || t.rfind("p=", 0) == 0) {
                size_t eq = t.find('=');
                Platform::parseUint64(t.substr(eq + 1), pkts);
            }
        }

        if (isHw) ++hwCount;
        else ++swCount;

        // Aggregate per client IP using centralized LAN subnet classifier
        if (m_lanClassifier.contains(srcIp)) {
            clientTraffic[srcIp].first += bytes;
            clientTraffic[srcIp].second += pkts;
        } else if (m_lanClassifier.contains(dstIp)) {
            clientTraffic[dstIp].first += bytes;
            clientTraffic[dstIp].second += pkts;
        }
    }

    if (tcpCount > 0 || udpCount > 0) {
        OTel::Metrics::gaugeInt("bcm.fcache.flows.by_protocol", static_cast<int64_t>(tcpCount), "{flows}", {{"protocol", "tcp"}});
        OTel::Metrics::gaugeInt("bcm.fcache.flows.by_protocol", static_cast<int64_t>(udpCount), "{flows}", {{"protocol", "udp"}});
        OTel::Metrics::gaugeInt("bcm.fcache.flows.by_tier", static_cast<int64_t>(hwCount), "{flows}", {{"tier", "hardware_archer"}});
        OTel::Metrics::gaugeInt("bcm.fcache.flows.by_tier", static_cast<int64_t>(swCount), "{flows}", {{"tier", "software_fcache"}});
    }

    // Top client flow emitters
    std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>> sorted(clientTraffic.begin(), clientTraffic.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.second.first > b.second.first; // sort by bytes descending
    });

    size_t count = std::min(sorted.size(), m_topClientFlows);
    for (size_t i = 0; i < count; ++i) {
        const auto& item = sorted[i];
        OTel::Metrics::sumInt("bcm.fcache.client.bytes", static_cast<int64_t>(item.second.first), true, OTel::Proto::Temporality::CUMULATIVE, "By", {{"client_ip", item.first}});
        OTel::Metrics::sumInt("bcm.fcache.client.packets", static_cast<int64_t>(item.second.second), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"client_ip", item.first}});
    }
}

void BcmFlowCacheCollector::parseProcFcacheBrList(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    int64_t brFlowCount = 0;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#' && line[0] != '-') {
            ++brFlowCount;
        }
    }
    OTel::Metrics::gaugeInt("bcm.fcache.flows.bridged", brFlowCount, "{flows}");
}

void BcmFlowCacheCollector::parseFcctlStatus(const std::string& output) {
    std::istringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = line.substr(0, colon);
        std::string valStr = line.substr(colon + 1);

        std::istringstream vss(valStr);
        int64_t val = 0;
        if (!(vss >> val)) continue;

        if (key.find("Hits") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.fcache.hits.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Misses") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.fcache.misses.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Flows") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.fcache.flows.active", val, "{flows}");
        }
    }
}

void BcmFlowCacheCollector::parseConntrack(const std::string& countPath, const std::string& maxPath) {
    std::ifstream countFile(countPath);
    int64_t ctCount = 0;
    if (countFile >> ctCount) {
        OTel::Metrics::gaugeInt("bcm.conntrack.count", ctCount, "{connections}");
    }

    std::ifstream maxFile(maxPath);
    int64_t ctMax = 0;
    if (maxFile >> ctMax) {
        OTel::Metrics::gaugeInt("bcm.conntrack.max", ctMax, "{connections}");
        if (ctMax > 0 && ctCount >= 0) {
            double util = static_cast<double>(ctCount) / static_cast<double>(ctMax);
            OTel::Metrics::gauge("bcm.conntrack.utilization", util, "1");
        }
    }
}

} // namespace Collectors
