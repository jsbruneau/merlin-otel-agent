#pragma once

#include "Collector.h"
#include "platform/IpClassifier.h"
#include <cstddef>
#include <string>

namespace Collectors {

class BcmFlowCacheCollector : public Collector {
public:
    const char* name() const override { return "bcm_flowcache"; }
    bool init(const Config& cfg) override;
    void reloadConfig(const Config& cfg) override;
    void collectFast() override;
    void collectSlow() override;

    // Testable parser methods
    void parseProcFcacheStats(const std::string& path = "/proc/fcache/stats");
    void parseProcFcacheMisc(const std::string& path = "/proc/fcache/misc");
    void parseProcFcacheNfList(const std::string& path = "/proc/fcache/nflist");
    void parseProcFcacheBrList(const std::string& path = "/proc/fcache/brlist");
    void parseFcctlStatus(const std::string& output);
    void parseConntrack(const std::string& countPath = "/proc/sys/net/netfilter/nf_conntrack_count",
                        const std::string& maxPath = "/proc/sys/net/netfilter/nf_conntrack_max");

private:
    Platform::IpClassifier m_lanClassifier;
    size_t m_topClientFlows = 32;
    bool m_hasFcacheProc = false;
};

} // namespace Collectors
