#pragma once

#include "Collector.h"
#include "platform/IpClassifier.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace Collectors {

struct FlowKey {
    std::string clientIp;
    std::string protocol;
    std::string destPort;

    bool operator<(const FlowKey& o) const {
        if (clientIp != o.clientIp) return clientIp < o.clientIp;
        if (protocol != o.protocol) return protocol < o.protocol;
        return destPort < o.destPort;
    }
};

struct FlowCounters {
    uint64_t txBytes = 0;
    uint64_t rxBytes = 0;
    uint64_t txPackets = 0;
    uint64_t rxPackets = 0;
};

class NetlinkConntrackCollector : public Collector {
public:
    ~NetlinkConntrackCollector() override;

    const char* name() const override { return "netlink_conntrack"; }
    bool init(const Config& cfg) override;
    void reloadConfig(const Config& cfg) override;
    void collectFast() override;
    void collectSlow() override {}

    // Testable helpers
    static std::string normalizePort(uint16_t dport, const std::string& proto);
    bool parseNetlinkMessage(const uint8_t* data, size_t len);
    void recordCompletedFlow(const std::string& srcIp,
                             const std::string& dstIp,
                             const std::string& proto,
                             uint16_t srcPort,
                             uint16_t dstPort,
                             uint64_t txBytes,
                             uint64_t rxBytes,
                             uint64_t txPackets,
                             uint64_t rxPackets);

    size_t trackedFlowCount() const { return m_flowTotals.size(); }
    const std::map<FlowKey, FlowCounters>& flowTotals() const { return m_flowTotals; }

private:
    void applyConfig(const Config& cfg);
    bool openNetlinkSocket();
    void enableConntrackAccounting();
    void drainSocket();

    Platform::IpClassifier m_lanClassifier;
    size_t m_maxFlows = 512;
    int m_fd = -1;
    std::map<FlowKey, FlowCounters> m_flowTotals;
};

} // namespace Collectors
