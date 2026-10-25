#pragma once

#include "Collector.h"
#include <string>
#include <vector>

namespace Collectors {

class NetInterfaceCollector : public Collector {
public:
    const char* name() const override { return "net"; }
    bool init(const Config& cfg) override;
    void collectFast() override;
    void collectSlow() override;

    static std::vector<std::string> discoverInterfaces(const std::string& procNetDevPath = "/proc/net/dev");

    // Testable parser methods
    void parseProcNetDev(const std::string& path = "/proc/net/dev");
    void parseSysClassNet(const std::string& basePath = "/sys/class/net");
    void collectEthtoolStats(const std::string& iface);
    void parseEthctlOutput(const std::string& iface, const std::string& output);

private:
    std::vector<std::string> m_monitoredIfaces;
    bool m_useEthtoolIoctl = true;
};

} // namespace Collectors
