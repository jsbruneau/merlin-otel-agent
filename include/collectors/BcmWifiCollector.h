#pragma once

#include "Collector.h"
#include <string>
#include <vector>

namespace Collectors {

class BcmWifiCollector : public Collector {
public:
    const char* name() const override { return "bcm_wifi"; }
    bool init(const Config& cfg) override;
    void collectFast() override;
    void collectSlow() override;

    // Interface discovery, validation, and band helpers
    static std::vector<std::string> discoverWifiInterfaces(const std::string& procNetDevPath = "/proc/net/dev");
    static std::string bandFromRadio(const std::string& radio);
    static bool isPhysicalRadio(const std::string& iface);
    static bool isValidMacAddress(const std::string& mac);

    // Testable parsers
    void parseNoise(const std::string& radio, const std::string& output);
    void parseChanimStats(const std::string& radio, const std::string& output);
    void parseAssocList(const std::string& radio, const std::string& output);
    void parsePhyTemp(const std::string& radio, const std::string& output);
    void parseStaInfo(const std::string& radio, const std::string& mac, const std::string& output);

    void setProcNetDevPath(const std::string& path) { m_procNetDevPath = path; }

private:
    std::string m_procNetDevPath = "/proc/net/dev";
};

} // namespace Collectors
