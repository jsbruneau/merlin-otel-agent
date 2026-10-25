#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace Platform {

struct IpSubnet {
    bool isIpv6 = false;
    uint32_t network4 = 0; // Host byte order (pre-masked)
    uint32_t mask4 = 0;    // Host byte order
    std::array<uint8_t, 16> network6{};
    std::array<uint8_t, 16> mask6{};

    static bool parse(const std::string& cidr, IpSubnet& out);
};

class IpClassifier {
public:
    IpClassifier();

    static const std::vector<std::string>& defaultLanSubnets();

    void setSubnets(const std::vector<std::string>& subnets);
    void setSubnets(const std::string& commaSeparated);

    const std::vector<std::string>& subnets() const { return m_rawSubnets; }

    // Centralized IP subnet lookup method used across all collectors
    bool contains(const std::string& ip) const;

private:
    void rebuild();

    std::vector<std::string> m_rawSubnets;
    std::vector<IpSubnet> m_parsedSubnets;
};

} // namespace Platform
