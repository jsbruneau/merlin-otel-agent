#include "platform/IpClassifier.h"
#include "platform/StringUtils.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iostream>
#include <sstream>

namespace Platform {

bool IpSubnet::parse(const std::string& cidr, IpSubnet& out) {
    std::string s = trimAndUnquote(cidr);
    if (s.empty()) return false;

    std::string addrStr = s;
    bool hasPrefix = false;
    uint32_t prefixLen = 0;

    size_t slash = s.find('/');
    if (slash != std::string::npos) {
        addrStr = trimWhitespace(s.substr(0, slash));
        std::string prefixStr = trimWhitespace(s.substr(slash + 1));
        if (addrStr.empty() || prefixStr.empty()) return false;

        for (char c : prefixStr) {
            if (c < '0' || c > '9') return false;
            prefixLen = prefixLen * 10U + static_cast<uint32_t>(c - '0');
            if (prefixLen > 128U) return false;
        }
        hasPrefix = true;
    }

    struct in_addr addr4{};
    if (inet_pton(AF_INET, addrStr.c_str(), &addr4) == 1) {
        uint32_t plen = hasPrefix ? prefixLen : 32U;
        if (plen > 32U) return false;

        uint32_t mask = (plen == 0U) ? 0U : (~0U << (32U - plen));
        uint32_t hostIp = ntohl(addr4.s_addr);

        out = IpSubnet{};
        out.isIpv6 = false;
        out.mask4 = mask;
        out.network4 = hostIp & mask;
        return true;
    }

    struct in6_addr addr6{};
    if (inet_pton(AF_INET6, addrStr.c_str(), &addr6) == 1) {
        uint32_t plen = hasPrefix ? prefixLen : 128U;
        if (plen > 128U) return false;

        out = IpSubnet{};
        out.isIpv6 = true;
        uint32_t fullBytes = plen / 8U;
        uint32_t remBits = plen % 8U;
        for (size_t i = 0; i < 16; ++i) {
            uint8_t maskByte = 0;
            if (i < fullBytes) {
                maskByte = 0xFFU;
            } else if (i == fullBytes && remBits > 0U) {
                maskByte = static_cast<uint8_t>((0xFFU << (8U - remBits)) & 0xFFU);
            }
            out.mask6[i] = maskByte;
            out.network6[i] = addr6.s6_addr[i] & maskByte;
        }
        return true;
    }

    return false;
}

const std::vector<std::string>& IpClassifier::defaultLanSubnets() {
    static const std::vector<std::string> defaults = {
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "fc00::/7"
    };
    return defaults;
}

IpClassifier::IpClassifier() : m_rawSubnets(defaultLanSubnets()) {
    rebuild();
}

void IpClassifier::rebuild() {
    m_parsedSubnets.clear();
    m_parsedSubnets.reserve(m_rawSubnets.size());
    for (const auto& raw : m_rawSubnets) {
        IpSubnet parsed;
        if (IpSubnet::parse(raw, parsed)) {
            m_parsedSubnets.push_back(parsed);
        } else if (!raw.empty()) {
            std::cerr << "[motel] Ignoring invalid LAN subnet in config: " << raw << "\n";
        }
    }
}

void IpClassifier::setSubnets(const std::vector<std::string>& subnets) {
    if (&subnets != &m_rawSubnets) {
        m_rawSubnets = subnets;
    }
    rebuild();
}

void IpClassifier::setSubnets(const std::string& commaSeparated) {
    std::vector<std::string> items;
    std::stringstream ss(commaSeparated);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token = trimAndUnquote(token);
        if (!token.empty()) {
            items.push_back(token);
        }
    }
    m_rawSubnets = std::move(items);
    rebuild();
}

bool IpClassifier::contains(const std::string& ip) const {
    if (ip.empty() || m_parsedSubnets.empty()) return false;

    if (ip.find(':') == std::string::npos) {
        struct in_addr addr4{};
        if (inet_pton(AF_INET, ip.c_str(), &addr4) != 1) return false;
        uint32_t hostIp = ntohl(addr4.s_addr);
        for (const auto& sub : m_parsedSubnets) {
            if (!sub.isIpv6 && (hostIp & sub.mask4) == sub.network4) {
                return true;
            }
        }
        return false;
    }

    struct in6_addr addr6{};
    if (inet_pton(AF_INET6, ip.c_str(), &addr6) != 1) return false;
    for (const auto& sub : m_parsedSubnets) {
        if (!sub.isIpv6) continue;
        bool match = true;
        for (size_t i = 0; i < 16; ++i) {
            if ((addr6.s6_addr[i] & sub.mask6[i]) != sub.network6[i]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

} // namespace Platform
