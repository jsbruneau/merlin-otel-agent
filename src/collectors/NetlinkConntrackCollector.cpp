#include "collectors/NetlinkConntrackCollector.h"
#include "otel/OtelMetrics.h"

#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <endian.h>
#include <fcntl.h>
#include <fstream>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef NLA_OK
#define NLA_OK(nla, len) ((len) >= sizeof(struct nlattr) && \
                          (nla)->nla_len >= sizeof(struct nlattr) && \
                          static_cast<size_t>((nla)->nla_len) <= (len))
#endif

#ifndef NLA_DATA
#define NLA_DATA(nla) (reinterpret_cast<const void*>(reinterpret_cast<const char*>(nla) + NLA_HDRLEN))
#endif

#ifndef NLA_PAYLOAD
#define NLA_PAYLOAD(nla) (static_cast<size_t>((nla)->nla_len - NLA_HDRLEN))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla, len) ( \
    (len) = ((len) >= static_cast<size_t>(NLA_ALIGN((nla)->nla_len))) ? ((len) - static_cast<size_t>(NLA_ALIGN((nla)->nla_len))) : 0, \
    reinterpret_cast<const struct nlattr*>(reinterpret_cast<const char*>(nla) + NLA_ALIGN((nla)->nla_len)) \
)
#endif

namespace Collectors {

NetlinkConntrackCollector::~NetlinkConntrackCollector() {
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
}

std::string NetlinkConntrackCollector::normalizePort(uint16_t dport, const std::string& /*proto*/) {
    switch (dport) {
        case 53:    return "53/dns";
        case 80:    return "80/http";
        case 443:   return "443/https";
        case 853:   return "853/dot";
        case 22:    return "22/ssh";
        case 123:   return "123/ntp";
        case 445:   return "445/smb";
        case 1194:  return "1194/openvpn";
        case 1935:  return "1935/rtmp";
        case 3074:  return "3074/gaming-xbox";
        case 3478:  return "3478/stun";
        case 8080:  return "8080/http-alt";
        case 8443:  return "8443/https-alt";
        case 27015: return "27015/steam";
        case 51820: return "51820/wireguard";
        default: break;
    }

    if (dport < 1024) {
        return std::to_string(dport);
    }
    return "high_ports";
}

void NetlinkConntrackCollector::applyConfig(const Config& cfg) {
    m_lanClassifier = cfg.lanClassifier;
    m_maxFlows = cfg.maxConntrackFlows > 0 ? cfg.maxConntrackFlows : 1;
}

void NetlinkConntrackCollector::reloadConfig(const Config& cfg) {
    applyConfig(cfg);
}

void NetlinkConntrackCollector::enableConntrackAccounting() {
    std::ofstream file("/proc/sys/net/netfilter/nf_conntrack_acct");
    if (file.is_open()) {
        file << "1\n";
    }
}

bool NetlinkConntrackCollector::openNetlinkSocket() {
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }

    m_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (m_fd < 0) return false;

    // Buffer to handle connection bursts without drop
    int rcvbuf = 256 * 1024;
    setsockopt(m_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    // NFNLGRP_CONNTRACK_DESTROY group bitmask
    sa.nl_groups = (1U << (NFNLGRP_CONNTRACK_DESTROY - 1));

    if (bind(m_fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) {
        close(m_fd);
        m_fd = -1;
        return false;
    }
    return true;
}

bool NetlinkConntrackCollector::init(const Config& cfg) {
    applyConfig(cfg);
    enableConntrackAccounting();
    return openNetlinkSocket();
}

void NetlinkConntrackCollector::collectFast() {
    drainSocket();

    // Export cumulative metrics aggregated by (client_ip, protocol, dest_port)
    for (const auto& kv : m_flowTotals) {
        const auto& key = kv.first;
        const auto& c = kv.second;

        std::map<std::string, std::string> txLabels = {
            {"client_ip", key.clientIp},
            {"protocol", key.protocol},
            {"dest_port", key.destPort},
            {"direction", "transmit"}
        };
        std::map<std::string, std::string> rxLabels = {
            {"client_ip", key.clientIp},
            {"protocol", key.protocol},
            {"dest_port", key.destPort},
            {"direction", "receive"}
        };

        OTel::Metrics::sumInt("bcm.traffic.completed.bytes", static_cast<int64_t>(c.txBytes), true, OTel::Proto::Temporality::CUMULATIVE, "By", txLabels);
        OTel::Metrics::sumInt("bcm.traffic.completed.bytes", static_cast<int64_t>(c.rxBytes), true, OTel::Proto::Temporality::CUMULATIVE, "By", rxLabels);

        OTel::Metrics::sumInt("bcm.traffic.completed.packets", static_cast<int64_t>(c.txPackets), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", txLabels);
        OTel::Metrics::sumInt("bcm.traffic.completed.packets", static_cast<int64_t>(c.rxPackets), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", rxLabels);
    }
}

void NetlinkConntrackCollector::drainSocket() {
    if (m_fd < 0) return;

    std::array<uint8_t, 8192> buf{};
    int maxMessages = 200; // Cap per tick to prevent starvation

    while (maxMessages-- > 0) {
        ssize_t len = recv(m_fd, buf.data(), buf.size(), MSG_DONTWAIT);
        if (len <= 0) break;
        parseNetlinkMessage(buf.data(), static_cast<size_t>(len));
    }
}

void NetlinkConntrackCollector::recordCompletedFlow(const std::string& srcIp,
                                                    const std::string& dstIp,
                                                    const std::string& proto,
                                                    uint16_t srcPort,
                                                    uint16_t dstPort,
                                                    uint64_t txBytes,
                                                    uint64_t rxBytes,
                                                    uint64_t txPackets,
                                                    uint64_t rxPackets) {
    std::string clientIp;
    uint16_t servicePort = 0;

    if (m_lanClassifier.contains(srcIp)) {
        clientIp = srcIp;
        servicePort = dstPort;
    } else if (m_lanClassifier.contains(dstIp)) {
        clientIp = dstIp;
        servicePort = srcPort; // Inbound connection into LAN
    }

    if (clientIp.empty()) return;

    FlowKey key{clientIp, proto, normalizePort(servicePort, proto)};
    auto it = m_flowTotals.find(key);
    if (it == m_flowTotals.end() && m_flowTotals.size() >= m_maxFlows) {
        // Bound cardinality against port scans or IPv6 privacy address rotation
        key = FlowKey{"other", proto, "overflow"};
    }

    auto& entry = m_flowTotals[key];
    entry.txBytes += txBytes;
    entry.rxBytes += rxBytes;
    entry.txPackets += txPackets;
    entry.rxPackets += rxPackets;
}

bool NetlinkConntrackCollector::parseNetlinkMessage(const uint8_t* data, size_t len) {
    if (!data || len < sizeof(struct nlmsghdr)) return false;

    const auto* nlh = reinterpret_cast<const struct nlmsghdr*>(data);
    while (NLMSG_OK(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) break;

        size_t msgLen = NLMSG_PAYLOAD(nlh, 0);
        if (msgLen < sizeof(struct nfgenmsg)) {
            nlh = NLMSG_NEXT(nlh, len);
            continue;
        }

        const auto* attrsData = reinterpret_cast<const uint8_t*>(NLMSG_DATA(nlh)) + sizeof(struct nfgenmsg);
        size_t attrsLen = msgLen - sizeof(struct nfgenmsg);

        std::string srcIp, dstIp;
        std::string protoStr = "tcp";
        uint16_t srcPort = 0, dstPort = 0;
        uint64_t txBytes = 0, rxBytes = 0, txPackets = 0, rxPackets = 0;

        // Iterate top-level attributes
        const auto* nla = reinterpret_cast<const struct nlattr*>(attrsData);
        while (NLA_OK(nla, attrsLen)) {
            uint16_t attrType = nla->nla_type & NLA_TYPE_MASK;

            if (attrType == CTA_TUPLE_ORIG) {
                // Parse nested CTA_TUPLE_ORIG
                size_t tupleLen = NLA_PAYLOAD(nla);
                const auto* tupleAttr = reinterpret_cast<const struct nlattr*>(NLA_DATA(nla));
                while (NLA_OK(tupleAttr, tupleLen)) {
                    uint16_t tType = tupleAttr->nla_type & NLA_TYPE_MASK;

                    if (tType == CTA_TUPLE_IP) {
                        size_t ipLen = NLA_PAYLOAD(tupleAttr);
                        const auto* ipAttr = reinterpret_cast<const struct nlattr*>(NLA_DATA(tupleAttr));
                        while (NLA_OK(ipAttr, ipLen)) {
                            uint16_t iType = ipAttr->nla_type & NLA_TYPE_MASK;
                            if (iType == CTA_IP_V4_SRC && NLA_PAYLOAD(ipAttr) >= 4) {
                                std::array<char, INET_ADDRSTRLEN> ipBuf{};
                                if (inet_ntop(AF_INET, NLA_DATA(ipAttr), ipBuf.data(), ipBuf.size())) srcIp = ipBuf.data();
                            } else if (iType == CTA_IP_V4_DST && NLA_PAYLOAD(ipAttr) >= 4) {
                                std::array<char, INET_ADDRSTRLEN> ipBuf{};
                                if (inet_ntop(AF_INET, NLA_DATA(ipAttr), ipBuf.data(), ipBuf.size())) dstIp = ipBuf.data();
                            } else if (iType == CTA_IP_V6_SRC && NLA_PAYLOAD(ipAttr) >= 16) {
                                std::array<char, INET6_ADDRSTRLEN> ipBuf{};
                                if (inet_ntop(AF_INET6, NLA_DATA(ipAttr), ipBuf.data(), ipBuf.size())) srcIp = ipBuf.data();
                            } else if (iType == CTA_IP_V6_DST && NLA_PAYLOAD(ipAttr) >= 16) {
                                std::array<char, INET6_ADDRSTRLEN> ipBuf{};
                                if (inet_ntop(AF_INET6, NLA_DATA(ipAttr), ipBuf.data(), ipBuf.size())) dstIp = ipBuf.data();
                            }
                            ipAttr = NLA_NEXT(ipAttr, ipLen);
                        }
                    } else if (tType == CTA_TUPLE_PROTO) {
                        size_t prLen = NLA_PAYLOAD(tupleAttr);
                        const auto* prAttr = reinterpret_cast<const struct nlattr*>(NLA_DATA(tupleAttr));
                        while (NLA_OK(prAttr, prLen)) {
                            uint16_t pType = prAttr->nla_type & NLA_TYPE_MASK;
                            if (pType == CTA_PROTO_NUM && NLA_PAYLOAD(prAttr) >= 1) {
                                uint8_t protoNum = *reinterpret_cast<const uint8_t*>(NLA_DATA(prAttr));
                                if (protoNum == 6) protoStr = "tcp";
                                else if (protoNum == 17) protoStr = "udp";
                                else if (protoNum == 1) protoStr = "icmp";
                                else protoStr = std::to_string(protoNum);
                            } else if (pType == CTA_PROTO_SRC_PORT && NLA_PAYLOAD(prAttr) >= 2) {
                                uint16_t rawPort = 0;
                                std::memcpy(&rawPort, NLA_DATA(prAttr), sizeof(rawPort));
                                srcPort = be16toh(rawPort);
                            } else if (pType == CTA_PROTO_DST_PORT && NLA_PAYLOAD(prAttr) >= 2) {
                                uint16_t rawPort = 0;
                                std::memcpy(&rawPort, NLA_DATA(prAttr), sizeof(rawPort));
                                dstPort = be16toh(rawPort);
                            }
                            prAttr = NLA_NEXT(prAttr, prLen);
                        }
                    }
                    tupleAttr = NLA_NEXT(tupleAttr, tupleLen);
                }
            } else if (attrType == CTA_COUNTERS_ORIG) {
                // Outbound counters (Tx)
                size_t cntLen = NLA_PAYLOAD(nla);
                const auto* cntAttr = reinterpret_cast<const struct nlattr*>(NLA_DATA(nla));
                while (NLA_OK(cntAttr, cntLen)) {
                    uint16_t cType = cntAttr->nla_type & NLA_TYPE_MASK;
                    if (cType == CTA_COUNTERS_BYTES && NLA_PAYLOAD(cntAttr) >= 8) {
                        uint64_t rawVal = 0;
                        std::memcpy(&rawVal, NLA_DATA(cntAttr), sizeof(rawVal));
                        txBytes = be64toh(rawVal);
                    } else if (cType == CTA_COUNTERS_PACKETS && NLA_PAYLOAD(cntAttr) >= 8) {
                        uint64_t rawVal = 0;
                        std::memcpy(&rawVal, NLA_DATA(cntAttr), sizeof(rawVal));
                        txPackets = be64toh(rawVal);
                    }
                    cntAttr = NLA_NEXT(cntAttr, cntLen);
                }
            } else if (attrType == CTA_COUNTERS_REPLY) {
                // Inbound counters (Rx)
                size_t cntLen = NLA_PAYLOAD(nla);
                const auto* cntAttr = reinterpret_cast<const struct nlattr*>(NLA_DATA(nla));
                while (NLA_OK(cntAttr, cntLen)) {
                    uint16_t cType = cntAttr->nla_type & NLA_TYPE_MASK;
                    if (cType == CTA_COUNTERS_BYTES && NLA_PAYLOAD(cntAttr) >= 8) {
                        uint64_t rawVal = 0;
                        std::memcpy(&rawVal, NLA_DATA(cntAttr), sizeof(rawVal));
                        rxBytes = be64toh(rawVal);
                    } else if (cType == CTA_COUNTERS_PACKETS && NLA_PAYLOAD(cntAttr) >= 8) {
                        uint64_t rawVal = 0;
                        std::memcpy(&rawVal, NLA_DATA(cntAttr), sizeof(rawVal));
                        rxPackets = be64toh(rawVal);
                    }
                    cntAttr = NLA_NEXT(cntAttr, cntLen);
                }
            }
            nla = NLA_NEXT(nla, attrsLen);
        }

        recordCompletedFlow(srcIp, dstIp, protoStr, srcPort, dstPort, txBytes, rxBytes, txPackets, rxPackets);

        nlh = NLMSG_NEXT(nlh, len);
    }
    return true;
}

} // namespace Collectors
