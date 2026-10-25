#include "collectors/NetInterfaceCollector.h"
#include "otel/OtelMetrics.h"
#include "platform/StringUtils.h"
#include "platform/SubprocessRunner.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace Collectors {

static bool isSafeIfaceName(const std::string& iface) {
    if (iface.empty() || iface.size() >= IFNAMSIZ) return false;
    for (unsigned char c : iface) {
        if (!std::isalnum(c) && c != '.' && c != '_' && c != '-') {
            return false;
        }
    }
    return true;
}

std::vector<std::string> NetInterfaceCollector::discoverInterfaces(const std::string& procNetDevPath) {
    std::vector<std::string> ifaces;
    std::ifstream file(procNetDevPath);
    if (file.is_open()) {
        std::string line;
        std::getline(file, line);
        std::getline(file, line);

        while (std::getline(file, line)) {
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;

            std::string iface = Platform::trimWhitespace(line.substr(0, colon));
            if (!isSafeIfaceName(iface) || iface == "lo") continue;

            if (iface.rfind("eth", 0) == 0 ||
                iface.rfind("br", 0) == 0 ||
                iface.rfind("wl", 0) == 0) {
                ifaces.push_back(iface);
            }
        }
    }

    if (ifaces.empty()) {
        ifaces = {"eth0", "eth1", "eth2", "eth3", "eth4", "br0", "wl0", "wl1", "wl2"};
    } else {
        std::sort(ifaces.begin(), ifaces.end());
        ifaces.erase(std::unique(ifaces.begin(), ifaces.end()), ifaces.end());
    }

    return ifaces;
}

bool NetInterfaceCollector::init(const Config& /*cfg*/) {
    m_monitoredIfaces = discoverInterfaces();
    return true;
}

void NetInterfaceCollector::collectFast() {
    m_monitoredIfaces = discoverInterfaces();
    parseProcNetDev();
    parseSysClassNet();

    // Collect physical MAC MIB stats on physical Ethernet ports (eth0, eth1, ..., excluding VLAN subinterfaces)
    for (const auto& iface : m_monitoredIfaces) {
        if (iface.rfind("eth", 0) == 0 && iface.find('.') == std::string::npos) {
            collectEthtoolStats(iface);
        }
    }
}

void NetInterfaceCollector::collectSlow() {}

void NetInterfaceCollector::parseProcNetDev(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    // Skip two header lines
    std::getline(file, line);
    std::getline(file, line);

    while (std::getline(file, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string iface = Platform::trimWhitespace(line.substr(0, colon));
        if (!isSafeIfaceName(iface)) continue;

        std::istringstream ss(line.substr(colon + 1));
        uint64_t rxBytes = 0, rxPackets = 0, rxErrs = 0, rxDrop = 0, rxFifo = 0, rxFrame = 0, rxCompressed = 0, rxMulticast = 0;
        uint64_t txBytes = 0, txPackets = 0, txErrs = 0, txDrop = 0, txFifo = 0, txColls = 0, txCarrier = 0, txCompressed = 0;

        if (ss >> rxBytes >> rxPackets >> rxErrs >> rxDrop >> rxFifo >> rxFrame >> rxCompressed >> rxMulticast
               >> txBytes >> txPackets >> txErrs >> txDrop >> txFifo >> txColls >> txCarrier >> txCompressed) {

            OTel::Metrics::sumInt("system.network.io", static_cast<int64_t>(rxBytes), true, OTel::Proto::Temporality::CUMULATIVE, "By", {{"device", iface}, {"direction", "receive"}});
            OTel::Metrics::sumInt("system.network.io", static_cast<int64_t>(txBytes), true, OTel::Proto::Temporality::CUMULATIVE, "By", {{"device", iface}, {"direction", "transmit"}});

            OTel::Metrics::sumInt("system.network.packets", static_cast<int64_t>(rxPackets), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "receive"}});
            OTel::Metrics::sumInt("system.network.packets", static_cast<int64_t>(txPackets), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "transmit"}});

            OTel::Metrics::sumInt("system.network.errors", static_cast<int64_t>(rxErrs), true, OTel::Proto::Temporality::CUMULATIVE, "{errors}", {{"device", iface}, {"direction", "receive"}});
            OTel::Metrics::sumInt("system.network.errors", static_cast<int64_t>(txErrs), true, OTel::Proto::Temporality::CUMULATIVE, "{errors}", {{"device", iface}, {"direction", "transmit"}});

            OTel::Metrics::sumInt("system.network.dropped", static_cast<int64_t>(rxDrop), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "receive"}});
            OTel::Metrics::sumInt("system.network.dropped", static_cast<int64_t>(txDrop), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "transmit"}});
        }
    }
}

void NetInterfaceCollector::parseSysClassNet(const std::string& basePath) {
    if (m_monitoredIfaces.empty()) {
        m_monitoredIfaces = discoverInterfaces();
    }

    for (const auto& iface : m_monitoredIfaces) {
        std::string speedPath = basePath + "/" + iface + "/speed";
        std::string operPath  = basePath + "/" + iface + "/operstate";

        std::ifstream operFile(operPath);
        if (operFile.is_open()) {
            std::string state;
            operFile >> state;
            double isUp = (state == "up") ? 1.0 : 0.0;
            OTel::Metrics::gauge("system.network.status", isUp, "1", {{"device", iface}, {"operstate", state}});
        }

        std::ifstream speedFile(speedPath);
        if (speedFile.is_open()) {
            int64_t speedMbps = 0;
            if (speedFile >> speedMbps && speedMbps > 0) {
                int64_t speedBits = speedMbps * 1000000LL;
                OTel::Metrics::gaugeInt("system.network.speed", speedBits, "bit/s", {{"device", iface}});
            }
        }
    }
}

void NetInterfaceCollector::collectEthtoolStats(const std::string& iface) {
    if (!isSafeIfaceName(iface)) return;

    bool ioctlSuccess = false;

    if (m_useEthtoolIoctl) {
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd >= 0) {
            struct ifreq ifr{};
            size_t copyLen = std::min(iface.size(), static_cast<size_t>(IFNAMSIZ - 1));
            std::copy_n(iface.c_str(), copyLen, ifr.ifr_name);
            ifr.ifr_name[copyLen] = '\0';

            struct ethtool_drvinfo drvinfo{};
            drvinfo.cmd = ETHTOOL_GDRVINFO;
            ifr.ifr_data = reinterpret_cast<char*>(&drvinfo);

            if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0 && drvinfo.n_stats > 0 && drvinfo.n_stats <= 4096) {
                size_t nStats = drvinfo.n_stats;
                size_t gstringsLen = sizeof(struct ethtool_gstrings) + nStats * ETH_GSTRING_LEN;
                std::vector<uint8_t> gstringsBuf(gstringsLen);
                auto* gstrings = reinterpret_cast<struct ethtool_gstrings*>(gstringsBuf.data());
                gstrings->cmd = ETHTOOL_GSTRINGS;
                gstrings->string_set = ETH_SS_STATS;
                gstrings->len = nStats;
                ifr.ifr_data = reinterpret_cast<char*>(gstrings);

                if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
                    size_t statsLen = sizeof(struct ethtool_stats) + nStats * sizeof(uint64_t);
                    std::vector<uint8_t> statsBuf(statsLen);
                    auto* stats = reinterpret_cast<struct ethtool_stats*>(statsBuf.data());
                    stats->cmd = ETHTOOL_GSTATS;
                    stats->n_stats = nStats;
                    ifr.ifr_data = reinterpret_cast<char*>(stats);

                    if (ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
                        ioctlSuccess = true;
                        for (size_t i = 0; i < nStats; ++i) {
                            const char* rawName = reinterpret_cast<const char*>(&gstrings->data[i * ETH_GSTRING_LEN]);
                            std::string statName(rawName, strnlen(rawName, ETH_GSTRING_LEN));
                            uint64_t val = stats->data[i];

                            if (statName.find("rx_bytes") != std::string::npos || statName.find("RxOctetsOK") != std::string::npos || statName.find("rx_octets") != std::string::npos) {
                                OTel::Metrics::sumInt("bcm.hw.network.io", static_cast<int64_t>(val), true, OTel::Proto::Temporality::CUMULATIVE, "By", {{"device", iface}, {"direction", "receive"}, {"tier", "switch_mac"}});
                            } else if (statName.find("tx_bytes") != std::string::npos || statName.find("TxOctetsOK") != std::string::npos || statName.find("tx_octets") != std::string::npos) {
                                OTel::Metrics::sumInt("bcm.hw.network.io", static_cast<int64_t>(val), true, OTel::Proto::Temporality::CUMULATIVE, "By", {{"device", iface}, {"direction", "transmit"}, {"tier", "switch_mac"}});
                            } else if (statName.find("rx_packets") != std::string::npos || statName.find("RxUnicastPkts") != std::string::npos || statName.find("rx_ucast") != std::string::npos) {
                                OTel::Metrics::sumInt("bcm.hw.network.packets", static_cast<int64_t>(val), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "receive"}, {"tier", "switch_mac"}});
                            } else if (statName.find("tx_packets") != std::string::npos || statName.find("TxUnicastPkts") != std::string::npos || statName.find("tx_ucast") != std::string::npos) {
                                OTel::Metrics::sumInt("bcm.hw.network.packets", static_cast<int64_t>(val), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "transmit"}, {"tier", "switch_mac"}});
                            } else if (statName.find("RxCRCAlignErrors") != std::string::npos || statName.find("rx_crc_errors") != std::string::npos) {
                                OTel::Metrics::sumInt("bcm.hw.network.errors", static_cast<int64_t>(val), true, OTel::Proto::Temporality::CUMULATIVE, "{errors}", {{"device", iface}, {"direction", "receive"}, {"tier", "switch_mac"}});
                            } else if (statName.find("TxDropPkts") != std::string::npos || statName.find("tx_drop") != std::string::npos) {
                                OTel::Metrics::sumInt("bcm.hw.network.dropped", static_cast<int64_t>(val), true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "transmit"}, {"tier", "switch_mac"}});
                            }
                        }
                    }
                }
            }
            close(fd);
        }
    }

    // Fall back to ethctl <iface> stats if SIOCETHTOOL failed
    if (!ioctlSuccess) {
        auto res = Platform::SubprocessRunner::run({"ethctl", iface, "stats"}, 500);
        if (res.success()) {
            parseEthctlOutput(iface, res.stdoutData);
        }
    }
}

void NetInterfaceCollector::parseEthctlOutput(const std::string& iface, const std::string& output) {
    std::istringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = Platform::trimWhitespace(line.substr(0, colon));
        std::string valStr = line.substr(colon + 1);

        std::istringstream vss(valStr);
        int64_t val = 0;
        if (!(vss >> val)) continue;

        if (key.find("RxOctets") != std::string::npos || key.find("rx_bytes") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.hw.network.io", val, true, OTel::Proto::Temporality::CUMULATIVE, "By", {{"device", iface}, {"direction", "receive"}, {"tier", "switch_mac"}});
        } else if (key.find("TxOctets") != std::string::npos || key.find("tx_bytes") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.hw.network.io", val, true, OTel::Proto::Temporality::CUMULATIVE, "By", {{"device", iface}, {"direction", "transmit"}, {"tier", "switch_mac"}});
        } else if (key.find("RxPkts") != std::string::npos || key.find("RxUnicast") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.hw.network.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "receive"}, {"tier", "switch_mac"}});
        } else if (key.find("TxPkts") != std::string::npos || key.find("TxUnicast") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.hw.network.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}", {{"device", iface}, {"direction", "transmit"}, {"tier", "switch_mac"}});
        }
    }
}

} // namespace Collectors
