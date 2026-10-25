#include "collectors/BcmWifiCollector.h"
#include "otel/OtelMetrics.h"
#include "platform/StringUtils.h"
#include "platform/SubprocessRunner.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace Collectors {

std::string BcmWifiCollector::bandFromRadio(const std::string& radio) {
    if (radio.rfind("wl0", 0) == 0) return "2.4g";
    if (radio.rfind("wl1", 0) == 0) return "5g";
    if (radio.rfind("wl2", 0) == 0) return "6g";
    return "unknown";
}

bool BcmWifiCollector::isPhysicalRadio(const std::string& iface) {
    // Physical radios have no dot in their name (wl0, wl1, wl2), VIFs have dots (wl0.1, wl1.1, etc.)
    return iface.find('.') == std::string::npos;
}

bool BcmWifiCollector::isValidMacAddress(const std::string& mac) {
    if (mac.size() != 17) return false;
    for (size_t i = 0; i < 17; ++i) {
        if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            if (mac[i] != ':') return false;
        } else {
            if (!std::isxdigit(static_cast<unsigned char>(mac[i]))) return false;
        }
    }
    return true;
}

std::vector<std::string> BcmWifiCollector::discoverWifiInterfaces(const std::string& procNetDevPath) {
    std::vector<std::string> ifaces;
    std::ifstream file(procNetDevPath);
    if (file.is_open()) {
        std::string line;
        // Skip two header lines
        std::getline(file, line);
        std::getline(file, line);

        while (std::getline(file, line)) {
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;

            std::string iface = Platform::trimWhitespace(line.substr(0, colon));

            // Match Broadcom wireless interfaces: wl[0-9]+ or wl[0-9]+\.[0-9]+
            if (iface.size() >= 3 && iface[0] == 'w' && iface[1] == 'l' &&
                std::isdigit(static_cast<unsigned char>(iface[2]))) {
                bool valid = true;
                bool seenDot = false;
                for (size_t i = 2; i < iface.size(); ++i) {
                    if (std::isdigit(static_cast<unsigned char>(iface[i]))) {
                        continue;
                    } else if (iface[i] == '.' && !seenDot && i > 2 && i + 1 < iface.size()) {
                        seenDot = true;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    ifaces.push_back(iface);
                }
            }
        }
    }

    // Fallback if /proc/net/dev had no active wl interfaces (e.g. test environment)
    if (ifaces.empty()) {
        ifaces = {"wl0", "wl1", "wl2"};
    } else {
        std::sort(ifaces.begin(), ifaces.end());
        ifaces.erase(std::unique(ifaces.begin(), ifaces.end()), ifaces.end());
    }

    return ifaces;
}

bool BcmWifiCollector::init(const Config& /*cfg*/) {
    return true;
}

void BcmWifiCollector::collectFast() {
    auto allIfaces = discoverWifiInterfaces(m_procNetDevPath);

    // 1. Radio hardware PHY metrics: collected on physical primary radios only
    for (const auto& radio : allIfaces) {
        if (!isPhysicalRadio(radio)) continue;

        auto resNoise = Platform::SubprocessRunner::run({"wl", "-i", radio, "noise"}, 300);
        if (resNoise.success()) parseNoise(radio, resNoise.stdoutData);

        auto resChanim = Platform::SubprocessRunner::run({"wl", "-i", radio, "chanim_stats"}, 500);
        if (resChanim.success()) parseChanimStats(radio, resChanim.stdoutData);

        auto resTemp = Platform::SubprocessRunner::run({"wl", "-i", radio, "phy_tempsense"}, 300);
        if (resTemp.success()) parsePhyTemp(radio, resTemp.stdoutData);
    }

    // 2. Client association counts: collected on ALL interfaces (primary + VIFs like wl0.1, wl1.1, wl2.1)
    for (const auto& iface : allIfaces) {
        auto resAssoc = Platform::SubprocessRunner::run({"wl", "-i", iface, "assoclist"}, 300);
        if (resAssoc.success()) parseAssocList(iface, resAssoc.stdoutData);
    }
}

void BcmWifiCollector::collectSlow() {
    auto allIfaces = discoverWifiInterfaces(m_procNetDevPath);

    for (const auto& iface : allIfaces) {
        auto resAssoc = Platform::SubprocessRunner::run({"wl", "-i", iface, "assoclist"}, 500);
        if (!resAssoc.success()) continue;

        std::istringstream ss(resAssoc.stdoutData);
        std::string line;
        int staCount = 0;
        while (std::getline(ss, line) && staCount < 16) {
            std::istringstream lss(line);
            std::string prefix, mac;
            lss >> prefix >> mac;
            if (mac.empty() && !prefix.empty()) mac = prefix;
            if (isValidMacAddress(mac)) {
                auto resSta = Platform::SubprocessRunner::run({"wl", "-i", iface, "sta_info", mac}, 500);
                if (resSta.success()) {
                    parseStaInfo(iface, mac, resSta.stdoutData);
                    ++staCount;
                }
            }
        }
    }
}

void BcmWifiCollector::parseNoise(const std::string& radio, const std::string& output) {
    std::istringstream ss(output);
    int noiseDbm = 0;
    if (ss >> noiseDbm && noiseDbm < 0) {
        std::string band = bandFromRadio(radio);
        OTel::Metrics::gauge("bcm.wifi.noise_dbm", static_cast<double>(noiseDbm), "dBm", {{"radio", radio}, {"band", band}});
    }
}

void BcmWifiCollector::parseChanimStats(const std::string& radio, const std::string& output) {
    std::istringstream ss(output);
    std::string line;
    std::string band = bandFromRadio(radio);
    while (std::getline(ss, line)) {
        if (line.find("txop") != std::string::npos || line.find("glitch") != std::string::npos) {
            // Header line, read next line with values
            if (std::getline(ss, line)) {
                std::istringstream lss(line);
                std::string ch;
                int tx = 0, inbss = 0, obss = 0, nocat = 0, nopkt = 0, doze = 0, txop = 0;
                uint64_t bcnt = 0, glitch = 0, badplcp = 0;
                if (lss >> ch >> tx >> inbss >> obss >> nocat >> nopkt >> doze >> txop >> bcnt >> glitch >> badplcp) {
                    OTel::Metrics::gauge("bcm.wifi.channel.utilization_percent", static_cast<double>(txop),   "%", {{"radio", radio}, {"band", band}, {"type", "txop"}});
                    OTel::Metrics::gauge("bcm.wifi.channel.utilization_percent", static_cast<double>(inbss),  "%", {{"radio", radio}, {"band", band}, {"type", "inbss"}});
                    OTel::Metrics::gauge("bcm.wifi.channel.utilization_percent", static_cast<double>(obss),   "%", {{"radio", radio}, {"band", band}, {"type", "obss"}});
                    OTel::Metrics::gauge("bcm.wifi.channel.utilization_percent", static_cast<double>(nocat),  "%", {{"radio", radio}, {"band", band}, {"type", "nocat"}});
                    OTel::Metrics::sumInt("bcm.wifi.channel.glitches", static_cast<int64_t>(glitch), true, OTel::Proto::Temporality::CUMULATIVE, "{glitches}", {{"radio", radio}, {"band", band}});
                    OTel::Metrics::sumInt("bcm.wifi.channel.bad_plcp", static_cast<int64_t>(badplcp), true, OTel::Proto::Temporality::CUMULATIVE, "{errors}", {{"radio", radio}, {"band", band}});
                }
            }
            break;
        }
    }
}

void BcmWifiCollector::parseAssocList(const std::string& radio, const std::string& output) {
    std::istringstream ss(output);
    std::string line;
    int count = 0;
    while (std::getline(ss, line)) {
        std::istringstream lss(line);
        std::string t1, t2;
        lss >> t1 >> t2;
        const std::string& candidate = t2.empty() ? t1 : t2;
        if (isValidMacAddress(candidate)) {
            ++count;
        }
    }
    std::string band = bandFromRadio(radio);
    OTel::Metrics::gaugeInt("bcm.wifi.clients.associated", count, "{clients}", {{"radio", radio}, {"band", band}});
}

void BcmWifiCollector::parsePhyTemp(const std::string& radio, const std::string& output) {
    std::istringstream ss(output);
    int rawTemp = 0;
    if (ss >> rawTemp && rawTemp > 0) {
        double cel = (rawTemp > 100) ? (rawTemp / 2.0) : static_cast<double>(rawTemp);
        std::string band = bandFromRadio(radio);
        OTel::Metrics::gauge("bcm.wifi.temperature", cel, "Cel", {{"radio", radio}, {"band", band}});
    }
}

void BcmWifiCollector::parseStaInfo(const std::string& radio, const std::string& mac, const std::string& output) {
    std::istringstream ss(output);
    std::string line;
    std::string band = bandFromRadio(radio);
    bool emittedRssi = false;
    bool emittedRate = false;

    while (std::getline(ss, line)) {
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (!emittedRssi && lower.find("rssi") != std::string::npos) {
            size_t colon = line.find(':');
            std::string valPart;
            if (colon != std::string::npos) {
                valPart = line.substr(colon + 1);
            } else {
                std::istringstream kss(line);
                std::string k;
                kss >> k;
                std::getline(kss, valPart);
            }

            std::istringstream vss(valPart);
            std::string tok;
            bool foundValidRssi = false;
            int bestRssi = -999;
            while (vss >> tok) {
                int64_t val = 0;
                if (Platform::parseInt64(tok, val) && val <= -1 && val >= -120) {
                    if (!foundValidRssi || static_cast<int>(val) > bestRssi) {
                        bestRssi = static_cast<int>(val);
                        foundValidRssi = true;
                    }
                }
            }
            if (foundValidRssi) {
                OTel::Metrics::gauge("bcm.wifi.sta.rssi_dbm", static_cast<double>(bestRssi), "dBm",
                                     {{"radio", radio}, {"band", band}, {"mac", mac}});
                emittedRssi = true;
            }
        } else if (!emittedRate &&
                   lower.find("rateset") == std::string::npos &&
                   (lower.find("rate of last tx") != std::string::npos ||
                    lower.find("tx_rate") != std::string::npos ||
                    (lower.find("rate") != std::string::npos && lower.find("rx") == std::string::npos))) {
            size_t colon = line.find(':');
            std::string valPart;
            if (colon != std::string::npos) {
                valPart = line.substr(colon + 1);
            } else {
                std::istringstream kss(line);
                std::string k;
                kss >> k;
                std::getline(kss, valPart);
            }

            std::istringstream vss(valPart);
            double rate = 0.0;
            if (vss >> rate && rate > 0.0) {
                if (lower.find("kbps") != std::string::npos) {
                    rate /= 1000.0;
                }
                OTel::Metrics::gauge("bcm.wifi.sta.rate_mbps", rate, "Mbit/s",
                                     {{"radio", radio}, {"band", band}, {"mac", mac}});
                emittedRate = true;
            }
        }
    }
}

} // namespace Collectors
