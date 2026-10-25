#include "collectors/BcmArcherCollector.h"
#include "otel/OtelMetrics.h"
#include "platform/SubprocessRunner.h"
#include <fstream>
#include <sstream>

namespace Collectors {

bool BcmArcherCollector::init(const Config& /*cfg*/) {
    std::ifstream testFile("/proc/archer/stats");
    m_hasArcherProc = testFile.good();
    return true;
}

void BcmArcherCollector::collectFast() {
    if (m_hasArcherProc) {
        parseArcherProc();
    } else {
        auto res = Platform::SubprocessRunner::run({"archer", "stats"}, 500);
        if (res.success()) {
            parseArcherCliOutput(res.stdoutData);
        }
    }
    checkNvramAccelerationState();
}

void BcmArcherCollector::collectSlow() {}

void BcmArcherCollector::parseArcherProc(const std::string& path) {
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

        if (key.find("Rx Packets") != std::string::npos || key.find("rx_packets") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.archer.rx.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Tx Packets") != std::string::npos || key.find("tx_packets") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.archer.tx.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Dropped") != std::string::npos || key.find("rx_dropped") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.archer.rx.dropped", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Active Flows") != std::string::npos || key.find("hw_flows") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.archer.flows.hw_active", val, "{flows}");
        } else if (key.find("Errors") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.archer.hw_errors", val, true, OTel::Proto::Temporality::CUMULATIVE, "{errors}");
        }
    }
}

void BcmArcherCollector::parseArcherCliOutput(const std::string& output) {
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

        if (key.find("Rx Packets") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.archer.rx.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Tx Packets") != std::string::npos) {
            OTel::Metrics::sumInt("bcm.archer.tx.packets", val, true, OTel::Proto::Temporality::CUMULATIVE, "{packets}");
        } else if (key.find("Flows") != std::string::npos) {
            OTel::Metrics::gaugeInt("bcm.archer.flows.hw_active", val, "{flows}");
        }
    }
}

void BcmArcherCollector::checkNvramAccelerationState() {
    auto resFc = Platform::SubprocessRunner::run({"nvram", "get", "fc_disable"}, 200);
    auto resRunner = Platform::SubprocessRunner::run({"nvram", "get", "runner_disable"}, 200);

    bool fcDisabled = (resFc.success() && resFc.stdoutData.find('1') != std::string::npos);
    bool runnerDisabled = (resRunner.success() && resRunner.stdoutData.find('1') != std::string::npos);

    double isAccelerated = (!fcDisabled && !runnerDisabled) ? 1.0 : 0.0;
    OTel::Metrics::gauge("bcm.acceleration.hardware_enabled", isAccelerated, "1");
}

} // namespace Collectors
