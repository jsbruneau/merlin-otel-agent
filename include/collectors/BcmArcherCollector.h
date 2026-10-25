#pragma once

#include "Collector.h"
#include <string>

namespace Collectors {

class BcmArcherCollector : public Collector {
public:
    const char* name() const override { return "bcm_archer"; }
    bool init(const Config& cfg) override;
    void collectFast() override;
    void collectSlow() override;

    // Testable parsers
    void parseArcherProc(const std::string& path = "/proc/archer/stats");
    void parseArcherCliOutput(const std::string& output);
    void checkNvramAccelerationState();

private:
    bool m_hasArcherProc = false;
};

} // namespace Collectors
