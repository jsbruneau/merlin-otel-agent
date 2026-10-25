#pragma once

#include "Config.h"

namespace Collectors {

class Collector {
public:
    virtual ~Collector() = default;
    virtual const char* name() const = 0;
    virtual bool init(const Config& cfg) = 0;
    virtual void reloadConfig(const Config& /*cfg*/) {}
    virtual void collectFast() = 0;
    virtual void collectSlow() {}
};

} // namespace Collectors
