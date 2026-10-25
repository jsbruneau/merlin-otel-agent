#pragma once

#include <string>
#include <vector>

namespace Platform {

struct SubprocessResult {
    int exitCode = -1;
    std::string stdoutData;
    std::string stderrData;
    bool timedOut = false;

    bool success() const { return exitCode == 0 && !timedOut; }
};

class SubprocessRunner {
public:
    // Executes argv[0] directly without /bin/sh using trusted binary resolution.
    static SubprocessResult run(const std::vector<std::string>& argv, int timeoutMs = 1000);
};

} // namespace Platform
