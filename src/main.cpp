#include "Config.h"
#include "otel/OtelDefaults.h"
#include "otel/OtelSender.h"
#include "otel/OtelMetrics.h"
#include "otel/OtelLogger.h"
#include "collectors/HostMetricsCollector.h"
#include "collectors/NetInterfaceCollector.h"
#include "collectors/BcmFlowCacheCollector.h"
#include "collectors/BcmArcherCollector.h"
#include "collectors/BcmWifiCollector.h"
#include "collectors/SyslogTailer.h"
#include "collectors/NetlinkConntrackCollector.h"

#include <iostream>
#include <vector>
#include <memory>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static std::atomic<bool> g_running{true};
static std::atomic<bool> g_reload{false};

static void signalHandler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_running = false;
    } else if (sig == SIGHUP) {
        g_reload = true;
    }
}

static void setupDaemon() {
    pid_t pid = fork();
    if (pid < 0) std::exit(1);
    if (pid > 0) std::exit(0); // Parent exits

    if (setsid() < 0) std::exit(1);

    pid = fork();
    if (pid < 0) std::exit(1);
    if (pid > 0) std::exit(0);

    umask(027);
    if (chdir("/") < 0) {}

    int devNull = open("/dev/null", O_RDWR);
    if (devNull >= 0) {
        dup2(devNull, STDIN_FILENO);
        dup2(devNull, STDOUT_FILENO);
        dup2(devNull, STDERR_FILENO);
        if (devNull > 2) close(devNull);
    }
}

int main(int argc, char* argv[]) {
    Config cfg = Config::parse(argc, argv);

    if (cfg.daemonize) {
        setupDaemon();
    }

    // Ignore SIGPIPE so closed HTTP sockets return EPIPE instead of killing the daemon
    struct sigaction saIgnore{};
    saIgnore.sa_handler = SIG_IGN;
    sigemptyset(&saIgnore.sa_mask);
    sigaction(SIGPIPE, &saIgnore, nullptr);

    // Register signal handlers
    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);

    // Record process start timestamp for OTLP cumulative counters
    (void)OTel::processStartUnixNano();

    // Initialize OTel Resources
    auto& res = OTel::defaultResource();
    res.serviceName = cfg.serviceName;
    res.serviceInstanceId = cfg.serviceInstanceId;
    res.hostName = cfg.hostName;
    for (const auto& kv : cfg.customAttributes) {
        res.set(kv.first, kv.second);
    }

    // Initialize Sender and OTel APIs
    OTel::OTelSender::init(cfg.endpoint, cfg.headers, cfg.queueCapacity, cfg.timeoutSec, cfg.verbose);
    OTel::Metrics::begin("merlin-router", MOTEL_VERSION);
    OTel::Logger::begin("merlin-router", MOTEL_VERSION);

    if (cfg.verbose) {
        std::cerr << "[motel] Starting merlin-otel-agent on " << cfg.hostName
                  << " -> " << cfg.endpoint << " (interval=" << cfg.scrapeIntervalSec << "s)\n";
    }

    // Initialize Collectors
    std::vector<std::unique_ptr<Collectors::Collector>> collectors;

    if (cfg.enableHost) {
        auto c = std::make_unique<Collectors::HostMetricsCollector>();
        if (c->init(cfg)) collectors.push_back(std::move(c));
    }
    if (cfg.enableNet) {
        auto c = std::make_unique<Collectors::NetInterfaceCollector>();
        if (c->init(cfg)) collectors.push_back(std::move(c));
    }
    if (cfg.enableFlowCache) {
        auto c = std::make_unique<Collectors::BcmFlowCacheCollector>();
        if (c->init(cfg)) collectors.push_back(std::move(c));
    }
    if (cfg.enableArcher) {
        auto c = std::make_unique<Collectors::BcmArcherCollector>();
        if (c->init(cfg)) collectors.push_back(std::move(c));
    }
    if (cfg.enableWifi) {
        auto c = std::make_unique<Collectors::BcmWifiCollector>();
        if (c->init(cfg)) collectors.push_back(std::move(c));
    }
    if (cfg.enableSyslog) {
        auto c = std::make_unique<Collectors::SyslogTailer>();
        if (c->init(cfg)) collectors.push_back(std::move(c));
    }
    if (cfg.enableNetlinkConntrack) {
        auto c = std::make_unique<Collectors::NetlinkConntrackCollector>();
        if (c->init(cfg)) collectors.push_back(std::move(c));
    }

    uint64_t lastFastTick = 0;
    uint64_t lastSlowTick = 0;

    // Emit initial daemon start log
    OTel::Logger::logInfo("merlin-otel-agent started", {{"version", MOTEL_VERSION}, {"platform", "bcm6765"}});

    while (g_running) {
        if (g_reload) {
            g_reload = false;
            if (cfg.loadFromFile(cfg.configFile)) {
                for (auto& col : collectors) {
                    col->reloadConfig(cfg);
                }
            }
        }

        uint64_t nowMs = OTel::monotonicMillis();

        // Check if fast tick is due
        if (nowMs - lastFastTick >= static_cast<uint64_t>(cfg.scrapeIntervalSec * 1000)) {
            lastFastTick = nowMs;

            OTel::Metrics::startBatch();
            OTel::Logger::startBatch();

            bool isSlowDue = (nowMs - lastSlowTick >= static_cast<uint64_t>(cfg.slowIntervalSec * 1000));
            if (isSlowDue) lastSlowTick = nowMs;

            for (auto& col : collectors) {
                col->collectFast();
                if (isSlowDue) col->collectSlow();
            }

            OTel::Metrics::flushBatch();
            OTel::Logger::flushBatch();
        }

        // Sleep 100ms in chunks so signal handling remains responsive
        usleep(100000);
    }

    OTel::Logger::logInfo("merlin-otel-agent stopping gracefully");
    OTel::Logger::flushBatch();
    OTel::Metrics::flushBatch();

    OTel::OTelSender::shutdown();

    if (cfg.verbose) {
        std::cerr << "[motel] Shutdown complete.\n";
    }

    return 0;
}
