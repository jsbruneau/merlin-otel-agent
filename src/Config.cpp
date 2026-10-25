#include "Config.h"
#include "platform/StringUtils.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>

static bool parseBoolValue(const std::string& val) {
    return (val == "1" || val == "true" || val == "TRUE" || val == "yes" || val == "on");
}

static void parseConfigInt(const std::string& key, const std::string& raw, int& target) {
    int64_t parsed = 0;
    if (Platform::parseInt64(raw, parsed) && parsed >= -2147483647LL && parsed <= 2147483647LL) {
        target = static_cast<int>(parsed);
    } else {
        std::cerr << "[motel] Invalid integer for '" << key << "': " << raw << " (keeping " << target << ")\n";
    }
}

static void parseConfigSize(const std::string& key, const std::string& raw, size_t& target) {
    uint64_t parsed = 0;
    if (Platform::parseUint64(raw, parsed)) {
        target = static_cast<size_t>(parsed);
    } else {
        std::cerr << "[motel] Invalid unsigned integer for '" << key << "': " << raw << " (keeping " << target << ")\n";
    }
}

static void parseConfigDouble(const std::string& key, const std::string& raw, double& target) {
    double parsed = 0.0;
    if (Platform::parseDouble(raw, parsed)) {
        target = parsed;
    } else {
        std::cerr << "[motel] Invalid number for '" << key << "': " << raw << " (keeping " << target << ")\n";
    }
}

void Config::clampBounds() {
    scrapeIntervalSec = std::clamp(scrapeIntervalSec, 1, 86400);
    slowIntervalSec = std::max(scrapeIntervalSec, std::min(slowIntervalSec, 86400));
    timeoutSec = std::clamp(timeoutSec, 1, 120);
    queueCapacity = std::clamp<size_t>(queueCapacity, 4, 4096);
    topClientFlows = std::clamp<size_t>(topClientFlows, 1, 1024);
    maxConntrackFlows = std::clamp<size_t>(maxConntrackFlows, 16, 16384);
    syslogRateLimit = std::max(0.0, syslogRateLimit);
    syslogBurstLimit = std::max(1.0, syslogBurstLimit);
}

bool Config::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        line = Platform::trimWhitespace(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = Platform::trimAndUnquote(line.substr(0, eq));
        std::string val = Platform::trimAndUnquote(line.substr(eq + 1));

        if (key == "endpoint") endpoint = val;
        else if (key == "headers") headers = val;
        else if (key == "service_name") serviceName = val;
        else if (key == "service_instance_id") serviceInstanceId = val;
        else if (key == "host_name") hostName = val;
        else if (key == "scrape_interval_sec") parseConfigInt(key, val, scrapeIntervalSec);
        else if (key == "slow_interval_sec") parseConfigInt(key, val, slowIntervalSec);
        else if (key == "syslog_file") syslogFile = val;
        else if (key == "syslog_from_beginning") syslogFromBeginning = parseBoolValue(val);
        else if (key == "syslog_rate_limit") parseConfigDouble(key, val, syslogRateLimit);
        else if (key == "syslog_burst_limit") parseConfigDouble(key, val, syslogBurstLimit);
        else if (key == "enable_host") enableHost = parseBoolValue(val);
        else if (key == "enable_net") enableNet = parseBoolValue(val);
        else if (key == "enable_flowcache") enableFlowCache = parseBoolValue(val);
        else if (key == "enable_archer") enableArcher = parseBoolValue(val);
        else if (key == "enable_wifi") enableWifi = parseBoolValue(val);
        else if (key == "enable_syslog") enableSyslog = parseBoolValue(val);
        else if (key == "enable_conntrack_events" || key == "enable_netlink_conntrack") enableNetlinkConntrack = parseBoolValue(val);
        else if (key == "lan_subnets" || key == "lan_ip_ranges") setLanSubnets(val);
        else if (key == "top_client_flows") parseConfigSize(key, val, topClientFlows);
        else if (key == "max_conntrack_flows") parseConfigSize(key, val, maxConntrackFlows);
        else if (key == "timeout_sec") parseConfigInt(key, val, timeoutSec);
        else if (key == "queue_capacity") parseConfigSize(key, val, queueCapacity);
        else if (key == "daemonize") daemonize = parseBoolValue(val);
        else if (key == "verbose") verbose = parseBoolValue(val);
        else customAttributes[key] = val;
    }

    clampBounds();
    return true;
}

Config Config::parse(int argc, char* argv[]) {
    Config cfg;

    const char* envEndpoint = std::getenv("OTEL_EXPORTER_OTLP_ENDPOINT");
    if (envEndpoint) cfg.endpoint = envEndpoint;

    const char* envHeaders = std::getenv("OTEL_EXPORTER_OTLP_HEADERS");
    if (envHeaders) cfg.headers = envHeaders;

    const char* envSvc = std::getenv("OTEL_SERVICE_NAME");
    if (envSvc) cfg.serviceName = envSvc;

    const char* envCt = std::getenv("MOTEL_ENABLE_CONNTRACK_EVENTS");
    if (envCt) cfg.enableNetlinkConntrack = parseBoolValue(envCt);

    const char* envLan = std::getenv("MOTEL_LAN_SUBNETS");
    if (envLan) cfg.setLanSubnets(envLan);

    // First pass: capture --config and handle --help
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) cfg.configFile = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: merlin-otel-agent [OPTIONS]\n"
                      << "Options:\n"
                      << "  -c, --config FILE            Path to configuration file\n"
                      << "  -e, --endpoint URL           OTLP/HTTP endpoint (default: http://127.0.0.1:4318)\n"
                      << "  -H, --headers HEADERS        Comma-separated headers (e.g. key1=val1,key2=val2)\n"
                      << "  -i, --interval SEC           Metrics scrape interval in seconds (default: 15)\n"
                      << "  -s, --syslog-file FILE       Path to syslog file (default: /tmp/syslog.log)\n"
                      << "      --lan-subnets LIST       Comma-separated LAN CIDRs (default: 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,fc00::/7)\n"
                      << "      --max-conntrack-flows N  Max unique completed flow keys tracked in memory (default: 512)\n"
                      << "      --syslog-from-beginning  Ingest from start of file instead of tail\n"
                      << "      --enable-conntrack-events    Enable in-process Netlink connection tracking (default)\n"
                      << "      --disable-conntrack-events   Disable in-process Netlink connection tracking\n"
                      << "  -d, --daemon                 Run in background as daemon\n"
                      << "  -v, --verbose                Enable verbose stderr logging\n"
                      << "  -h, --help                   Show this help message\n";
            std::exit(0);
        } else if (arg == "-e" || arg == "--endpoint" ||
                   arg == "-H" || arg == "--headers" ||
                   arg == "-i" || arg == "--interval" ||
                   arg == "-s" || arg == "--syslog-file" ||
                   arg == "--lan-subnets" || arg == "--max-conntrack-flows") {
            if (i + 1 < argc) ++i;
        }
    }

    // Load config file if present
    cfg.loadFromFile(cfg.configFile);

    // Second pass: apply CLI overrides on top of config file
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) ++i;
        } else if (arg == "-e" || arg == "--endpoint") {
            if (i + 1 < argc) cfg.endpoint = argv[++i];
        } else if (arg == "-H" || arg == "--headers") {
            if (i + 1 < argc) cfg.headers = argv[++i];
        } else if (arg == "-i" || arg == "--interval") {
            if (i + 1 < argc) parseConfigInt("--interval", argv[++i], cfg.scrapeIntervalSec);
        } else if (arg == "-s" || arg == "--syslog-file") {
            if (i + 1 < argc) cfg.syslogFile = argv[++i];
        } else if (arg == "--lan-subnets") {
            if (i + 1 < argc) cfg.setLanSubnets(argv[++i]);
        } else if (arg == "--max-conntrack-flows") {
            if (i + 1 < argc) parseConfigSize("--max-conntrack-flows", argv[++i], cfg.maxConntrackFlows);
        } else if (arg == "--enable-conntrack-events") {
            cfg.enableNetlinkConntrack = true;
        } else if (arg == "--disable-conntrack-events" || arg == "--no-conntrack-events") {
            cfg.enableNetlinkConntrack = false;
        } else if (arg == "--syslog-from-beginning") {
            cfg.syslogFromBeginning = true;
        } else if (arg == "-d" || arg == "--daemon") {
            cfg.daemonize = true;
        } else if (arg == "-v" || arg == "--verbose") {
            cfg.verbose = true;
        }
    }

    cfg.clampBounds();
    return cfg;
}
