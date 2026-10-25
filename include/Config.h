#pragma once

#include "platform/IpClassifier.h"
#include <cstddef>
#include <map>
#include <string>
#include <vector>

struct Config {
    std::string configFile = "/jffs/etc/motel.conf";
    std::string endpoint = "http://127.0.0.1:4318";
    std::string headers;
    std::string serviceName = "merlin-router";
    std::string serviceInstanceId = "rt-be92u";
    std::string hostName = "router";

    int scrapeIntervalSec = 15;
    int slowIntervalSec = 60;
    std::string syslogFile = "/tmp/syslog.log";
    bool syslogFromBeginning = false;
    double syslogRateLimit = 50.0;
    double syslogBurstLimit = 100.0;

    bool enableHost = true;
    bool enableNet = true;
    bool enableFlowCache = true;
    bool enableArcher = true;
    bool enableWifi = true;
    bool enableSyslog = true;
    bool enableNetlinkConntrack = true;

    size_t topClientFlows = 32;
    size_t maxConntrackFlows = 512;
    int timeoutSec = 5;
    size_t queueCapacity = 128;
    bool daemonize = false;
    bool verbose = false;

    // Centralized LAN subnet classifier (defaults to RFC1918 + IPv6 ULA)
    Platform::IpClassifier lanClassifier;

    std::map<std::string, std::string> customAttributes;

    void setLanSubnets(const std::vector<std::string>& subnets) { lanClassifier.setSubnets(subnets); }
    void setLanSubnets(const std::string& commaSeparated) { lanClassifier.setSubnets(commaSeparated); }
    bool isLanIp(const std::string& ip) const { return lanClassifier.contains(ip); }

    void clampBounds();

    static Config parse(int argc, char* argv[]);
    bool loadFromFile(const std::string& path);
};
