#include "Config.h"
#include "collectors/BcmArcherCollector.h"
#include "collectors/BcmFlowCacheCollector.h"
#include "collectors/BcmWifiCollector.h"
#include "collectors/HostMetricsCollector.h"
#include "collectors/NetInterfaceCollector.h"
#include "collectors/NetlinkConntrackCollector.h"
#include "collectors/SyslogTailer.h"
#include "otel/OtelLogger.h"
#include "otel/OtelMetrics.h"
#include "otel/OtelProtoEncoder.h"
#include "otel/OtelSender.h"
#include "platform/SubprocessRunner.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAILED: " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            return 1; \
        } \
    } while (0)

namespace {

const OTel::Proto::MetricPoint* findMetric(
    const std::vector<OTel::Proto::MetricPoint>& pts,
    const std::string& name,
    const std::map<std::string, std::string>& requiredAttrs = {}) {
    for (const auto& pt : pts) {
        if (pt.name != name) continue;
        bool match = true;
        for (const auto& kv : requiredAttrs) {
            auto it = pt.attributes.find(kv.first);
            if (it == pt.attributes.end() || it->second != kv.second) {
                match = false;
                break;
            }
        }
        if (match) return &pt;
    }
    return nullptr;
}

size_t countMetrics(
    const std::vector<OTel::Proto::MetricPoint>& pts,
    const std::string& name) {
    size_t count = 0;
    for (const auto& pt : pts) {
        if (pt.name == name) ++count;
    }
    return count;
}

} // namespace

int testProtoEncoder() {
    OTel::OTelResourceConfig res;
    res.serviceName = "test-router";
    res.serviceInstanceId = "rt-be92u-001";
    res.hostName = "test-host";
    res.set("device.model", "RT-BE92U");

    // 1. MetricBatch with Gauge and Cumulative Sum (with start_time_unix_nano)
    OTel::Proto::MetricBatch mb;
    mb.addGauge("system.cpu.utilization", 0.42, "1", {{"cpu", "cpu0"}});
    mb.addGauge("system.cpu.utilization", 0.55, "1", {{"cpu", "cpu1"}});
    const uint64_t startTs = 1700000000123456789ULL;
    const uint64_t sampleTs = 1700000015123456789ULL;
    mb.addSumInt("system.network.io", 1099511627776LL, true,
                 OTel::Proto::Temporality::CUMULATIVE, "By",
                 {{"device", "eth0"}, {"direction", "receive"}},
                 sampleTs, startTs);

    auto metricBytes = mb.encode(res);
    TEST_ASSERT(!metricBytes.empty(), "Metric batch encoding should not be empty");
    TEST_ASSERT((metricBytes[0] & 0x07) == 2, "First tag must be length-delimited wire type");

    // Verify NumberDataPoint.attributes tag 7 (0x3a) AND start_time_unix_nano tag 2 (0x11) + little-endian fixed64
    bool foundAttrTag = (std::find(metricBytes.begin(), metricBytes.end(), 0x3a) != metricBytes.end());
    TEST_ASSERT(foundAttrTag, "Field 7 (attributes tag 0x3a) must be present on NumberDataPoint");

    std::vector<uint8_t> expectedStartField;
    OTel::Proto::writeTag(expectedStartField, 2, 1); // 0x11
    OTel::Proto::writeFixed64(expectedStartField, startTs);
    auto startIt = std::search(metricBytes.begin(), metricBytes.end(),
                               expectedStartField.begin(), expectedStartField.end());
    TEST_ASSERT(startIt != metricBytes.end(),
                "Field 2 (start_time_unix_nano) must be encoded on cumulative Sum NumberDataPoint");

    // 2. LogBatch
    OTel::Proto::LogBatch lb;
    lb.addRecord("INFO", 9, "Router started up", {{"syslog.app", "kernel"}},
                 sampleTs, "0123456789abcdef0123456789abcdef", "0123456789abcdef");
    auto logBytes = lb.encode(res);
    TEST_ASSERT(!logBytes.empty(), "Log batch encoding should not be empty");
    TEST_ASSERT((logBytes[0] & 0x07) == 2, "First tag must be length-delimited wire type");

    std::cout << "[PASS] testProtoEncoder\n";
    return 0;
}

int testSyslogParser() {
    Collectors::SyslogTailer tailer;
    std::string app, pid, sev, body;
    uint64_t timeNano = 0;

    // 1. Normal info log with hostname
    std::string line1 = "Oct 24 13:45:01 RT-BE92U-1234 kernel: [12345.678] eth0 (10G WAN): link up";
    TEST_ASSERT(tailer.parseLine(line1, app, pid, sev, body, timeNano), "parse line 1");
    TEST_ASSERT(app == "kernel", "app should be kernel");
    TEST_ASSERT(sev == "INFO", "severity should be INFO");
    TEST_ASSERT(timeNano > 0, "valid timestamp parsed");

    // 2. Error log with PID
    std::string line2 = "Oct 24 13:45:02 RT-BE92U-1234 dnsmasq[543]: failed to bind DHCP socket";
    TEST_ASSERT(tailer.parseLine(line2, app, pid, sev, body, timeNano), "parse line 2");
    TEST_ASSERT(app == "dnsmasq", "app should be dnsmasq");
    TEST_ASSERT(pid == "543", "pid should be 543");
    TEST_ASSERT(sev == "ERROR", "severity should be ERROR");

    // 3. Fatal OOM log
    std::string line3 = "Oct 24 13:45:03 kernel: Out of memory: Kill process 1234 (dropbear)";
    TEST_ASSERT(tailer.parseLine(line3, app, pid, sev, body, timeNano), "parse line 3");
    TEST_ASSERT(sev == "FATAL", "severity should be FATAL");

    // 4. Malformed dates/times must NEVER throw std::invalid_argument / std::out_of_range
    TEST_ASSERT(tailer.parseLine("Oct XX 13:45:01 router app: malformed day", app, pid, sev, body, timeNano),
                "malformed non-numeric day handled safely");
    TEST_ASSERT(timeNano == 0, "malformed day yields timeNano == 0");

    TEST_ASSERT(tailer.parseLine("Oct 99999999999999999999999 13:45:01 router app: overflow day", app, pid, sev, body, timeNano),
                "overflow day handled safely");
    TEST_ASSERT(timeNano == 0, "overflow day yields timeNano == 0");

    TEST_ASSERT(tailer.parseLine("Oct 24 99:88:77 router app: invalid clock error", app, pid, sev, body, timeNano),
                "out-of-bounds HH:MM:SS handled safely");
    TEST_ASSERT(timeNano == 0 && sev == "ERROR", "invalid clock still infers severity");

    // 5. End-to-end processBuffer -> OTel::Logger::activeBatch() assertion
    Config testCfg;
    testCfg.syslogRateLimit = 5.0;
    testCfg.syslogBurstLimit = 5.0;
    tailer.init(testCfg);

    OTel::Logger::startBatch();
    std::string rawStream = line1 + "\n" + line2 + "\n";
    tailer.processBuffer(rawStream.data(), rawStream.size());
    const auto& records = OTel::Logger::activeBatch().records();
    TEST_ASSERT(records.size() == 2, "processBuffer emitted 2 log records");
    TEST_ASSERT(records[0].severityText == "INFO", "record 0 severity INFO");
    TEST_ASSERT(records[0].attributes.at("syslog.app") == "kernel", "record 0 syslog.app=kernel");
    TEST_ASSERT(records[1].severityText == "ERROR", "record 1 severity ERROR");
    TEST_ASSERT(records[1].attributes.at("syslog.app") == "dnsmasq", "record 1 syslog.app=dnsmasq");
    TEST_ASSERT(records[1].attributes.at("syslog.pid") == "543", "record 1 syslog.pid=543");
    OTel::Logger::clearBatch();

    // Remaining 3 tokens in burst of 5
    for (int i = 0; i < 3; ++i) {
        TEST_ASSERT(tailer.allowLog(), "allow remaining burst");
    }
    TEST_ASSERT(!tailer.allowLog(), "throttle burst overflow");

    std::cout << "[PASS] testSyslogParser\n";
    return 0;
}

int testHostMetricsParser() {
    OTel::Metrics::startBatch();
    Collectors::HostMetricsCollector col;

    // Tick 1 of /proc/stat
    char statFile[] = "/tmp/mock_stat_XXXXXX";
    int fd = mkstemp(statFile);
    TEST_ASSERT(fd >= 0, "mkstemp stat 1");
    const char* statContent1 =
        "cpu  2000 0 1000 7000 0 0 0 0 0 0\n"
        "cpu0 1000 0 500 3500 0 0 0 0 0 0\n";
    TEST_ASSERT(write(fd, statContent1, std::strlen(statContent1)) > 0, "write stat 1");
    close(fd);
    col.parseProcStat(statFile);

    // Tick 2 of /proc/stat: cpu0 advances by +250 active, +750 idle (total +1000 => 0.25 utilization)
    fd = open(statFile, O_WRONLY | O_TRUNC);
    TEST_ASSERT(fd >= 0, "reopen stat 2");
    const char* statContent2 =
        "cpu  2500 0 1500 8500 0 0 0 0 0 0\n"
        "cpu0 1200 0 550 4250 0 0 0 0 0 0\n";
    TEST_ASSERT(write(fd, statContent2, std::strlen(statContent2)) > 0, "write stat 2");
    close(fd);
    col.parseProcStat(statFile);
    unlink(statFile);

    // /proc/meminfo
    char memFile[] = "/tmp/mock_mem_XXXXXX";
    fd = mkstemp(memFile);
    TEST_ASSERT(fd >= 0, "mkstemp mem");
    const char* memContent =
        "MemTotal:        1000000 kB\n"
        "MemFree:          400000 kB\n"
        "MemAvailable:     600000 kB\n"
        "Buffers:           50000 kB\n"
        "Cached:           200000 kB\n"
        "Slab:              80000 kB\n"
        "SReclaimable:      50000 kB\n"
        "SUnreclaim:        30000 kB\n";
    TEST_ASSERT(write(fd, memContent, std::strlen(memContent)) > 0, "write mem");
    close(fd);
    col.parseProcMeminfo(memFile);
    unlink(memFile);

    // /proc/loadavg
    char loadFile[] = "/tmp/mock_load_XXXXXX";
    fd = mkstemp(loadFile);
    TEST_ASSERT(fd >= 0, "mkstemp load");
    const char* loadContent = "0.75 0.50 0.25 3/142 9999\n";
    TEST_ASSERT(write(fd, loadContent, std::strlen(loadContent)) > 0, "write load");
    close(fd);
    col.parseProcLoadavg(loadFile);
    unlink(loadFile);

    const auto& pts = OTel::Metrics::activeBatch().points();
    const auto* cpuUtil = findMetric(pts, "system.cpu.utilization", {{"cpu", "cpu0"}});
    TEST_ASSERT(cpuUtil != nullptr, "system.cpu.utilization emitted for cpu0");
    TEST_ASSERT(std::fabs(cpuUtil->doubleValue - 0.25) < 1e-6, "cpu0 utilization == 0.25");

    const auto* cpuTime = findMetric(pts, "system.cpu.time", {{"cpu", "cpu0"}, {"state", "user"}});
    TEST_ASSERT(cpuTime != nullptr && !cpuTime->isGauge && cpuTime->startTimestampNano > 0,
                "system.cpu.time cumulative sum has startTimestampNano");

    const auto* memUsed = findMetric(pts, "system.memory.usage", {{"state", "used"}});
    TEST_ASSERT(memUsed != nullptr && memUsed->isInt && memUsed->intValue == 400000LL * 1024LL,
                "system.memory.usage used == 400000 KiB");

    const auto* memUtil = findMetric(pts, "system.memory.utilization");
    TEST_ASSERT(memUtil != nullptr && std::fabs(memUtil->doubleValue - 0.4) < 1e-6,
                "system.memory.utilization == 0.4");

    const auto* load1m = findMetric(pts, "system.cpu.load_average.1m");
    TEST_ASSERT(load1m != nullptr && std::fabs(load1m->doubleValue - 0.75) < 1e-6,
                "load_average.1m == 0.75");

    const auto* procRun = findMetric(pts, "system.processes.running");
    const auto* procTot = findMetric(pts, "system.processes.total");
    TEST_ASSERT(procRun != nullptr && procRun->intValue == 3, "running processes == 3");
    TEST_ASSERT(procTot != nullptr && procTot->intValue == 142, "total processes == 142");

    OTel::Metrics::clearBatch();
    std::cout << "[PASS] testHostMetricsParser\n";
    return 0;
}

int testNetInterfaceParser() {
    char devFile[] = "/tmp/mock_netdev_XXXXXX";
    int fd = mkstemp(devFile);
    TEST_ASSERT(fd >= 0, "mkstemp netdev");
    const char* devContent =
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 999999    1000    0    0    0     0          0         0 999999     1000    0    0    0     0       0          0\n"
        "  eth0: 104857600 200000    3    7    0     0          0         0 52428800  100000    1    2    0     0       0          0\n"
        "  eth6: 2048000    15000    0    0    0     0          0         0 1024000     8000    0    0    0     0       0          0\n"
        "   br0: 80000000  150000    0    0    0     0          0         0 40000000   80000    0    0    0     0       0          0\n";
    TEST_ASSERT(write(fd, devContent, std::strlen(devContent)) > 0, "write netdev");
    close(fd);

    auto discovered = Collectors::NetInterfaceCollector::discoverInterfaces(devFile);
    TEST_ASSERT(std::find(discovered.begin(), discovered.end(), "lo") == discovered.end(), "lo excluded from discovery");
    TEST_ASSERT(std::find(discovered.begin(), discovered.end(), "eth6") != discovered.end(), "eth6 dynamically discovered");
    TEST_ASSERT(std::find(discovered.begin(), discovered.end(), "br0") != discovered.end(), "br0 dynamically discovered");

    OTel::Metrics::startBatch();
    Collectors::NetInterfaceCollector col;
    col.parseProcNetDev(devFile);
    unlink(devFile);

    std::string mockEthctl =
        "RxOctets: 104857600\n"
        "TxOctets: 52428800\n"
        "RxPkts: 200000\n"
        "TxPkts: 100000\n";
    col.parseEthctlOutput("eth0", mockEthctl);

    const auto& pts = OTel::Metrics::activeBatch().points();
    const auto* rxIo = findMetric(pts, "system.network.io", {{"device", "eth0"}, {"direction", "receive"}});
    const auto* txIo = findMetric(pts, "system.network.io", {{"device", "eth0"}, {"direction", "transmit"}});
    const auto* rxDrop = findMetric(pts, "system.network.dropped", {{"device", "eth0"}, {"direction", "receive"}});
    const auto* hwRx = findMetric(pts, "bcm.hw.network.io", {{"device", "eth0"}, {"direction", "receive"}, {"tier", "switch_mac"}});

    TEST_ASSERT(rxIo != nullptr && rxIo->intValue == 104857600LL, "eth0 rx bytes == 104857600");
    TEST_ASSERT(txIo != nullptr && txIo->intValue == 52428800LL, "eth0 tx bytes == 52428800");
    TEST_ASSERT(rxDrop != nullptr && rxDrop->intValue == 7LL, "eth0 rx dropped == 7");
    TEST_ASSERT(hwRx != nullptr && hwRx->intValue == 104857600LL, "bcm.hw.network.io eth0 rx == 104857600");

    OTel::Metrics::clearBatch();
    std::cout << "[PASS] testNetInterfaceParser\n";
    return 0;
}

int testBcmFlowCacheParser() {
    char statsFile[] = "/tmp/mock_fcache_stats_XXXXXX";
    int fd = mkstemp(statsFile);
    TEST_ASSERT(fd >= 0, "mkstemp fcache stats");
    const char* statsContent =
        "Flow Cache Statistics:\n"
        "  Total Flows: 1024 / 16384\n"
        "  Hits (Pkts): 5000000\n"
        "  Hits (Bytes): 4000000000\n"
        "  Misses: 20000\n"
        "  Evictions: 15\n"
        "  Alloc Failures: 2\n";
    TEST_ASSERT(write(fd, statsContent, std::strlen(statsContent)) > 0, "write fcache stats");
    close(fd);

    OTel::Metrics::startBatch();
    Collectors::BcmFlowCacheCollector col;
    col.parseProcFcacheStats(statsFile);
    unlink(statsFile);

    char nfFile[] = "/tmp/mock_nflist_XXXXXX";
    fd = mkstemp(nfFile);
    TEST_ASSERT(fd >= 0, "mkstemp nflist");
    const char* nfContent =
        "# id proto src:sport dst:dport pkts bytes flags\n"
        "1 TCP 192.168.50.100:54321 1.1.1.1:443 pkts=5000 bytes=4000000 HW_ARCHER\n"
        "2 UDP 192.168.50.100:12345 8.8.8.8:53 pkts=100 bytes=8000 SW_FCACHE\n"
        "3 TCP 192.168.50.200:43210 1.2.3.4:80 pkts=1000 bytes=800000 HW_ARCHER\n";
    TEST_ASSERT(write(fd, nfContent, std::strlen(nfContent)) > 0, "write nflist");
    close(fd);

    col.parseProcFcacheNfList(nfFile);
    unlink(nfFile);

    const auto& pts = OTel::Metrics::activeBatch().points();
    const auto* active = findMetric(pts, "bcm.fcache.flows.active");
    const auto* maxFlows = findMetric(pts, "bcm.fcache.flows.max");
    const auto* hitsPkts = findMetric(pts, "bcm.fcache.hits.packets");
    const auto* hitsBytes = findMetric(pts, "bcm.fcache.hits.bytes");
    const auto* misses = findMetric(pts, "bcm.fcache.misses.packets");
    const auto* evict = findMetric(pts, "bcm.fcache.evictions");
    const auto* allocFail = findMetric(pts, "bcm.fcache.alloc_failures");

    TEST_ASSERT(active != nullptr && active->intValue == 1024, "fcache active == 1024");
    TEST_ASSERT(maxFlows != nullptr && maxFlows->intValue == 16384, "fcache max == 16384");
    TEST_ASSERT(hitsPkts != nullptr && hitsPkts->intValue == 5000000, "fcache hits.packets == 5000000");
    TEST_ASSERT(hitsBytes != nullptr && hitsBytes->intValue == 4000000000LL, "fcache hits.bytes == 4000000000");
    TEST_ASSERT(misses != nullptr && misses->intValue == 20000, "fcache misses == 20000");
    TEST_ASSERT(evict != nullptr && evict->intValue == 15, "fcache evictions == 15");
    TEST_ASSERT(allocFail != nullptr && allocFail->intValue == 2, "fcache alloc_failures == 2");

    const auto* tcpFlows = findMetric(pts, "bcm.fcache.flows.by_protocol", {{"protocol", "tcp"}});
    const auto* udpFlows = findMetric(pts, "bcm.fcache.flows.by_protocol", {{"protocol", "udp"}});
    const auto* hwTier = findMetric(pts, "bcm.fcache.flows.by_tier", {{"tier", "hardware_archer"}});
    const auto* swTier = findMetric(pts, "bcm.fcache.flows.by_tier", {{"tier", "software_fcache"}});
    TEST_ASSERT(tcpFlows != nullptr && tcpFlows->intValue == 2, "fcache tcp flows == 2");
    TEST_ASSERT(udpFlows != nullptr && udpFlows->intValue == 1, "fcache udp flows == 1");
    TEST_ASSERT(hwTier != nullptr && hwTier->intValue == 2, "fcache hw tier == 2");
    TEST_ASSERT(swTier != nullptr && swTier->intValue == 1, "fcache sw tier == 1");

    const auto* client1Bytes = findMetric(pts, "bcm.fcache.client.bytes", {{"client_ip", "192.168.50.100"}});
    const auto* client1Pkts = findMetric(pts, "bcm.fcache.client.packets", {{"client_ip", "192.168.50.100"}});
    const auto* client2Bytes = findMetric(pts, "bcm.fcache.client.bytes", {{"client_ip", "192.168.50.200"}});
    TEST_ASSERT(client1Bytes != nullptr && client1Bytes->intValue == 4008000LL, "client .100 bytes == 4008000");
    TEST_ASSERT(client1Pkts != nullptr && client1Pkts->intValue == 5100LL, "client .100 pkts == 5100");
    TEST_ASSERT(client2Bytes != nullptr && client2Bytes->intValue == 800000LL, "client .200 bytes == 800000");

    OTel::Metrics::clearBatch();
    std::cout << "[PASS] testBcmFlowCacheParser\n";
    return 0;
}

int testBcmArcherParser() {
    char statsFile[] = "/tmp/mock_archer_stats_XXXXXX";
    int fd = mkstemp(statsFile);
    TEST_ASSERT(fd >= 0, "mkstemp archer");
    const char* statsContent =
        "Broadcom Archer Runner Stats:\n"
        "  Rx Packets: 15000000\n"
        "  Tx Packets: 12000000\n"
        "  Dropped: 42\n"
        "  Active Flows: 850\n"
        "  Errors: 3\n";
    TEST_ASSERT(write(fd, statsContent, std::strlen(statsContent)) > 0, "write archer");
    close(fd);

    OTel::Metrics::startBatch();
    Collectors::BcmArcherCollector col;
    col.parseArcherProc(statsFile);
    unlink(statsFile);

    const auto& pts = OTel::Metrics::activeBatch().points();
    const auto* rx = findMetric(pts, "bcm.archer.rx.packets");
    const auto* tx = findMetric(pts, "bcm.archer.tx.packets");
    const auto* drop = findMetric(pts, "bcm.archer.rx.dropped");
    const auto* flows = findMetric(pts, "bcm.archer.flows.hw_active");
    const auto* errs = findMetric(pts, "bcm.archer.hw_errors");

    TEST_ASSERT(rx != nullptr && rx->intValue == 15000000LL, "archer rx == 15000000");
    TEST_ASSERT(tx != nullptr && tx->intValue == 12000000LL, "archer tx == 12000000");
    TEST_ASSERT(drop != nullptr && drop->intValue == 42LL, "archer dropped == 42");
    TEST_ASSERT(flows != nullptr && flows->intValue == 850LL, "archer hw_active == 850");
    TEST_ASSERT(errs != nullptr && errs->intValue == 3LL, "archer hw_errors == 3");

    OTel::Metrics::clearBatch();
    std::cout << "[PASS] testBcmArcherParser\n";
    return 0;
}

int testBcmWifiParser() {
    // 1. Strict MAC address validation (prevents command argument injection)
    TEST_ASSERT(Collectors::BcmWifiCollector::isValidMacAddress("00:11:22:aa:BB:cc"), "valid MAC");
    TEST_ASSERT(!Collectors::BcmWifiCollector::isValidMacAddress("00:11:22:33:44:55;id"), "reject shell metachar");
    TEST_ASSERT(!Collectors::BcmWifiCollector::isValidMacAddress("00:11:22:33:44"), "reject short MAC");
    TEST_ASSERT(!Collectors::BcmWifiCollector::isValidMacAddress("00-11-22-33-44-55"), "reject hyphen MAC");
    TEST_ASSERT(!Collectors::BcmWifiCollector::isValidMacAddress("GG:11:22:33:44:55"), "reject non-hex MAC");

    // 2. Parser metric assertions
    OTel::Metrics::startBatch();
    Collectors::BcmWifiCollector col;

    col.parseNoise("wl1", "-92");
    col.parseAssocList("wl1", "assoclist 00:11:22:33:44:55\nassoclist 66:77:88:99:AA:BB\n");
    col.parseAssocList("wl1.1", "assoclist AA:BB:CC:DD:EE:FF\n");
    col.parsePhyTemp("wl1", "114"); // Half-degree Broadcom sensor -> 57.0 C

    std::string mockChanim =
        "chanim_stats:\n"
        "ch tx inbss obss nocat nopkt doze txop bcnt glitch badplcp\n"
        "36 12 18 5 2 0 0 63 12345 10 2\n";
    col.parseChanimStats("wl1", mockChanim);

    // Real Broadcom HND `wl -i wl2 sta_info` output format (with rateset, kbps, and 4-antenna RSSI)
    std::string realStaInfo =
        "sta AA:BB:CC:DD:EE:FF:\n"
        "\t aid:1\n"
        "\t rateset [ 6 9 12 18 24 36 48 54 ]\n"
        "\t idle 0 seconds\n"
        "\t rate of last tx pkt: 2402000 kbps - 1201000 kbps\n"
        "\t rate of last rx pkt: 1921500 kbps\n"
        "\t per antenna rssi of last rx data frame: -55 -58 -49 0\n"
        "\t per antenna average rssi of rx data frames: -56 -59 -50 0\n";
    col.parseStaInfo("wl2", "AA:BB:CC:DD:EE:FF", realStaInfo);

    const auto& pts = OTel::Metrics::activeBatch().points();
    const auto* noise = findMetric(pts, "bcm.wifi.noise_dbm", {{"radio", "wl1"}, {"band", "5g"}});
    const auto* assocMain = findMetric(pts, "bcm.wifi.clients.associated", {{"radio", "wl1"}, {"band", "5g"}});
    const auto* assocGuest = findMetric(pts, "bcm.wifi.clients.associated", {{"radio", "wl1.1"}, {"band", "5g"}});
    const auto* temp = findMetric(pts, "bcm.wifi.temperature", {{"radio", "wl1"}, {"band", "5g"}});
    const auto* txop = findMetric(pts, "bcm.wifi.channel.utilization_percent", {{"radio", "wl1"}, {"type", "txop"}});
    const auto* glitches = findMetric(pts, "bcm.wifi.channel.glitches", {{"radio", "wl1"}});
    const auto* staRssi = findMetric(pts, "bcm.wifi.sta.rssi_dbm", {{"radio", "wl2"}, {"band", "6g"}, {"mac", "AA:BB:CC:DD:EE:FF"}});
    const auto* staRate = findMetric(pts, "bcm.wifi.sta.rate_mbps", {{"radio", "wl2"}, {"band", "6g"}, {"mac", "AA:BB:CC:DD:EE:FF"}});

    TEST_ASSERT(noise != nullptr && std::fabs(noise->doubleValue - (-92.0)) < 1e-6, "wifi noise == -92 dBm");
    TEST_ASSERT(assocMain != nullptr && assocMain->intValue == 2, "wl1 associated == 2");
    TEST_ASSERT(assocGuest != nullptr && assocGuest->intValue == 1, "wl1.1 associated == 1");
    TEST_ASSERT(temp != nullptr && std::fabs(temp->doubleValue - 57.0) < 1e-6, "wl1 phy temp == 57.0 C");
    TEST_ASSERT(txop != nullptr && std::fabs(txop->doubleValue - 63.0) < 1e-6, "wl1 txop == 63%");
    TEST_ASSERT(glitches != nullptr && glitches->intValue == 10, "wl1 glitches == 10");
    TEST_ASSERT(staRssi != nullptr && std::fabs(staRssi->doubleValue - (-49.0)) < 1e-6,
                "sta_info extracts strongest valid negative antenna RSSI (-49 dBm, ignoring 0)");
    TEST_ASSERT(staRate != nullptr && std::fabs(staRate->doubleValue - 2402.0) < 1e-6,
                "sta_info converts 2402000 kbps -> 2402.0 Mbps and ignores rateset");
    TEST_ASSERT(countMetrics(pts, "bcm.wifi.sta.rssi_dbm") == 1, "only one rssi metric emitted per station");
    TEST_ASSERT(countMetrics(pts, "bcm.wifi.sta.rate_mbps") == 1, "only one rate metric emitted per station");

    OTel::Metrics::clearBatch();

    // 3. Band, physical classification, and VIF discovery
    TEST_ASSERT(Collectors::BcmWifiCollector::bandFromRadio("wl0") == "2.4g", "band wl0");
    TEST_ASSERT(Collectors::BcmWifiCollector::bandFromRadio("wl1.1") == "5g", "band wl1.1");
    TEST_ASSERT(Collectors::BcmWifiCollector::bandFromRadio("wl2.1") == "6g", "band wl2.1");
    TEST_ASSERT(Collectors::BcmWifiCollector::isPhysicalRadio("wl0"), "wl0 is physical");
    TEST_ASSERT(!Collectors::BcmWifiCollector::isPhysicalRadio("wl0.1"), "wl0.1 is virtual");

    char mockNetDev[] = "/tmp/mock_proc_net_dev_wifi_XXXXXX";
    int fd = mkstemp(mockNetDev);
    TEST_ASSERT(fd >= 0, "mkstemp wifi netdev");
    const char* devContent =
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 1000 0 0 0 0 0 0 0 1000 0 0 0 0 0 0 0\n"
        "   wl0: 1000 0 0 0 0 0 0 0 1000 0 0 0 0 0 0 0\n"
        " wl0.1:  500 0 0 0 0 0 0 0  500 0 0 0 0 0 0 0\n"
        "   wl1: 2000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"
        " wl1.1:  800 0 0 0 0 0 0 0  800 0 0 0 0 0 0 0\n"
        " wl1.2:  200 0 0 0 0 0 0 0  200 0 0 0 0 0 0 0\n"
        "   wl2: 3000 0 0 0 0 0 0 0 3000 0 0 0 0 0 0 0\n"
        " wl2.1:  100 0 0 0 0 0 0 0  100 0 0 0 0 0 0 0\n";
    TEST_ASSERT(write(fd, devContent, std::strlen(devContent)) > 0, "write wifi netdev");
    close(fd);

    auto discovered = Collectors::BcmWifiCollector::discoverWifiInterfaces(mockNetDev);
    unlink(mockNetDev);
    TEST_ASSERT(discovered.size() == 7, "expected 7 wifi interfaces");

    std::cout << "[PASS] testBcmWifiParser\n";
    return 0;
}

int testNetlinkConntrackParser() {
    // 1. normalizePort
    TEST_ASSERT(Collectors::NetlinkConntrackCollector::normalizePort(443, "tcp") == "443/https", "443/https");
    TEST_ASSERT(Collectors::NetlinkConntrackCollector::normalizePort(80, "tcp") == "80/http", "80/http");
    TEST_ASSERT(Collectors::NetlinkConntrackCollector::normalizePort(53, "udp") == "53/dns", "53/dns");
    TEST_ASSERT(Collectors::NetlinkConntrackCollector::normalizePort(22, "tcp") == "22/ssh", "22/ssh");
    TEST_ASSERT(Collectors::NetlinkConntrackCollector::normalizePort(12345, "tcp") == "high_ports", "high_ports");

    // 2. Robustness on malformed or empty buffers
    Collectors::NetlinkConntrackCollector col;
    TEST_ASSERT(!col.parseNetlinkMessage(nullptr, 0), "null message");
    uint8_t dummy[16]{};
    col.parseNetlinkMessage(dummy, sizeof(dummy));

    // 3. Cardinality cap enforcement (maxConntrackFlows) + overflow aggregation + metric emission
    Config cfg;
    cfg.maxConntrackFlows = 16;
    cfg.clampBounds();
    col.reloadConfig(cfg);

    // Insert 25 distinct system-port flows (ports 1..25) from LAN client
    for (uint16_t port = 1; port <= 25; ++port) {
        col.recordCompletedFlow("192.168.50.10", "1.1.1.1", "tcp", 50000, port, 1000, 2000, 10, 20);
    }
    // 16 distinct keys + 1 overflow sentinel ("other", "tcp", "overflow") = 17 bounded entries
    TEST_ASSERT(col.trackedFlowCount() == 17, "m_flowTotals bounded to maxConntrackFlows + 1 overflow key");

    // Updating an existing flow key must still accumulate in-place without going to overflow
    col.recordCompletedFlow("192.168.50.10", "1.1.1.1", "tcp", 50000, 1, 500, 500, 5, 5);
    TEST_ASSERT(col.trackedFlowCount() == 17, "updating existing key does not grow map");

    OTel::Metrics::startBatch();
    col.collectFast(); // m_fd is -1, so drainSocket is a no-op and m_flowTotals is exported
    const auto& pts = OTel::Metrics::activeBatch().points();

    const auto* port1Tx = findMetric(pts, "bcm.traffic.completed.bytes",
                                     {{"client_ip", "192.168.50.10"}, {"protocol", "tcp"}, {"dest_port", "1"}, {"direction", "transmit"}});
    const auto* overflowTx = findMetric(pts, "bcm.traffic.completed.bytes",
                                        {{"client_ip", "other"}, {"protocol", "tcp"}, {"dest_port", "overflow"}, {"direction", "transmit"}});
    const auto* overflowRx = findMetric(pts, "bcm.traffic.completed.bytes",
                                        {{"client_ip", "other"}, {"protocol", "tcp"}, {"dest_port", "overflow"}, {"direction", "receive"}});

    TEST_ASSERT(port1Tx != nullptr && port1Tx->intValue == 1500LL, "port 1 tx bytes == 1000 + 500");
    // Ports 17..25 (9 flows) overflowed with 1000 txBytes and 2000 rxBytes each
    TEST_ASSERT(overflowTx != nullptr && overflowTx->intValue == 9000LL, "overflow tx bytes == 9 * 1000");
    TEST_ASSERT(overflowRx != nullptr && overflowRx->intValue == 18000LL, "overflow rx bytes == 9 * 2000");

    OTel::Metrics::clearBatch();
    std::cout << "[PASS] testNetlinkConntrackParser\n";
    return 0;
}

int testSubprocessDirectExec() {
    // 1. Prove shell metacharacters are passed literally to argv (NO /bin/sh -c execution)
    const std::string payload = "hello; $(uname -a) `id` | cat";
    auto res = Platform::SubprocessRunner::run({"/bin/echo", payload}, 1000);
    TEST_ASSERT(res.success(), "/bin/echo direct execution succeeded");
    TEST_ASSERT(res.stdoutData == payload + "\n", "shell metacharacters were NOT interpreted by /bin/sh");

    // 2. Bare command name resolution across trusted directories (no access() TOCTOU)
    auto bareRes = Platform::SubprocessRunner::run({"echo", "bare-ok"}, 1000);
    TEST_ASSERT(bareRes.success() && bareRes.stdoutData == "bare-ok\n", "bare binary resolved in /bin");

    // 3. Reject untrusted relative paths and path traversal
    auto badRel = Platform::SubprocessRunner::run({"./untrusted_binary"}, 500);
    TEST_ASSERT(!badRel.success() && badRel.exitCode == 127, "relative binary path rejected");

    auto badTraversal = Platform::SubprocessRunner::run({"/bin/../bin/echo", "nope"}, 500);
    TEST_ASSERT(!badTraversal.success() && badTraversal.exitCode == 127, "path traversal rejected");

    std::cout << "[PASS] testSubprocessDirectExec\n";
    return 0;
}

int testLanIpConfigAndLookup() {
    // 1. Default centralized LAN ranges (RFC1918 + IPv6 ULA)
    Config defaultCfg;
    TEST_ASSERT(defaultCfg.isLanIp("192.168.50.100"), "default lan 192.168.50.100");
    TEST_ASSERT(defaultCfg.isLanIp("10.255.255.254"), "default lan 10.255.255.254");
    TEST_ASSERT(defaultCfg.isLanIp("172.16.0.1"), "default lan 172.16.0.1");
    TEST_ASSERT(defaultCfg.isLanIp("172.31.255.254"), "default lan 172.31.255.254");
    TEST_ASSERT(!defaultCfg.isLanIp("172.15.255.254"), "172.15.x is outside 172.16.0.0/12");
    TEST_ASSERT(!defaultCfg.isLanIp("172.32.0.1"), "172.32.x is outside 172.16.0.0/12");
    TEST_ASSERT(!defaultCfg.isLanIp("1.1.1.1"), "wan 1.1.1.1");
    TEST_ASSERT(defaultCfg.isLanIp("fd12:3456:789a::1"), "default ipv6 ULA fd00::/8");
    TEST_ASSERT(!defaultCfg.isLanIp("2606:4700:4700::1111"), "wan ipv6");
    TEST_ASSERT(!defaultCfg.isLanIp(""), "empty ip");
    TEST_ASSERT(!defaultCfg.isLanIp("10.invalid.ip"), "malformed ip");

    // 2. Custom LAN subnet list
    Config customCfg;
    customCfg.setLanSubnets("192.168.50.0/24, 10.99.0.5, 2001:db8:abcd::/48");
    TEST_ASSERT(customCfg.isLanIp("192.168.50.1"), "custom /24 match .1");
    TEST_ASSERT(!customCfg.isLanIp("192.168.1.1"), "upstream double-NAT 192.168.1.1 excluded");
    TEST_ASSERT(customCfg.isLanIp("10.99.0.5"), "single host IP /32 match");
    TEST_ASSERT(!customCfg.isLanIp("10.99.0.6"), "adjacent single host IP excluded");
    TEST_ASSERT(customCfg.isLanIp("2001:db8:abcd:1::42"), "custom ipv6 /48 match");

    // 3. Config file parsing of lan_subnets + malformed/out-of-range numeric config resilience
    char confPath[] = "/tmp/mock_motel_conf_XXXXXX";
    int fd = mkstemp(confPath);
    TEST_ASSERT(fd >= 0, "mkstemp conf");
    const char* confContent =
        "lan_subnets = 192.168.88.0/24, 172.18.0.0/16\n"
        "scrape_interval_sec = 0\n"
        "slow_interval_sec = -10\n"
        "timeout_sec = invalid_number\n"
        "max_conntrack_flows = 99999999\n"
        "queue_capacity = 0\n";
    TEST_ASSERT(write(fd, confContent, std::strlen(confContent)) > 0, "write conf");
    close(fd);

    Config fileCfg;
    TEST_ASSERT(fileCfg.loadFromFile(confPath), "loadFromFile conf succeeds without throwing");
    unlink(confPath);
    TEST_ASSERT(fileCfg.customAttributes.find("lan_subnets") == fileCfg.customAttributes.end(),
                "lan_subnets must not leak into customAttributes");
    TEST_ASSERT(fileCfg.customAttributes.find("max_conntrack_flows") == fileCfg.customAttributes.end(),
                "max_conntrack_flows must not leak into customAttributes");
    TEST_ASSERT(fileCfg.isLanIp("192.168.88.42"), "file conf 192.168.88.0/24");
    TEST_ASSERT(!fileCfg.isLanIp("192.168.50.1"), "file conf excludes 192.168.50.1");
    TEST_ASSERT(fileCfg.scrapeIntervalSec == 1, "scrapeIntervalSec clamped >= 1 (prevents 0-interval spin)");
    TEST_ASSERT(fileCfg.slowIntervalSec >= fileCfg.scrapeIntervalSec, "slowIntervalSec clamped >= scrapeIntervalSec");
    TEST_ASSERT(fileCfg.timeoutSec == 5, "invalid timeout_sec preserves default 5");
    TEST_ASSERT(fileCfg.maxConntrackFlows == 16384, "maxConntrackFlows clamped to upper bound 16384");
    TEST_ASSERT(fileCfg.queueCapacity == 4, "queueCapacity clamped >= 4");

    // 4. CLI flags override
    const char* argvLan[] = {"merlin-otel-agent", "--lan-subnets", "10.42.0.0/16", "--max-conntrack-flows", "256", "--disable-conntrack-events"};
    Config cliCfg = Config::parse(6, const_cast<char**>(argvLan));
    TEST_ASSERT(cliCfg.isLanIp("10.42.1.5"), "cli --lan-subnets match");
    TEST_ASSERT(cliCfg.maxConntrackFlows == 256, "cli --max-conntrack-flows 256");
    TEST_ASSERT(!cliCfg.enableNetlinkConntrack, "cli --disable-conntrack-events");

    std::cout << "[PASS] testLanIpConfigAndLookup\n";
    return 0;
}

int testHttpUrlAndLoopbackSender() {
    // 1. URL parsing with IPv4 and bracketed IPv6 literals
    std::string ep1 = "http://192.168.1.100:5080/api/default/";
    TEST_ASSERT(OTel::OTelSender::buildSignalUrl(ep1, "/v1/metrics") == "http://192.168.1.100:5080/api/default/v1/metrics",
                "buildSignalUrl trailing slash");

    std::string epV6 = "http://[fd00::10]:5080/api/default";
    auto parsedV6 = OTel::OTelSender::parseUrl(epV6);
    TEST_ASSERT(parsedV6.scheme == "http", "ipv6 scheme");
    TEST_ASSERT(parsedV6.host == "fd00::10", "ipv6 unbracketed host for getaddrinfo");
    TEST_ASSERT(parsedV6.port == "5080", "ipv6 port 5080");
    TEST_ASSERT(parsedV6.basePath == "/api/default", "ipv6 basePath");
    TEST_ASSERT(OTel::OTelSender::buildSignalUrl(epV6, "/v1/logs") == "http://[fd00::10]:5080/api/default/v1/logs",
                "buildSignalUrl preserves RFC 3986 brackets for IPv6");

    auto parsedV6DefaultPort = OTel::OTelSender::parseUrl("http://[::1]/v1/metrics");
    TEST_ASSERT(parsedV6DefaultPort.host == "::1" && parsedV6DefaultPort.port == "80", "ipv6 default port 80");

    // 2. Header parsing with '=' and Base64 padding
    std::string h = "X-Scope-OrgID=default,Authorization=Basic%20PLACEHOLDER_AUTH_TOKEN==";
    auto hdrs = OTel::OTelSender::parseHttpHeaders(h);
    TEST_ASSERT(hdrs.size() == 2, "2 headers parsed");
    TEST_ASSERT(hdrs[0] == "X-Scope-OrgID: default", "header 0");
    TEST_ASSERT(hdrs[1] == "Authorization: Basic PLACEHOLDER_AUTH_TOKEN==", "header 1");

    // 3. Reject https:// endpoints explicitly (lean agent uses native HTTP/1.1; no plaintext leak)
    OTel::OTelSender::init("https://127.0.0.1:65534/api/default", "Authorization=Basic PLACEHOLDER_AUTH_TOKEN", 8, 1, false);
    OTel::OTelSender::sendProto("/v1/metrics", std::vector<uint8_t>{0x0a, 0x00});
    usleep(50000);
    OTel::OTelSender::shutdown();
    TEST_ASSERT(OTel::OTelSender::sentCount() == 0 && OTel::OTelSender::failedCount() >= 1,
                "https:// endpoint rejected without plaintext transmission");

    // 4. Ephemeral loopback TCP HTTP server test with 80 KB payload (tests sendAll partial-write loop)
    int listenFd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    TEST_ASSERT(listenFd >= 0, "loopback listen socket");
    int opt = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // ephemeral port
    TEST_ASSERT(bind(listenFd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0, "bind loopback");
    TEST_ASSERT(listen(listenFd, 1) == 0, "listen loopback");

    socklen_t addrLen = sizeof(addr);
    TEST_ASSERT(getsockname(listenFd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == 0, "getsockname");
    uint16_t port = ntohs(addr.sin_port);

    const size_t kLargePayloadSize = 80 * 1024; // 81920 bytes > typical single write chunk
    std::vector<uint8_t> expectedBody(kLargePayloadSize);
    for (size_t i = 0; i < kLargePayloadSize; ++i) {
        expectedBody[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    }

    std::string receivedHeaders;
    std::vector<uint8_t> receivedBody;

    std::thread serverThread([&]() {
        int clientFd = accept(listenFd, nullptr, nullptr);
        if (clientFd < 0) return;

        std::string rawReq;
        char buf[4096];
        size_t headerEnd = std::string::npos;
        while ((headerEnd = rawReq.find("\r\n\r\n")) == std::string::npos) {
            ssize_t n = recv(clientFd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            rawReq.append(buf, static_cast<size_t>(n));
        }

        if (headerEnd != std::string::npos) {
            receivedHeaders = rawReq.substr(0, headerEnd);
            size_t bodyStart = headerEnd + 4;
            receivedBody.assign(rawReq.begin() + static_cast<std::ptrdiff_t>(bodyStart), rawReq.end());

            while (receivedBody.size() < kLargePayloadSize) {
                ssize_t n = recv(clientFd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                receivedBody.insert(receivedBody.end(), buf, buf + n);
            }
        }

        const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(clientFd, resp, std::strlen(resp), 0);
        close(clientFd);
    });

    std::string loopbackEndpoint = "http://127.0.0.1:" + std::to_string(port) + "/api/default";
    OTel::OTelSender::init(loopbackEndpoint, "Authorization=Basic PLACEHOLDER_AUTH_TOKEN", 16, 3, false);
    std::vector<uint8_t> payloadCopy = expectedBody;
    OTel::OTelSender::sendProto("/v1/metrics", std::move(payloadCopy));

    serverThread.join();
    close(listenFd);
    OTel::OTelSender::shutdown();

    TEST_ASSERT(receivedHeaders.find("POST /api/default/v1/metrics HTTP/1.1") != std::string::npos,
                "loopback HTTP request line matches OpenObserve subpath");
    TEST_ASSERT(receivedHeaders.find("Authorization: Basic PLACEHOLDER_AUTH_TOKEN") != std::string::npos,
                "loopback HTTP Authorization header intact");
    TEST_ASSERT(receivedHeaders.find("Content-Length: 81920") != std::string::npos,
                "loopback HTTP Content-Length == 81920");
    TEST_ASSERT(receivedBody == expectedBody,
                "full 80 KB payload received byte-for-byte without partial-write truncation");
    TEST_ASSERT(OTel::OTelSender::sentCount() == 1 && OTel::OTelSender::failedCount() == 0,
                "OTelSender recorded 1 sent payload and 0 failures");

    std::cout << "[PASS] testHttpUrlAndLoopbackSender\n";
    return 0;
}

int main() {
    std::cout << "Running merlin-otel-agent unit tests...\n";
    if (testProtoEncoder() != 0) return 1;
    if (testSyslogParser() != 0) return 1;
    if (testHostMetricsParser() != 0) return 1;
    if (testNetInterfaceParser() != 0) return 1;
    if (testBcmFlowCacheParser() != 0) return 1;
    if (testBcmArcherParser() != 0) return 1;
    if (testBcmWifiParser() != 0) return 1;
    if (testNetlinkConntrackParser() != 0) return 1;
    if (testSubprocessDirectExec() != 0) return 1;
    if (testLanIpConfigAndLookup() != 0) return 1;
    if (testHttpUrlAndLoopbackSender() != 0) return 1;

    std::cout << "ALL TESTS PASSED!\n";
    return 0;
}
