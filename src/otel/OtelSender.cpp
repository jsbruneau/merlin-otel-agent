#include "otel/OtelSender.h"
#include "otel/OtelDefaults.h"
#include "platform/StringUtils.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netdb.h>
#include <poll.h>
#include <random>
#include <sstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace OTel {

static std::string urlDecode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            auto hexVal = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int v1 = hexVal(in[i + 1]);
            int v2 = hexVal(in[i + 2]);
            if (v1 >= 0 && v2 >= 0) {
                out.push_back(static_cast<char>((v1 << 4) | v2));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

static std::string formatHostAuthority(const std::string& host) {
    if (host.find(':') != std::string::npos) {
        return "[" + host + "]";
    }
    return host;
}

static bool sendAll(int fd, const void* rawData, size_t len) {
    const auto* ptr = static_cast<const uint8_t*>(rawData);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, ptr + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

OTelSender::ParsedUrl OTelSender::parseUrl(const std::string& rawUrl) {
    ParsedUrl p;
    std::string u = Platform::trimAndUnquote(rawUrl);
    size_t schemePos = u.find("://");
    if (schemePos != std::string::npos) {
        p.scheme = u.substr(0, schemePos);
        std::transform(p.scheme.begin(), p.scheme.end(), p.scheme.begin(), ::tolower);
        u = u.substr(schemePos + 3);
    }

    size_t slashPos = u.find('/');
    std::string hostPort;
    if (slashPos != std::string::npos) {
        hostPort = u.substr(0, slashPos);
        p.basePath = u.substr(slashPos);
        while (p.basePath.size() > 1 && p.basePath.back() == '/') {
            p.basePath.pop_back();
        }
        if (p.basePath == "/") p.basePath.clear();
    } else {
        hostPort = u;
    }

    // Strip signal suffixes if user configured full signal URL in base endpoint
    const std::string v1m = "/v1/metrics";
    const std::string v1l = "/v1/logs";
    const std::string v1t = "/v1/traces";
    if (p.basePath.size() >= v1m.size() &&
        p.basePath.compare(p.basePath.size() - v1m.size(), v1m.size(), v1m) == 0) {
        p.basePath.erase(p.basePath.size() - v1m.size());
    } else if (p.basePath.size() >= v1l.size() &&
               p.basePath.compare(p.basePath.size() - v1l.size(), v1l.size(), v1l) == 0) {
        p.basePath.erase(p.basePath.size() - v1l.size());
    } else if (p.basePath.size() >= v1t.size() &&
               p.basePath.compare(p.basePath.size() - v1t.size(), v1t.size(), v1t) == 0) {
        p.basePath.erase(p.basePath.size() - v1t.size());
    }

    if (!hostPort.empty() && hostPort.front() == '[') {
        size_t rbracket = hostPort.find(']');
        if (rbracket != std::string::npos) {
            p.host = hostPort.substr(1, rbracket - 1);
            if (rbracket + 1 < hostPort.size() && hostPort[rbracket + 1] == ':') {
                p.port = hostPort.substr(rbracket + 2);
            } else {
                p.port = (p.scheme == "https") ? "443" : "80";
            }
            return p;
        }
    }

    size_t colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        p.host = hostPort.substr(0, colonPos);
        p.port = hostPort.substr(colonPos + 1);
    } else {
        p.host = hostPort;
        p.port = (p.scheme == "https") ? "443" : "80";
    }

    return p;
}

std::string OTelSender::buildSignalUrl(const std::string& endpoint, const std::string& signalPath) {
    auto p = parseUrl(endpoint);
    return p.scheme + "://" + formatHostAuthority(p.host) + ":" + p.port + p.basePath + signalPath;
}

std::string OTelSender::buildSignalPath(const std::string& endpoint, const std::string& signalPath) {
    auto p = parseUrl(endpoint);
    return p.basePath + signalPath;
}

std::vector<std::string> OTelSender::parseHttpHeaders(const std::string& rawHeaders) {
    std::vector<std::string> result;
    if (rawHeaders.empty()) return result;

    std::stringstream ss(rawHeaders);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token = Platform::trimAndUnquote(token);
        if (token.empty()) continue;

        size_t sep = token.find_first_of(":=");
        if (sep == std::string::npos) continue;

        std::string headerName = Platform::trimAndUnquote(token.substr(0, sep));
        std::string headerVal = urlDecode(Platform::trimAndUnquote(token.substr(sep + 1)));

        if (!headerName.empty()) {
            result.push_back(headerName + ": " + headerVal);
        }
    }
    return result;
}

OTelSender& OTelSender::instance() {
    static OTelSender s;
    return s;
}

OTelSender::~OTelSender() {
    shutdown();
}

void OTelSender::init(const std::string& endpoint, const std::string& headers,
                      size_t queueCapacity, int timeoutSec, bool verbose) {
    auto& s = instance();
    if (s.m_running.load()) {
        shutdown();
    }

    if (parseUrl(endpoint).scheme == "https") {
        std::cerr << "[motel] ERROR: https:// endpoint configured ('" << endpoint
                  << "'), but agent was built for native HTTP/1.1 LAN ingestion. "
                  << "Refusing to transmit telemetry over unencrypted TCP.\n";
    }

    std::lock_guard<std::mutex> lock(s.m_mutex);
    s.m_endpoint = endpoint;
    s.m_headers = headers;
    s.m_capacity = (queueCapacity >= 4) ? queueCapacity : 16;
    s.m_timeoutSec = (timeoutSec >= 1) ? timeoutSec : 5;
    s.m_verbose = verbose;
    s.m_queue.assign(s.m_capacity, OTelQueuedItem{});
    s.m_head = 0;
    s.m_tail = 0;
    s.m_count = 0;
    s.m_dropped.store(0);
    s.m_sent.store(0);
    s.m_failed.store(0);
    s.m_consecutiveFailures.store(0);

    s.m_running.store(true);
    s.m_worker = std::thread(&OTelSender::workerLoop, &s);
}

void OTelSender::shutdown() {
    auto& s = instance();
    {
        std::lock_guard<std::mutex> lock(s.m_mutex);
        if (!s.m_running.load()) return;
        s.m_running.store(false);
        s.m_cv.notify_all();
    }
    if (s.m_worker.joinable()) {
        s.m_worker.join();
    }
}

void OTelSender::sendProto(const std::string& path, std::vector<uint8_t>&& payload) {
    if (payload.empty()) return;
    OTelQueuedItem item;
    item.path = path;
    item.contentType = "application/x-protobuf";
    item.payload = std::move(payload);
    instance().enqueue(std::move(item));
}

uint64_t OTelSender::droppedCount() { return instance().m_dropped.load(); }
uint64_t OTelSender::sentCount()    { return instance().m_sent.load(); }
uint64_t OTelSender::failedCount()  { return instance().m_failed.load(); }

void OTelSender::enqueue(OTelQueuedItem&& item) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_running.load()) return;

    if (m_count >= m_capacity) {
        m_head = (m_head + 1) % m_capacity;
        --m_count;
        m_dropped.fetch_add(1);
    }

    m_queue[m_tail] = std::move(item);
    m_tail = (m_tail + 1) % m_capacity;
    ++m_count;
    m_cv.notify_one();
}

void OTelSender::workerLoop() {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> jitterDist(0, 999);

    while (true) {
        OTelQueuedItem item;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this]() {
                return !m_running.load() || m_count > 0;
            });

            if (!m_running.load() && m_count == 0) {
                break;
            }

            // Circuit Breaker: if in backoff cooldown, sleep before probing the network
            uint32_t failures = m_consecutiveFailures.load();
            if (failures > 0) {
                if (!m_running.load()) {
                    // Sink is down and daemon is shutting down; exit immediately instead of spinning
                    break;
                }
                uint32_t shift = (failures > 4) ? 4 : failures;
                uint32_t baseMs = 1000U * (1U << shift);
                if (baseMs > 30000U) baseMs = 30000U;
                uint32_t backoffMs = baseMs + jitterDist(rng);

                m_cv.wait_for(lock, std::chrono::milliseconds(backoffMs), [this]() {
                    return !m_running.load();
                });

                if (!m_running.load()) {
                    break;
                }
            }

            item = std::move(m_queue[m_head]);
            m_head = (m_head + 1) % m_capacity;
            --m_count;
        }

        if (item.payload.empty() || item.path.empty()) {
            continue;
        }

        bool ok = postHttp(item);

        if (ok) {
            m_sent.fetch_add(1);
            m_consecutiveFailures.store(0);
        } else {
            m_failed.fetch_add(1);
            m_consecutiveFailures.fetch_add(1);

            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_count > 4) {
                size_t discardCount = m_count - 4;
                m_head = (m_head + discardCount) % m_capacity;
                m_count = 4;
                m_dropped.fetch_add(discardCount);
            }
        }
    }
}

bool OTelSender::postHttp(const OTelQueuedItem& item) {
    auto parsed = parseUrl(m_endpoint);
    if (parsed.scheme == "https") {
        if (m_verbose) {
            std::cerr << "[motel] Cannot POST to https:// endpoint (native HTTP/1.1 agent only)\n";
        }
        return false;
    }

    std::string fullPath = parsed.basePath + item.path;

    struct addrinfo hints{};
    struct addrinfo* res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(parsed.host.c_str(), parsed.port.c_str(), &hints, &res) != 0 || !res) {
        if (m_verbose) {
            std::cerr << "[motel] DNS resolution failed for " << parsed.host << ":" << parsed.port << "\n";
        }
        return false;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return false;
    }

    fcntl(fd, F_SETFL, O_NONBLOCK);

    int connRes = connect(fd, res->ai_addr, res->ai_addrlen);
    if (connRes < 0 && errno == EINPROGRESS) {
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int pRes = poll(&pfd, 1, 2000);
        if (pRes <= 0) {
            close(fd);
            freeaddrinfo(res);
            return false;
        }
        int soError = 0;
        socklen_t len = sizeof(soError);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len);
        if (soError != 0) {
            close(fd);
            freeaddrinfo(res);
            return false;
        }
    } else if (connRes < 0) {
        close(fd);
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);

    fcntl(fd, F_SETFL, 0);
    struct timeval tv{};
    tv.tv_sec = m_timeoutSec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::ostringstream req;
    req << "POST " << fullPath << " HTTP/1.1\r\n";
    req << "Host: " << formatHostAuthority(parsed.host) << ":" << parsed.port << "\r\n";
    req << "User-Agent: merlin-otel-agent/" << MOTEL_VERSION << "\r\n";
    req << "Content-Type: " << item.contentType << "\r\n";
    req << "Content-Length: " << item.payload.size() << "\r\n";
    req << "Connection: close\r\n";

    for (const auto& h : parseHttpHeaders(m_headers)) {
        req << h << "\r\n";
    }
    req << "\r\n";

    std::string headerStr = req.str();
    if (!sendAll(fd, headerStr.data(), headerStr.size()) ||
        !sendAll(fd, item.payload.data(), item.payload.size())) {
        close(fd);
        return false;
    }

    std::array<char, 512> respBuf{};
    ssize_t n = 0;
    do {
        n = recv(fd, respBuf.data(), respBuf.size() - 1, 0);
    } while (n < 0 && errno == EINTR);
    close(fd);

    if (n <= 0) return false;
    respBuf[static_cast<size_t>(n)] = '\0';

    if (std::strstr(respBuf.data(), "HTTP/1.") != nullptr) {
        const char* code = std::strchr(respBuf.data(), ' ');
        if (code && code[1] == '2') {
            return true;
        }
    }

    if (m_verbose) {
        std::cerr << "[motel] Raw HTTP rejected response: " << respBuf.data() << "\n";
    }
    return false;
}

} // namespace OTel
