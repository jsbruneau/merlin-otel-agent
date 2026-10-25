#include "platform/SubprocessRunner.h"
#include <array>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace Platform {

static int64_t monotonicMs() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000LL + static_cast<int64_t>(ts.tv_nsec) / 1000000LL;
}

static bool isSafeBareBinaryName(const std::string& name) {
    if (name.empty() || name == "." || name == "..") return false;
    for (unsigned char c : name) {
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
            return false;
        }
    }
    return true;
}

static std::vector<std::string> buildTrustedCandidates(const std::string& bin) {
    static const std::array<const char*, 5> kTrustedDirs = {
        "/usr/sbin/",
        "/sbin/",
        "/usr/bin/",
        "/bin/",
        "/jffs/bin/"
    };

    std::vector<std::string> candidates;
    if (bin.empty() || bin.find("..") != std::string::npos) {
        return candidates;
    }

    if (bin.find('/') != std::string::npos) {
        for (const char* dir : kTrustedDirs) {
            std::string prefix(dir);
            if (bin.rfind(prefix, 0) == 0) {
                std::string leaf = bin.substr(prefix.size());
                if (isSafeBareBinaryName(leaf)) {
                    candidates.push_back(bin);
                }
                break;
            }
        }
        return candidates;
    }

    if (!isSafeBareBinaryName(bin)) {
        return candidates;
    }

    candidates.reserve(kTrustedDirs.size());
    for (const char* dir : kTrustedDirs) {
        candidates.push_back(std::string(dir) + bin);
    }
    return candidates;
}

static void drainFdNonBlocking(int fd, std::string& dest) {
    if (fd < 0) return;
    std::array<char, 1024> buf{};
    while (true) {
        ssize_t n = read(fd, buf.data(), buf.size());
        if (n > 0) {
            dest.append(buf.data(), static_cast<size_t>(n));
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
}

SubprocessResult SubprocessRunner::run(const std::vector<std::string>& argv, int timeoutMs) {
    SubprocessResult result;
    if (argv.empty() || argv[0].empty()) return result;

    auto candidates = buildTrustedCandidates(argv[0]);
    if (candidates.empty()) {
        result.exitCode = 127;
        return result;
    }

    int outPipe[2]{-1, -1};
    int errPipe[2]{-1, -1};
    if (pipe2(outPipe, O_CLOEXEC) != 0) return result;
    if (pipe2(errPipe, O_CLOEXEC) != 0) {
        close(outPipe[0]);
        close(outPipe[1]);
        return result;
    }

    std::vector<std::string> mutableArgs = argv;
    std::vector<char*> cArgs;
    cArgs.reserve(mutableArgs.size() + 1);
    for (auto& s : mutableArgs) {
        cArgs.push_back(s.data());
    }
    cArgs.push_back(nullptr);

    char pathEnv[] = "PATH=/usr/sbin:/sbin:/usr/bin:/bin";
    char* cleanEnv[] = {pathEnv, nullptr};

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, errPipe[1], STDERR_FILENO);

    pid_t pid = -1;
    int spawnErr = ENOENT;
    for (const auto& candidate : candidates) {
        spawnErr = posix_spawn(&pid, candidate.c_str(), &actions, nullptr, cArgs.data(), cleanEnv);
        if (spawnErr == 0) {
            break;
        }
    }
    posix_spawn_file_actions_destroy(&actions);

    close(outPipe[1]);
    close(errPipe[1]);

    if (spawnErr != 0 || pid < 0) {
        close(outPipe[0]);
        close(errPipe[0]);
        result.exitCode = 127;
        return result;
    }

    fcntl(outPipe[0], F_SETFL, O_NONBLOCK);
    fcntl(errPipe[0], F_SETFL, O_NONBLOCK);

    struct pollfd fds[2]{};
    fds[0].fd = outPipe[0];
    fds[0].events = POLLIN;
    fds[1].fd = errPipe[0];
    fds[1].events = POLLIN;

    int64_t deadlineMs = monotonicMs() + (timeoutMs > 0 ? timeoutMs : 1);

    while (true) {
        int64_t now = monotonicMs();
        if (now >= deadlineMs) break;

        if (fds[0].fd >= 0 || fds[1].fd >= 0) {
            int waitSlice = static_cast<int>(deadlineMs - now);
            if (waitSlice > 50) waitSlice = 50;
            int ret = poll(fds, 2, waitSlice);
            if (ret > 0) {
                for (int i = 0; i < 2; ++i) {
                    if (fds[i].fd < 0) continue;
                    std::string& target = (i == 0) ? result.stdoutData : result.stderrData;
                    if (fds[i].revents & POLLIN) {
                        std::array<char, 1024> chunk{};
                        ssize_t n = read(fds[i].fd, chunk.data(), chunk.size());
                        if (n > 0) {
                            target.append(chunk.data(), static_cast<size_t>(n));
                        } else if (n == 0) {
                            close(fds[i].fd);
                            fds[i].fd = -1;
                        }
                    } else if (fds[i].revents & (POLLHUP | POLLERR)) {
                        drainFdNonBlocking(fds[i].fd, target);
                        close(fds[i].fd);
                        fds[i].fd = -1;
                    }
                }
            }
        } else {
            usleep(10000);
        }

        int status = 0;
        pid_t p = waitpid(pid, &status, WNOHANG);
        if (p == pid) {
            drainFdNonBlocking(fds[0].fd, result.stdoutData);
            drainFdNonBlocking(fds[1].fd, result.stderrData);
            if (fds[0].fd >= 0) close(fds[0].fd);
            if (fds[1].fd >= 0) close(fds[1].fd);

            if (WIFEXITED(status)) {
                result.exitCode = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                result.exitCode = 128 + WTERMSIG(status);
            }
            return result;
        }
    }

    if (fds[0].fd >= 0) close(fds[0].fd);
    if (fds[1].fd >= 0) close(fds[1].fd);

    result.timedOut = true;
    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
    return result;
}

} // namespace Platform
