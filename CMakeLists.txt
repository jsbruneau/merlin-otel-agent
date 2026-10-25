cmake_minimum_required(VERSION 3.20)
project(merlin-otel-agent VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(MOTEL_BUILD_STATIC "Link static binary for Asuswrt-Merlin" ON)
option(MOTEL_BUILD_COLLECTORS "Build router collectors, daemon, and tests (disable in Docker Layer 2)" ON)
option(MOTEL_BUILD_TESTS "Build unit test suite" ON)

# Size and footprint optimization flags for embedded router deployment
add_compile_options(
    -Wall
    -Wextra
    -Wno-unused-parameter
    -ffunction-sections
    -fdata-sections
)

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    add_compile_options(-Os -fno-ident)
    add_link_options(-Wl,--gc-sections -s)
endif()

find_package(Threads REQUIRED)

# -----------------------------------------------------------------------------
# Target 1: OTel Embedded Core + Platform Layer (Built & cached in Docker Layer 3)
# -----------------------------------------------------------------------------
set(OTEL_EMBEDDED_SOURCES
    src/Config.cpp
    src/otel/OtelProtoEncoder.cpp
    src/otel/OtelMetrics.cpp
    src/otel/OtelLogger.cpp
    src/otel/OtelSender.cpp
    src/platform/IpClassifier.cpp
    src/platform/SubprocessRunner.cpp
)

add_library(otel_embedded_core STATIC ${OTEL_EMBEDDED_SOURCES})
target_compile_definitions(otel_embedded_core PUBLIC MOTEL_VERSION="${PROJECT_VERSION}")
target_include_directories(otel_embedded_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(otel_embedded_core PUBLIC Threads::Threads)

# -----------------------------------------------------------------------------
# Target 2: Broadcom / Merlin Collectors, Daemon & Tests (Built in Docker Layer 4)
# -----------------------------------------------------------------------------
if(MOTEL_BUILD_COLLECTORS)
    set(MOTEL_COLLECTOR_SOURCES
        src/collectors/HostMetricsCollector.cpp
        src/collectors/NetInterfaceCollector.cpp
        src/collectors/BcmFlowCacheCollector.cpp
        src/collectors/BcmArcherCollector.cpp
        src/collectors/BcmWifiCollector.cpp
        src/collectors/SyslogTailer.cpp
        src/collectors/NetlinkConntrackCollector.cpp
    )

    add_library(motel_collectors STATIC ${MOTEL_COLLECTOR_SOURCES})
    target_include_directories(motel_collectors PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(motel_collectors PUBLIC otel_embedded_core)

    add_executable(merlin-otel-agent src/main.cpp)
    target_link_libraries(merlin-otel-agent PRIVATE motel_collectors)

    if(MOTEL_BUILD_STATIC)
        target_link_options(merlin-otel-agent PRIVATE -static)
    endif()

    if(MOTEL_BUILD_TESTS)
        enable_testing()
        add_executable(test_collectors tests/test_collectors.cpp)
        target_link_libraries(test_collectors PRIVATE motel_collectors)
        if(MOTEL_BUILD_STATIC)
            target_link_options(test_collectors PRIVATE -static)
        endif()
        add_test(NAME test_collectors COMMAND test_collectors)
    endif()
endif()
