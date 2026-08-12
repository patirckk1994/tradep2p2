cmake_minimum_required(VERSION 3.20)
# C is needed only for third_party/falcon-impl-20211101/ (vendored FALCON
# reference source, built by tradep2p_falcon_vendor below) - everything
# else in this project is C++20.
project(TradeP2PMinimal VERSION 0.6.1 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)
include(GNUInstallDirs)

# Experimental post-quantum blind-signature primitive (specs.txt SS9.3a).
# OFF by default - this is this codebase's first compile-time feature
# gate, deliberately a stricter bar than every other optional feature
# here (security tiers, fee plugin), which are runtime-gated only. This
# is unreviewed novel cryptography (see BLIND/REVIEW_REQUEST.md); turning
# this ON is a separate, explicit decision from anything else in this
# project, and a mediator/client built without it has zero trace of the
# feature - no wire types dispatched, no extra dependency surface
# (nlohmann/json, the vendored FALCON C source), no subprocess-spawning
# code path compiled in at all. Requires a separately-built Rust sidecar
# (blindsig-prover/, cargo build --release) - not built by this CMake
# configure step; the compiled binary's path is supplied at runtime via
# TRADEP2P_BLINDSIG_PROVER_PATH. Also off at runtime unless
# TRADEP2P_BLINDSIG_ENABLE=1 is separately set - see lobby.cpp/main.cpp.
option(TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL
    "Compile in the experimental, unreviewed post-quantum blind-signature primitive (specs.txt SS9.3a)"
    OFF)

# Declared unconditionally (10 small vendored .c files, no dependencies of
# its own beyond libc/libm - cheap to configure even when unused) but
# only ever linked into `tradep2p` when the option above is ON.
add_library(tradep2p_falcon_vendor STATIC
    third_party/falcon-impl-20211101/codec.c
    third_party/falcon-impl-20211101/common.c
    third_party/falcon-impl-20211101/falcon.c
    third_party/falcon-impl-20211101/fft.c
    third_party/falcon-impl-20211101/fpr.c
    third_party/falcon-impl-20211101/keygen.c
    third_party/falcon-impl-20211101/rng.c
    third_party/falcon-impl-20211101/shake.c
    third_party/falcon-impl-20211101/sign.c
    third_party/falcon-impl-20211101/vrfy.c
)
target_include_directories(tradep2p_falcon_vendor PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/falcon-impl-20211101>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/tradep2p-falcon-impl-20211101>
)
target_compile_options(tradep2p_falcon_vendor PRIVATE -O2)

add_library(tradep2p
    src/protocol.cpp
    src/mediator.cpp
    src/secure_channel.cpp
    src/lobby.cpp
    src/registry.cpp
    src/dashboard_client.cpp
    src/identity.cpp
    src/keystore.cpp
    src/journal.cpp
    src/room_persistence.cpp
    src/recovery.cpp
    src/history.cpp
    src/recognition.cpp
    src/mediator_auth.cpp
    src/ephemeral.cpp
    src/receipt.cpp
    src/login.cpp
    src/disclosure.cpp
)
add_library(tradep2p::tradep2p ALIAS tradep2p)
# BUILD_INTERFACE/INSTALL_INTERFACE split is required for this target to be
# install()/export()-able - a bare relative path only resolves correctly
# for in-tree consumers, and CMake refuses to export it as-is.
target_include_directories(tradep2p PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(tradep2p PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS})
target_compile_options(tradep2p PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

if(TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL)
    if(NOT TARGET tradep2p_blns7933_reference)
        include(${CMAKE_SOURCE_DIR}/cmake/BLNS7933Integration.cmake)
    endif()
    target_sources(tradep2p PRIVATE
        src/blindsig_wire.cpp
        src/blindsig_wire_q7933.cpp
        src/blindsig_falcon.cpp
        src/blindsig_keystore.cpp
        src/blindsig_subprocess.cpp
        src/blindsig_signer.cpp
        src/blindsig_signer_q7933.cpp
        src/blindsig_client.cpp
        src/blindsig_client_q7933.cpp
        src/q7933_credential.cpp
        src/q7933_issuance_store.cpp
        src/q7933_presentation.cpp
    )
    target_link_libraries(tradep2p PRIVATE tradep2p_falcon_vendor)
    target_link_libraries(tradep2p PUBLIC tradep2p_blns7933_reference)
    target_include_directories(tradep2p PRIVATE third_party/nlohmann-json)
    target_compile_definitions(tradep2p PUBLIC TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL=1)
endif()

add_executable(tradep2p_cli src/main.cpp)
target_link_libraries(tradep2p_cli PRIVATE tradep2p)
target_compile_options(tradep2p_cli PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p-dashboard src/http_dashboard.cpp)
target_include_directories(tradep2p-dashboard PRIVATE
    ${CMAKE_SOURCE_DIR}/cpp-httplib-master
)
target_link_libraries(tradep2p-dashboard PRIVATE tradep2p Threads::Threads)
target_compile_features(tradep2p-dashboard PRIVATE cxx_std_20)
target_compile_options(tradep2p-dashboard PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p-webclient src/http_webclient.cpp)
target_include_directories(tradep2p-webclient PRIVATE
    ${CMAKE_SOURCE_DIR}/cpp-httplib-master
)
target_link_libraries(tradep2p-webclient PRIVATE tradep2p Threads::Threads)
target_compile_features(tradep2p-webclient PRIVATE cxx_std_20)
target_compile_options(tradep2p-webclient PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p-mediator-dashboard src/http_mediator_dashboard.cpp)
target_include_directories(tradep2p-mediator-dashboard PRIVATE
    ${CMAKE_SOURCE_DIR}/cpp-httplib-master
)
target_link_libraries(tradep2p-mediator-dashboard PRIVATE OpenSSL::Crypto Threads::Threads)
target_compile_features(tradep2p-mediator-dashboard PRIVATE cxx_std_20)
target_compile_options(tradep2p-mediator-dashboard PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p-registry-dashboard src/http_registry_dashboard.cpp)
target_include_directories(tradep2p-registry-dashboard PRIVATE
    ${CMAKE_SOURCE_DIR}/cpp-httplib-master
)
target_link_libraries(tradep2p-registry-dashboard PRIVATE tradep2p Threads::Threads)
target_compile_features(tradep2p-registry-dashboard PRIVATE cxx_std_20)
target_compile_options(tradep2p-registry-dashboard PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

enable_testing()
add_executable(tradep2p_unit_tests tests/protocol_tests.cpp)
target_link_libraries(tradep2p_unit_tests PRIVATE tradep2p)
target_compile_options(tradep2p_unit_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_unit_tests COMMAND tradep2p_unit_tests)

add_executable(tradep2p_identity_tests tests/identity_tests.cpp)
target_link_libraries(tradep2p_identity_tests PRIVATE tradep2p)
target_compile_options(tradep2p_identity_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_identity_tests COMMAND tradep2p_identity_tests)

add_executable(tradep2p_keystore_tests tests/keystore_tests.cpp)
target_link_libraries(tradep2p_keystore_tests PRIVATE tradep2p)
target_compile_options(tradep2p_keystore_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_keystore_tests COMMAND tradep2p_keystore_tests)

add_executable(tradep2p_journal_tests tests/journal_tests.cpp)
target_link_libraries(tradep2p_journal_tests PRIVATE tradep2p)
target_compile_options(tradep2p_journal_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_journal_tests COMMAND tradep2p_journal_tests)

add_executable(tradep2p_recovery_tests tests/recovery_tests.cpp)
target_link_libraries(tradep2p_recovery_tests PRIVATE tradep2p)
target_compile_options(tradep2p_recovery_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_recovery_tests COMMAND tradep2p_recovery_tests)

add_executable(tradep2p_history_tests tests/history_tests.cpp)
target_link_libraries(tradep2p_history_tests PRIVATE tradep2p)
target_compile_options(tradep2p_history_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_history_tests COMMAND tradep2p_history_tests)

add_executable(tradep2p_recognition_tests tests/recognition_tests.cpp)
target_link_libraries(tradep2p_recognition_tests PRIVATE tradep2p)
target_compile_options(tradep2p_recognition_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_recognition_tests COMMAND tradep2p_recognition_tests)

add_executable(tradep2p_ephemeral_tests tests/ephemeral_tests.cpp)
target_link_libraries(tradep2p_ephemeral_tests PRIVATE tradep2p)
target_compile_options(tradep2p_ephemeral_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_ephemeral_tests COMMAND tradep2p_ephemeral_tests)

add_executable(tradep2p_receipt_tests tests/receipt_tests.cpp)
target_link_libraries(tradep2p_receipt_tests PRIVATE tradep2p)
target_compile_options(tradep2p_receipt_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_receipt_tests COMMAND tradep2p_receipt_tests)

add_executable(tradep2p_login_tests tests/login_tests.cpp)
target_link_libraries(tradep2p_login_tests PRIVATE tradep2p)
target_compile_options(tradep2p_login_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_login_tests COMMAND tradep2p_login_tests)

add_executable(tradep2p_disclosure_tests tests/disclosure_tests.cpp)
target_link_libraries(tradep2p_disclosure_tests PRIVATE tradep2p)
target_compile_options(tradep2p_disclosure_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_disclosure_tests COMMAND tradep2p_disclosure_tests)

add_executable(tradep2p_mediator_auth_tests tests/mediator_auth_tests.cpp)
target_link_libraries(tradep2p_mediator_auth_tests PRIVATE tradep2p)
target_compile_options(tradep2p_mediator_auth_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_mediator_auth_tests COMMAND tradep2p_mediator_auth_tests)

if(TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL)
    # Exception to this codebase's live-verify-only precedent for new
    # network features (specs.txt SS9.3a) - the wire codec and keystore
    # are pure, fast, deterministic, and specifically the parts exposed
    # to a hostile network peer or an on-disk file, unlike the zkVM
    # proving/verifying and subprocess/queue behavior, which stay
    # live-verify-only (slow, external-toolchain-dependent).
    add_executable(tradep2p_blindsig_wire_tests tests/blindsig_wire_tests.cpp)
    target_link_libraries(tradep2p_blindsig_wire_tests PRIVATE tradep2p)
    target_compile_options(tradep2p_blindsig_wire_tests PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    )
    add_test(NAME tradep2p_blindsig_wire_tests COMMAND tradep2p_blindsig_wire_tests)

    add_executable(tradep2p_blindsig_wire_q7933_tests tests/blindsig_wire_q7933_tests.cpp)
    target_link_libraries(tradep2p_blindsig_wire_q7933_tests PRIVATE tradep2p)
    target_compile_options(tradep2p_blindsig_wire_q7933_tests PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    )
    add_test(NAME tradep2p_blindsig_wire_q7933_tests COMMAND tradep2p_blindsig_wire_q7933_tests)

    add_executable(tradep2p_blindsig_keystore_tests tests/blindsig_keystore_tests.cpp)
    target_link_libraries(tradep2p_blindsig_keystore_tests PRIVATE tradep2p)
    target_compile_options(tradep2p_blindsig_keystore_tests PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    )
    add_test(NAME tradep2p_blindsig_keystore_tests COMMAND tradep2p_blindsig_keystore_tests)

    add_executable(tradep2p_q7933_credential_tests tests/q7933_credential_tests.cpp)
    target_link_libraries(tradep2p_q7933_credential_tests PRIVATE tradep2p)
    target_compile_options(tradep2p_q7933_credential_tests PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    )
    add_test(NAME tradep2p_q7933_credential_tests COMMAND tradep2p_q7933_credential_tests)
endif()

# ---------------------------------------------------------------------------
# Library packaging: makes `tradep2p` consumable by a SEPARATE, external
# project via find_package(tradep2p) - e.g. a future standalone MCP server
# that links directly against the protocol/crypto/identity core instead of
# shelling out to tradep2p_cli or re-parsing its JSON state snapshots.
# Every binary/test target above already builds against this exact library
# in-tree; this section only adds the install/export machinery, it changes
# nothing about how those in-tree targets are built.
#
# `cmake --install build --prefix /some/prefix` installs the static library,
# every public header under include/tradep2p/, and a tradep2pConfig.cmake +
# tradep2pConfigVersion.cmake pair, so a downstream project's own
# CMakeLists.txt can do:
#   find_package(tradep2p REQUIRED)
#   target_link_libraries(my_tool PRIVATE tradep2p::tradep2p)
# and get the library, its OpenSSL/Threads public dependencies, and the full
# header set, without needing to live inside this source tree.
# ---------------------------------------------------------------------------

# tradep2p_falcon_vendor rides along in the same export set as tradep2p
# itself - required because tradep2p privately links it whenever
# TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL is on, and CMake requires every
# target a to-be-exported target links (even PRIVATE) to itself be part
# of an export set. When the q=7933 reference target exists, export it
# alongside the main library; when the experimental option is off, it may
# not exist at all, so build the install target list conditionally.
set(tradep2p_install_targets tradep2p tradep2p_falcon_vendor)
if(TARGET tradep2p_blns7933_reference)
    list(APPEND tradep2p_install_targets tradep2p_blns7933_reference)
endif()
install(TARGETS ${tradep2p_install_targets}
    EXPORT tradep2pTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/tradep2p
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)
install(DIRECTORY third_party/falcon-impl-20211101/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tradep2p-falcon-impl-20211101
    FILES_MATCHING PATTERN "*.h"
)
install(EXPORT tradep2pTargets
    FILE tradep2pTargets.cmake
    NAMESPACE tradep2p::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tradep2p
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tradep2pConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/tradep2pConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tradep2p
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/tradep2pConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/tradep2pConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/tradep2pConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tradep2p
)
