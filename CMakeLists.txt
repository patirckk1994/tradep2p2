cmake_minimum_required(VERSION 3.20)
project(TradeP2PMinimal VERSION 0.6.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)
include(GNUInstallDirs)

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

install(TARGETS tradep2p
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
