cmake_minimum_required(VERSION 3.20)
project(TradeP2PMinimal VERSION 0.6.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

add_library(tradep2p
    src/protocol.cpp
    src/mediator.cpp
    src/secure_channel.cpp
    src/lobby.cpp
    src/registry.cpp
    src/dashboard_client.cpp
)
target_include_directories(tradep2p PUBLIC include)
target_link_libraries(tradep2p PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
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
target_link_libraries(tradep2p-mediator-dashboard PRIVATE Threads::Threads)
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
