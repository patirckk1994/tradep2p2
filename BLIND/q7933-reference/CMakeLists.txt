cmake_minimum_required(VERSION 3.20)
project(tradep2p_blns7933_reference LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost REQUIRED)

add_library(tradep2p_blns7933_reference STATIC
    ../../src/blindsig_blns7933.cpp
    ../../src/blindsig_blns7933_integer_ring.cpp
    ../../src/blindsig_blns7933_ntrusolve.cpp
)
target_include_directories(tradep2p_blns7933_reference PUBLIC
    ../../include
    ${Boost_INCLUDE_DIRS}
)
target_compile_options(tradep2p_blns7933_reference PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_reference_tests
    ../../tests/blindsig_blns7933_tests.cpp
)
target_link_libraries(tradep2p_blns7933_reference_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_reference_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_ntrusolve_tests
    ../../tests/blindsig_blns7933_ntrusolve_tests.cpp
)
target_link_libraries(tradep2p_blns7933_ntrusolve_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_ntrusolve_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

enable_testing()
add_test(NAME tradep2p_blns7933_reference_tests COMMAND tradep2p_blns7933_reference_tests)
add_test(NAME tradep2p_blns7933_ntrusolve_tests COMMAND tradep2p_blns7933_ntrusolve_tests)
