# Isolated build integration for the q=7933 BLNS23 reference path.
#
# This deliberately does NOT add these sources to the main tradep2p library
# and does NOT wire the reference solver into BlindSigSigner/BlindSigKeystore.
# It only makes the reference library and its tests part of a normal root
# build when the existing experimental blind-signature feature gate is ON.

if(NOT TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL)
    return()
endif()

# This file may be injected immediately after project() through
# CMAKE_PROJECT_INCLUDE, before the root CMakeLists reaches its own
# enable_testing() call. Repeating enable_testing() later is harmless.
enable_testing()

include(CheckIncludeFileCXX)
check_include_file_cxx("boost/multiprecision/cpp_int.hpp"
    TRADEP2P_HAVE_BOOST_MULTIPRECISION_CPP_INT)
if(NOT TRADEP2P_HAVE_BOOST_MULTIPRECISION_CPP_INT)
    message(FATAL_ERROR
        "BLNS7933 reference path requires boost/multiprecision/cpp_int.hpp")
endif()

add_library(tradep2p_blns7933_reference STATIC
    src/blindsig_blns7933.cpp
    src/blindsig_blns7933_integer_ring.cpp
    src/blindsig_blns7933_ntrusolve.cpp
)
target_include_directories(tradep2p_blns7933_reference PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_features(tradep2p_blns7933_reference PUBLIC cxx_std_20)
target_compile_options(tradep2p_blns7933_reference PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_reference_tests
    tests/blindsig_blns7933_tests.cpp
)
target_link_libraries(tradep2p_blns7933_reference_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_reference_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_reference_tests
    COMMAND tradep2p_blns7933_reference_tests)

add_executable(tradep2p_blns7933_ntrusolve_tests
    tests/blindsig_blns7933_ntrusolve_tests.cpp
)
target_link_libraries(tradep2p_blns7933_ntrusolve_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_ntrusolve_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_ntrusolve_tests
    COMMAND tradep2p_blns7933_ntrusolve_tests)
