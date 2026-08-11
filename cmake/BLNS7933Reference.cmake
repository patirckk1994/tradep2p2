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
check_include_file_cxx("boost/multiprecision/cpp_dec_float.hpp"
    TRADEP2P_HAVE_BOOST_MULTIPRECISION_CPP_DEC_FLOAT)
if(NOT TRADEP2P_HAVE_BOOST_MULTIPRECISION_CPP_DEC_FLOAT)
    message(FATAL_ERROR
        "BLNS7933 global reducer requires boost/multiprecision/cpp_dec_float.hpp")
endif()

add_library(tradep2p_blns7933_reference STATIC
    src/blindsig_blns7933.cpp
    src/blindsig_blns7933_integer_ring.cpp
    src/blindsig_blns7933_ntrusolve.cpp
    src/blindsig_blns7933_reduce.cpp
    src/blindsig_blns7933_babai_reduce.cpp
    src/blindsig_blns7933_gaussian.cpp
    src/blindsig_blns7933_quality.cpp
    src/blindsig_blns7933_real_ring.cpp
    src/blindsig_blns7933_ldl.cpp
    src/blindsig_blns7933_sampling.cpp
    src/blindsig_blns7933_sign.cpp
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

add_executable(tradep2p_blns7933_reduce_tests
    tests/blindsig_blns7933_reduce_tests.cpp
)
target_link_libraries(tradep2p_blns7933_reduce_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_reduce_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_reduce_tests
    COMMAND tradep2p_blns7933_reduce_tests)

add_executable(tradep2p_blns7933_babai_reduce_tests
    tests/blindsig_blns7933_babai_reduce_tests.cpp
)
target_link_libraries(tradep2p_blns7933_babai_reduce_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_babai_reduce_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_babai_reduce_tests
    COMMAND tradep2p_blns7933_babai_reduce_tests)

add_executable(tradep2p_blns7933_gaussian_tests
    tests/blindsig_blns7933_gaussian_tests.cpp
)
target_link_libraries(tradep2p_blns7933_gaussian_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_gaussian_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_gaussian_tests
    COMMAND tradep2p_blns7933_gaussian_tests)

add_executable(tradep2p_blns7933_quality_tests
    tests/blindsig_blns7933_quality_tests.cpp
)
target_link_libraries(tradep2p_blns7933_quality_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_quality_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_quality_tests
    COMMAND tradep2p_blns7933_quality_tests)

add_executable(tradep2p_blns7933_real_ring_tests
    tests/blindsig_blns7933_real_ring_tests.cpp
)
target_link_libraries(tradep2p_blns7933_real_ring_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_real_ring_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_real_ring_tests
    COMMAND tradep2p_blns7933_real_ring_tests)

add_executable(tradep2p_blns7933_ldl_tests
    tests/blindsig_blns7933_ldl_tests.cpp
)
target_link_libraries(tradep2p_blns7933_ldl_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_ldl_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_ldl_tests
    COMMAND tradep2p_blns7933_ldl_tests)

add_executable(tradep2p_blns7933_sign_tests
    tests/blindsig_blns7933_sign_tests.cpp
)
target_link_libraries(tradep2p_blns7933_sign_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_sign_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_sign_tests
    COMMAND tradep2p_blns7933_sign_tests)

# Manual diagnostics target: deliberately not a CTest test. It compares the
# exact coordinate baseline against the high-precision global reduction at
# d=16/32/64 only and must be invoked explicitly.
add_executable(tradep2p_blns7933_scaling_diagnostics
    BLIND/q7933-reference/scaling_diagnostics.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_diagnostics PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_diagnostics PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

# Explicit next-size gates. These deliberately skip the direct 64-pass
# coordinate baseline and measure NTRUSolve -> global Babai -> exact cleanup
# for one deterministic candidate only. They are manual-only so normal CTest
# runs stay cheap and cannot accidentally become scaling benchmarks.
add_executable(tradep2p_blns7933_scaling_128_diagnostic
    BLIND/q7933-reference/scaling_128_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_128_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_128_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_scaling_256_diagnostic
    BLIND/q7933-reference/scaling_256_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_256_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_256_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

# Actual BLNS23 ring-size machinery gate. This is still a single deterministic
# anchor, not TrapGen sampling, and remains manual-only.
add_executable(tradep2p_blns7933_scaling_512_diagnostic
    BLIND/q7933-reference/scaling_512_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_512_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_512_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

# Reproducible small-coefficient corpus. Candidate rejection is diagnostic
# output, not a CTest failure; accepted candidates retain strict exact
# relation/norm invariants through global reduction and cleanup.
add_executable(tradep2p_blns7933_corpus_diagnostics
    BLIND/q7933-reference/corpus_diagnostics.cpp
)
target_link_libraries(tradep2p_blns7933_corpus_diagnostics PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_corpus_diagnostics PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

# TrapGen candidate-generation diagnostic (Gaussian sampling -> invertibility
# -> quality bound -> NTRUSolve -> reduce), with per-attempt rejection
# visibility. Manual-only, same reasoning as the scaling diagnostics above.
add_executable(tradep2p_blns7933_trapgen_diagnostic
    BLIND/q7933-reference/trapgen_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_trapgen_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_trapgen_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_sign_diagnostic
    BLIND/q7933-reference/sign_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_sign_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_sign_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_sign_512_diagnostic
    BLIND/q7933-reference/sign_512_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_sign_512_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_sign_512_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
