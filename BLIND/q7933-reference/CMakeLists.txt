cmake_minimum_required(VERSION 3.20)
project(tradep2p_blns7933_reference LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost REQUIRED)

find_package(OpenSSL REQUIRED)

add_library(tradep2p_blns7933_reference STATIC
    ../../src/blindsig_blns7933.cpp
    ../../src/blindsig_blns7933_integer_ring.cpp
    ../../src/blindsig_blns7933_ntrusolve.cpp
    ../../src/blindsig_blns7933_reduce.cpp
    ../../src/blindsig_blns7933_babai_reduce.cpp
    ../../src/blindsig_blns7933_gaussian.cpp
    ../../src/blindsig_blns7933_quality.cpp
    ../../src/blindsig_blns7933_real_ring.cpp
    ../../src/blindsig_blns7933_ldl.cpp
    ../../src/blindsig_blns7933_sampling.cpp
    ../../src/blindsig_blns7933_sign.cpp
    ../../src/blindsig_blns7933_csprng.cpp
)
target_include_directories(tradep2p_blns7933_reference PUBLIC
    ../../include
    ${Boost_INCLUDE_DIRS}
)
target_link_libraries(tradep2p_blns7933_reference PUBLIC OpenSSL::Crypto)
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

add_executable(tradep2p_blns7933_reduce_tests
    ../../tests/blindsig_blns7933_reduce_tests.cpp
)
target_link_libraries(tradep2p_blns7933_reduce_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_reduce_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_babai_reduce_tests
    ../../tests/blindsig_blns7933_babai_reduce_tests.cpp
)
target_link_libraries(tradep2p_blns7933_babai_reduce_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_babai_reduce_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_gaussian_tests
    ../../tests/blindsig_blns7933_gaussian_tests.cpp
)
target_link_libraries(tradep2p_blns7933_gaussian_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_gaussian_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_quality_tests
    ../../tests/blindsig_blns7933_quality_tests.cpp
)
target_link_libraries(tradep2p_blns7933_quality_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_quality_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_real_ring_tests
    ../../tests/blindsig_blns7933_real_ring_tests.cpp
)
target_link_libraries(tradep2p_blns7933_real_ring_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_real_ring_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_ldl_tests
    ../../tests/blindsig_blns7933_ldl_tests.cpp
)
target_link_libraries(tradep2p_blns7933_ldl_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_ldl_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_sign_tests
    ../../tests/blindsig_blns7933_sign_tests.cpp
)
target_link_libraries(tradep2p_blns7933_sign_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_sign_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_csprng_tests
    ../../tests/blindsig_blns7933_csprng_tests.cpp
)
target_link_libraries(tradep2p_blns7933_csprng_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_csprng_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

# Manual diagnostics: deliberately NOT registered with CTest.
add_executable(tradep2p_blns7933_scaling_diagnostics
    scaling_diagnostics.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_diagnostics PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_diagnostics PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_scaling_128_diagnostic
    scaling_128_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_128_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_128_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_scaling_256_diagnostic
    scaling_256_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_256_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_256_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_scaling_512_diagnostic
    scaling_512_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_scaling_512_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_scaling_512_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_corpus_diagnostics
    corpus_diagnostics.cpp
)
target_link_libraries(tradep2p_blns7933_corpus_diagnostics PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_corpus_diagnostics PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_trapgen_diagnostic
    trapgen_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_trapgen_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_trapgen_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_sign_diagnostic
    sign_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_sign_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_sign_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_sign_512_diagnostic
    sign_512_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_sign_512_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_sign_512_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_distribution_diagnostic
    distribution_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_distribution_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_distribution_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

add_executable(tradep2p_blns7933_distribution_512_diagnostic
    distribution_512_diagnostic.cpp
)
target_link_libraries(tradep2p_blns7933_distribution_512_diagnostic PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_distribution_512_diagnostic PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

enable_testing()
add_test(NAME tradep2p_blns7933_reference_tests COMMAND tradep2p_blns7933_reference_tests)
add_test(NAME tradep2p_blns7933_ntrusolve_tests COMMAND tradep2p_blns7933_ntrusolve_tests)
add_test(NAME tradep2p_blns7933_reduce_tests COMMAND tradep2p_blns7933_reduce_tests)
add_test(NAME tradep2p_blns7933_babai_reduce_tests COMMAND tradep2p_blns7933_babai_reduce_tests)
add_test(NAME tradep2p_blns7933_gaussian_tests COMMAND tradep2p_blns7933_gaussian_tests)
add_test(NAME tradep2p_blns7933_quality_tests COMMAND tradep2p_blns7933_quality_tests)
add_test(NAME tradep2p_blns7933_real_ring_tests COMMAND tradep2p_blns7933_real_ring_tests)
add_test(NAME tradep2p_blns7933_ldl_tests COMMAND tradep2p_blns7933_ldl_tests)
add_test(NAME tradep2p_blns7933_sign_tests COMMAND tradep2p_blns7933_sign_tests)
add_test(NAME tradep2p_blns7933_csprng_tests COMMAND tradep2p_blns7933_csprng_tests)
