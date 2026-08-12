# Root-build integration layer for q=7933 host adapters.
#
# Keep BLNS7933Reference.cmake itself as the isolated math/reference build.
# This layer includes it first, then adds the thin mediator-facing adapters
# and their tests. The whole file is reached only through the q7933
# experimental preset; normal/default builds remain untouched.

# The root CMakeLists may include this layer again later. Under the
# blns7933-root preset this file has already run through CMAKE_PROJECT_INCLUDE,
# so make a second include a clean no-op.
include_guard(GLOBAL)

include("${CMAKE_CURRENT_LIST_DIR}/BLNS7933Reference.cmake")

if(NOT TRADEP2P_ENABLE_BLINDSIG_EXPERIMENTAL)
    return()
endif()

if(NOT TARGET tradep2p_blns7933_reference)
    message(FATAL_ERROR "BLNS7933Integration expected tradep2p_blns7933_reference target")
endif()

target_sources(tradep2p_blns7933_reference PRIVATE
    src/blindsig_ntru_q7933.cpp
    src/blindsig_keystore_q7933.cpp
    src/blindsig_ticket_store_q7933.cpp
)
# OpenSSL::Crypto is already linked PUBLIC by BLNS7933Reference.cmake
# (blindsig_blns7933_csprng.cpp's own CryptoRng needs it); this file's
# blindsig_keystore_q7933.cpp needs the same library, no new link needed.

add_executable(tradep2p_blns7933_ntru_adapter_tests
    tests/blindsig_ntru_q7933_tests.cpp
)
target_link_libraries(tradep2p_blns7933_ntru_adapter_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_ntru_adapter_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_ntru_adapter_tests
    COMMAND tradep2p_blns7933_ntru_adapter_tests)

add_executable(tradep2p_blns7933_keystore_tests
    tests/blindsig_keystore_q7933_tests.cpp
)
target_link_libraries(tradep2p_blns7933_keystore_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_keystore_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_keystore_tests
    COMMAND tradep2p_blns7933_keystore_tests)

add_executable(tradep2p_blns7933_ticket_store_tests
    tests/blindsig_ticket_store_q7933_tests.cpp
)
target_link_libraries(tradep2p_blns7933_ticket_store_tests PRIVATE
    tradep2p_blns7933_reference
)
target_compile_options(tradep2p_blns7933_ticket_store_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_ticket_store_tests
    COMMAND tradep2p_blns7933_ticket_store_tests)

# Pure q7933 wire-codec regression. Kept independent of the root tradep2p
# target so it stays cheap and can catch malformed/truncated codec bugs
# without dragging in the mediator or the q12289 Falcon backend.
add_executable(tradep2p_blns7933_wire_tests
    tests/blindsig_wire_q7933_tests.cpp
    src/blindsig_wire_q7933.cpp
)
target_include_directories(tradep2p_blns7933_wire_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_features(tradep2p_blns7933_wire_tests PRIVATE cxx_std_20)
target_compile_options(tradep2p_blns7933_wire_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)
add_test(NAME tradep2p_blns7933_wire_tests
    COMMAND tradep2p_blns7933_wire_tests)

# Phase 3 compile gate. The verifier/service call the existing blindsig
# subprocess layer and therefore do not belong inside the isolated math
# archive. This OBJECT target gives us an explicit cheap compile target even
# before running a whole mediator build.
add_library(tradep2p_blns7933_phase3_compile OBJECT
    src/blindsig_wire_q7933.cpp
    src/blindsig_signer_q7933.cpp
    src/blindsig_service_q7933.cpp
)
target_include_directories(tradep2p_blns7933_phase3_compile PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann-json
)
target_link_libraries(tradep2p_blns7933_phase3_compile PRIVATE
    tradep2p_blns7933_reference
)
target_compile_features(tradep2p_blns7933_phase3_compile PRIVATE cxx_std_20)
target_compile_options(tradep2p_blns7933_phase3_compile PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
)

# CMAKE_PROJECT_INCLUDE runs this file from project(), before the root
# CMakeLists has created its `tradep2p` target. Defer the actual attachment
# until the end of this directory instead of teaching the normal root build
# about q7933. This keeps the integration strictly additive to the q7933
# preset while letting lobby/main link the real Phase 3 implementation.
function(tradep2p_attach_blns7933_host_integration)
    if(NOT TARGET tradep2p)
        message(FATAL_ERROR "q7933 host integration expected the root tradep2p target")
    endif()
    target_sources(tradep2p PRIVATE
        src/blindsig_wire_q7933.cpp
        src/blindsig_signer_q7933.cpp
        src/blindsig_service_q7933.cpp
    )
    target_link_libraries(tradep2p PRIVATE tradep2p_blns7933_reference)
    target_compile_definitions(tradep2p PUBLIC TRADEP2P_ENABLE_BLNS7933_INTEGRATION=1)
endfunction()

cmake_language(DEFER CALL tradep2p_attach_blns7933_host_integration)
