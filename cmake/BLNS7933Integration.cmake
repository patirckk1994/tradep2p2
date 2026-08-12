# Root-build integration layer for q=7933 host adapters.
#
# Keep BLNS7933Reference.cmake itself as the isolated math/reference build.
# This layer includes it first, then adds the thin mediator-facing adapters
# and their tests. Nothing here is added to the normal tradep2p target, and
# the whole file is still only reached through the experimental preset.

# The root CMakeLists may include this layer again later when it wires the
# actual mediator target. Under the blns7933-root preset this file has already
# run through CMAKE_PROJECT_INCLUDE, so make that second include a clean no-op.
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

# Phase 3 compile gate. These two sources belong to the eventual `tradep2p`
# mediator target, not to the math/reference archive: the signer calls the
# existing blindsig subprocess layer and would create a circular static-link
# dependency if it were stuffed into tradep2p_blns7933_reference. An OBJECT
# target lets the experimental preset compile them now, under the project's
# full warning set, without pretending the root protocol/lobby wiring is done.
add_library(tradep2p_blns7933_phase3_compile OBJECT
    src/blindsig_wire_q7933.cpp
    src/blindsig_signer_q7933.cpp
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
