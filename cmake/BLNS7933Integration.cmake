# Root-build integration layer for q=7933 host adapters.
#
# Keep BLNS7933Reference.cmake itself as the isolated math/reference build.
# This layer includes it first, then adds the thin mediator-facing adapters
# and their tests. Nothing here is added to the normal tradep2p target, and
# the whole file is still only reached through the experimental preset.

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
