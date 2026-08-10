/* TradeP2P mediator fee-plugin ABI (Mode B: in-process, dlopen'd).
 *
 * Plain C, not C++: C++ has no stable ABI across independently compiled
 * shared objects (name mangling, exception handling, standard library
 * version), so this is the only interface a plugin built with a different
 * compiler/toolchain than the mediator itself can still safely implement.
 * A plugin .so exports the two functions below via extern "C" (or, if
 * written in C, simply by including this header) and is loaded via
 * TRADEP2P_FEE_PLUGIN_PATH - see lobby.cpp's fee_plugin_thread_ and
 * plugins/README.md for the full contract, including the one real,
 * unavoidable cost of this mode: a crashing or hanging plugin takes the
 * whole mediator process down with it, since it runs on the mediator's
 * own thread in the mediator's own address space. Operators who want
 * process isolation instead should use Mode A (plugins/README.md's
 * admin-channel protocol) rather than this header.
 */
#ifndef TRADEP2P_FEE_PLUGIN_ABI_H
#define TRADEP2P_FEE_PLUGIN_ABI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bumped on any incompatible change to the struct layout or the meaning
 * of either function below. tradep2p_fee_plugin_abi_version() must return
 * exactly this value for the mediator's build - a mismatch fails mediator
 * startup loudly (refuses to load the plugin at all) rather than risking
 * a silent struct-layout mismatch across dlopen. */
#define TRADEP2P_FEE_PLUGIN_ABI_VERSION 1

typedef struct {
    /* Lowercase hex, no separators - see protocol.hpp's room_id_to_hex(). */
    const char* room_id_hex;
    const char* asset;
    uint64_t amount;
    const char* address;
    /* Unix timestamp (seconds) of the moment this room first started
     * waiting for fee confirmation - see RoomEntry::fee_confirmation_
     * pending_since in lobby.cpp. */
    uint64_t since_unix_seconds;
} tradep2p_fee_check_request;

/* Must return TRADEP2P_FEE_PLUGIN_ABI_VERSION exactly. Called once, right
 * after dlopen/dlsym, before the mediator ever calls
 * tradep2p_fee_plugin_check(). */
int tradep2p_fee_plugin_abi_version(void);

/* Called once per pending fee, once per poll interval, by the mediator's
 * own dedicated polling thread - never concurrently with itself (one
 * thread, one call in flight at a time), but free to block on whatever
 * I/O it needs (a chain RPC call, etc) for as long as that takes; it
 * simply delays that poll's remaining rooms and the next poll.
 * `request` and every string it points to are valid only for the
 * duration of this call - the mediator owns that memory and may free or
 * reuse it immediately after this function returns, so a plugin that
 * needs a value afterward must copy it.
 *
 * Return:
 *    1  fee has been confirmed paid - the mediator confirms the room's
 *       fee leg and completes it exactly as an operator typing CONFIRMFEE
 *       would.
 *    0  not paid yet (or not yet confirmable) - tried again next poll.
 *   -1  the plugin could not determine an answer this time (e.g. an RPC
 *       call failed) - treated identically to 0, tried again next poll,
 *       never treated as an implicit confirmation. */
int tradep2p_fee_plugin_check(const tradep2p_fee_check_request* request);

#ifdef __cplusplus
}
#endif

#endif /* TRADEP2P_FEE_PLUGIN_ABI_H */
