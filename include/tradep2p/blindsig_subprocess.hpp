#pragma once

// Safe subprocess execution of the blindsig-prover sidecar CLI. This is
// the first code path in this codebase's history that shells out to an
// external process at all - see specs.txt SS9.3a for why a sidecar
// process rather than an FFI/embedded dependency.
//
// Uses posix_spawn, not fork()+exec(): LobbyServer is heavily
// multi-threaded (snapshot thread, fee-plugin thread, per-client
// threads), and a bare fork() from a multithreaded process only
// duplicates the calling thread - if another thread held a malloc/libc
// lock at the moment of fork(), the child can deadlock before it ever
// reaches exec(). posix_spawn avoids that whole class of bug by
// construction and is the standard glibc-recommended primitive for
// exactly this situation.

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace tradep2p::blindsig {

struct SidecarResult {
    // -1 if the process was killed (timed_out=true) or never started
    // (spawn_error non-empty); the child's actual exit code otherwise.
    int exit_code{-1};
    bool timed_out{false};
    std::string stdout_text;
    std::string stderr_text;
    // Non-empty ONLY if the subprocess could not even be started/waited
    // on (pipe()/posix_spawn()/waitpid() failure - an environment/
    // configuration problem, e.g. a bad --blindsig-prover-path). This is
    // a DIFFERENT failure category from a nonzero exit_code or malformed
    // stdout - callers must not conflate "the tool couldn't run at all"
    // with "the tool ran and reported a rejection."
    std::string spawn_error;

    [[nodiscard]] bool spawned_ok() const { return spawn_error.empty(); }
};

// Runs `prover_path` with `args` (argv[1..], NOT including argv[0] -
// prover_path itself is used for that), writing `stdin_payload` to the
// child's stdin and collecting its stdout/stderr, killing it (SIGKILL)
// if it has not exited within `timeout`. Stdin writing and stdout/stderr
// reading all happen concurrently on separate threads, so a full OS pipe
// buffer on any one of the three streams can never deadlock against the
// others.
[[nodiscard]] SidecarResult run_blindsig_prover(const std::string& prover_path,
                                                 const std::vector<std::string>& args,
                                                 std::string_view stdin_payload,
                                                 std::chrono::seconds timeout);

// Validates that `result` actually spawned (throws std::runtime_error,
// with stderr_text folded in for diagnostics, if not) and that
// stdout_text is syntactically valid JSON - every blindsig-prover
// subcommand contracts to always print exactly one JSON object on
// stdout, success or failure, even across a caught panic (see
// blindsig-prover/prover/src/main.rs's module comment) - then returns
// stdout_text UNCHANGED. Deliberately returns the raw string, not a
// parsed value: each subcommand's JSON shape differs (see schema.rs on
// the Rust side), so parsing into a specific typed shape is left to the
// caller, keeping nlohmann::json out of this header's public API
// entirely (only this function's .cpp implementation needs it, to
// validate parseability).
[[nodiscard]] std::string require_sidecar_stdout(const SidecarResult& result);

} // namespace tradep2p::blindsig
