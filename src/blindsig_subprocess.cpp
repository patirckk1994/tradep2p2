#include "tradep2p/blindsig_subprocess.hpp"

#include <nlohmann/json.hpp>

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <mutex>
#include <thread>

extern char** environ;

namespace tradep2p::blindsig {
namespace {

struct Pipe {
    int read_fd{-1};
    int write_fd{-1};
};

Pipe make_pipe() {
    int fds[2];
    if (::pipe(fds) != 0) {
        throw std::runtime_error(std::string("blindsig subprocess: pipe() failed: ") + std::strerror(errno));
    }
    return Pipe{fds[0], fds[1]};
}

void close_if_valid(int& fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

// Writes `payload` to `fd`, then closes it - this thread OWNS `fd` for its
// entire lifetime, closing it is this function's job alone (the caller
// never touches it again after handing it off). SIGPIPE is already
// globally ignored by this process (see main.cpp's startup sequence), so
// the child closing its stdin early surfaces here as a plain EPIPE
// return, not a signal - handled the same as any other write error: stop
// writing.
void write_all_then_close(int fd, std::string_view payload) {
    std::size_t written = 0U;
    while (written < payload.size()) {
        const ssize_t n = ::write(fd, payload.data() + written, payload.size() - written);
        if (n > 0) {
            written += static_cast<std::size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    ::close(fd);
}

// Reads until EOF (or error) on `fd`, appending into `out`, then closes
// `fd` - same single-owner-closes-it-itself discipline as the writer.
void read_all_then_close(int fd, std::string& out) {
    char buffer[65536];
    for (;;) {
        const ssize_t n = ::read(fd, buffer, sizeof buffer);
        if (n > 0) {
            out.append(buffer, static_cast<std::size_t>(n));
        } else if (n == 0) {
            break; // EOF
        } else if (errno == EINTR) {
            continue;
        } else {
            break; // treat any other read error as end-of-stream
        }
    }
    ::close(fd);
}

} // namespace

SidecarResult run_blindsig_prover(const std::string& prover_path, const std::vector<std::string>& args,
                                   std::string_view stdin_payload, std::chrono::seconds timeout) {
    SidecarResult result;

    Pipe stdin_pipe;
    Pipe stdout_pipe;
    Pipe stderr_pipe;
    try {
        stdin_pipe = make_pipe();
        stdout_pipe = make_pipe();
        stderr_pipe = make_pipe();
    } catch (const std::exception& e) {
        close_if_valid(stdin_pipe.read_fd);
        close_if_valid(stdin_pipe.write_fd);
        close_if_valid(stdout_pipe.read_fd);
        close_if_valid(stdout_pipe.write_fd);
        close_if_valid(stderr_pipe.read_fd);
        close_if_valid(stderr_pipe.write_fd);
        result.spawn_error = e.what();
        return result;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, stdin_pipe.read_fd, STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, stdout_pipe.write_fd, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, stderr_pipe.write_fd, STDERR_FILENO);
    // Close every original pipe fd in the child after the dup2s above -
    // the dup2 targets (0/1/2) stay open; these numbered originals would
    // otherwise leak into the child as extra open fds.
    posix_spawn_file_actions_addclose(&actions, stdin_pipe.read_fd);
    posix_spawn_file_actions_addclose(&actions, stdin_pipe.write_fd);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe.read_fd);
    posix_spawn_file_actions_addclose(&actions, stdout_pipe.write_fd);
    posix_spawn_file_actions_addclose(&actions, stderr_pipe.read_fd);
    posix_spawn_file_actions_addclose(&actions, stderr_pipe.write_fd);

    std::vector<char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(const_cast<char*>(prover_path.c_str()));
    for (const auto& a : args) {
        argv.push_back(const_cast<char*>(a.c_str()));
    }
    argv.push_back(nullptr);

    pid_t pid = -1;
    const int spawn_rc = posix_spawn(&pid, prover_path.c_str(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);

    if (spawn_rc != 0) {
        close_if_valid(stdin_pipe.read_fd);
        close_if_valid(stdin_pipe.write_fd);
        close_if_valid(stdout_pipe.read_fd);
        close_if_valid(stdout_pipe.write_fd);
        close_if_valid(stderr_pipe.read_fd);
        close_if_valid(stderr_pipe.write_fd);
        result.spawn_error = std::string("posix_spawn failed for '") + prover_path + "': " + std::strerror(spawn_rc);
        return result;
    }

    // Parent no longer needs the child-side ends of any pipe.
    close_if_valid(stdin_pipe.read_fd);
    close_if_valid(stdout_pipe.write_fd);
    close_if_valid(stderr_pipe.write_fd);

    // Stdin writer, stdout/stderr readers all run concurrently on their
    // own threads, each owning and closing exactly one fd, so a full OS
    // pipe buffer on any one of the three streams can never deadlock
    // against the others (the risk a naive "write all of stdin, then
    // read all of stdout" would carry once payload/output sizes exceed
    // the OS pipe buffer - 64KB on Linux by default).
    std::thread writer(write_all_then_close, stdin_pipe.write_fd, stdin_payload);
    std::thread stdout_reader(read_all_then_close, stdout_pipe.read_fd, std::ref(result.stdout_text));
    std::thread stderr_reader(read_all_then_close, stderr_pipe.read_fd, std::ref(result.stderr_text));

    // Watchdog: SIGKILLs the child if it hasn't exited within `timeout`.
    // Woken early the moment the main thread's waitpid() below returns,
    // so a fast-exiting child never makes this thread wait out the full
    // timeout before joining.
    std::mutex done_mutex;
    std::condition_variable done_cv;
    bool done = false;
    std::thread watchdog([&] {
        std::unique_lock<std::mutex> lock(done_mutex);
        if (!done_cv.wait_for(lock, timeout, [&] { return done; })) {
            ::kill(pid, SIGKILL);
        }
    });

    int status = 0;
    const pid_t waited = ::waitpid(pid, &status, 0);
    const int wait_errno = errno;
    {
        std::lock_guard<std::mutex> lock(done_mutex);
        done = true;
    }
    done_cv.notify_all();
    watchdog.join();
    writer.join();
    stdout_reader.join();
    stderr_reader.join();

    if (waited < 0) {
        result.spawn_error = std::string("waitpid failed: ") + std::strerror(wait_errno);
        return result;
    }
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
        result.timed_out = true;
        result.exit_code = -1;
    } else if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else {
        result.exit_code = -1;
    }
    return result;
}

std::string require_sidecar_stdout(const SidecarResult& result) {
    if (!result.spawned_ok()) {
        throw std::runtime_error("blindsig-prover could not be run: " + result.spawn_error);
    }
    if (!nlohmann::json::accept(result.stdout_text)) {
        throw std::runtime_error(
            "blindsig-prover produced non-JSON stdout (tool-contract violation) - stderr was: " +
            result.stderr_text);
    }
    return result.stdout_text;
}

} // namespace tradep2p::blindsig
