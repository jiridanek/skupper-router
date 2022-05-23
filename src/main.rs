/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// https://doc.rust-lang.org/reference/items/external-blocks.html#the-link-attribute
// #[link(name = "skupper-router-static")]
// extern "C" {
//     fn qd_port_int(port_str: *const libc::c_char) -> libc::c_int;
// }

// #![allow(non_upper_case_globals)]
// #![allow(non_camel_case_types)]
// #![allow(non_snake_case)]
// include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::c_void;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

use getopts::Matches;
use libc::c_char;

// use bindings as c;
mod next;
use next as c;

use crate::next::{PyGILState_STATE, qd_dispatch_t};
use crate::c::qd_server_stop;

// mod next_expanded;
// mod bindings;

// use global variable so that we can access this from signal handler
static mut dispatch: *mut qd_dispatch_t = std::ptr::null_mut();

/*


#include "config.h"

#include "qpid/dispatch.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int            exit_with_sigint = 0;
static qd_dispatch_t *dispatch = 0;
static qd_log_source_t *log_source = 0;
static const char* argv0 = 0;

/**
 * Configures the handler function. Specify SIG_IGN to ignore incoming signals.
 */
static void install_signal_handler(void (*handler)(int))
{
    signal(SIGHUP, handler);
    signal(SIGQUIT, handler);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);
}

*/

unsafe fn qd_log(
    source: *mut c::qd_log_source_t,
    level: c::qd_log_level_t,
) {
    let __FILE__ = std::ffi::CString::new("fake file").unwrap();
    let __LINE__ = 42;
    let __VA_ARGS__ = std::ffi::CString::new("fake args").unwrap();
    if c::qd_log_enabled(source, level) {
        c::qd_log_impl(source, level, __FILE__.as_ptr(), __LINE__, __VA_ARGS__.as_ptr());
    }
}

unsafe fn check(fd: i32) {
    let argv0 = std::ffi::CString::new("skupper-router").unwrap();
    let module = std::ffi::CString::new("source").unwrap();
    let log_source = c::qd_log_source(module.as_ptr());

    if c::qd_error_code() != 0 {
        let m1 = std::ffi::CString::new("Router start-up failed: %s").unwrap();
        qd_log(log_source, c::qd_log_level_t_QD_LOG_CRITICAL); //, m1.as_ptr(), c::qd_error_message());
        let fmt = std::ffi::CString::new("%s: %s\n").unwrap();
        c::dprintf(fd, fmt.as_ptr(), argv0.as_ptr(), c::qd_error_message());
        // c::close(fd);
        c::exit(1);
    }
}

fn fail(fd: i32, msg: &str) {
    println!("fail called: {}", msg);
    // if unsafe { libc::__errno_location() } != 0 {
    //     unsafe { c::qd_error_errno(libc::errno, __VA_ARGS__) };
    // } else {
    //     unsafe { c::qd_error(QD_ERROR_RUNTIME, __VA_ARGS__) };
    //     unsafe { check(fd) };
    // }
}

/*

static void daemon_process(const char *config_path, const char *python_pkgdir, bool test_hooks,
                           const char *pidfile, const char *user)
{

}

#define DEFAULT_DISPATCH_PYTHON_DIR QPID_DISPATCH_HOME_INSTALLED "/python"

void usage(char **argv) {
    fprintf(stdout, "Usage: %s [OPTIONS]\n\n", argv[0]);
    fprintf(stdout, "  -c, --config=PATH (%s)\n", DEFAULT_CONFIG_PATH);
    fprintf(stdout, "                             Load configuration from file at PATH\n");
    fprintf(stdout, "  -I, --include=PATH (%s)\n", DEFAULT_DISPATCH_PYTHON_DIR);
    fprintf(stdout, "                             Location of Dispatch's Python library\n");
    fprintf(stdout, "  -d, --daemon               Run process as a SysV-style daemon\n");
    fprintf(stdout, "  -P, --pidfile              If daemon, the file for the stored daemon pid\n");
    fprintf(stdout, "  -U, --user                 If daemon, the username to run as\n");
    fprintf(stdout, "  -T, --test-hooks           Enable internal system testing features\n");
    fprintf(stdout, "  -v, --version              Print the version of Qpid Dispatch Router\n");
    fprintf(stdout, "  -h, --help                 Print this help\n");
}

int main(int argc, char **argv)
{
    argv0 = argv[0];
    const char *config_path   = DEFAULT_CONFIG_PATH;
    const char *python_pkgdir = DEFAULT_DISPATCH_PYTHON_DIR;
}


 */

fn print_usage(program: &str, opts: getopts::Options) {
    let brief = format!("Usage: {} [OPTIONS]", program);
    print!("{}", opts.usage(&brief));
}

#[no_mangle]
pub extern "C" fn qd_python_lock() -> c::qd_python_lock_state_t {
    println!("FAKEEE");
    let fname = std::ffi::CString::new("qd_python_lock").unwrap();
    // unsafe { libc::dlopen(libc::RTLD_NEXT as *const c_char, 0); }
    let ptr = unsafe { libc::dlsym(libc::RTLD_NEXT, fname.as_ptr()) };
    // let symbol: unsafe extern "C" fn() -> c::qd_python_lock_state_t = ptr as unsafe extern "C" fn() -> c::qd_python_lock_state_t;
    // https://rust-lang.github.io/unsafe-code-guidelines/layout/function-pointers.html
    let symbol = unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> c::qd_python_lock_state_t>(ptr) };
    let result: c::qd_python_lock_state_t = unsafe { symbol() };
    return result;
}


fn main() {
    // let s = std::ffi::CString::new("amqp").unwrap();
    // // let x = unsafe { next::qd_port_int(s.as_ptr()) };
    // let x = unsafe { c::qd_port_int(s.as_ptr()) };
    // println!("max compressed length of a 100 byte buffer: {}", x);

    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();

    // TODO: indicate default values for --config and --include
    let mut opts = getopts::Options::new();
    opts
        .optopt("c", "config", "Load configuration from file at PATH", "PATH")
        .optopt("I", "include", "Location of Dispatch's Python library", "PATH")
        .optflag("d", "daemon", "Run process as a SysV-style daemon")
        .optflag("P", "pidfile", "If daemon, the file for the stored daemon pid")
        .optopt("U", "user", "If daemon, the username to run as", "USER")
        .optflag("T", "test-hooks", "Enable internal system testing features")
        .optflag("v", "version", "Print the version of Qpid Dispatch Router")
        .optflag("h", "help", "Print this help")
    ;
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => {
            println!("{}", f.to_string());
            print_usage(&program, opts);
            std::process::exit(1);
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if matches.opt_present("v") {
        println!("{}", "some version");
        return;
    }
    if !matches.free.is_empty() {
        // if (optind < argc) {
        //     fprintf(stderr, "Unexpected arguments:");
        //     for (; optind < argc; ++optind) fprintf(stderr, " %s", argv[optind]);
        //     fprintf(stderr, "\n\n");
        //     usage(argv);
        //     exit(1);
        // }
        print_usage(&program, opts);
        std::process::exit(1);
    };

    let config_path = matches.opt_str("c").unwrap_or(String::from("/home/jdanek/repos/skupper-router/cmake-build-debug/install/etc/skupper-router/skrouterd.conf"));
    let python_pkgdir = matches.opt_str("I").unwrap_or(String::from("/home/jdanek/repos/skupper-router/cmake-build-debug/install/lib/skupper-router/python"));
    let daemon_mode = matches.opt_present("d");
    let pidfile = matches.opt_str("P");
    let user = matches.opt_str("U");
    let test_hooks = matches.opt_present("T");

    if daemon_mode {
        daemon_process(config_path, python_pkgdir, test_hooks, pidfile, user);
    } else {
        main_process(config_path, python_pkgdir, test_hooks, 2);
    }

    return;
}

/**
 * This is the OS signal handler, invoked on an undetermined thread at a completely
 * arbitrary point of time.
 */
extern fn handle_signal(signal: i32) {
    use nix::sys::signal;

    let signal = nix::sys::signal::Signal::try_from(signal).unwrap();
    println!("got signal: {}", signal);

    /* Ignore future signals, dispatch may already be freed */
    install_signal_handler(nix::sys::signal::SigHandler::SigIgn);
    match signal {
        nix::sys::signal::SIGINT => {
            let exit_with_sigint = 1;
            unsafe {
                qd_server_stop(dispatch); /* qpid_server_stop is signal-safe */
            }
        }
        nix::sys::signal::SIGQUIT => {
            unsafe {
                qd_server_stop(dispatch); /* qpid_server_stop is signal-safe */
            }
        }
        _ => {}
    }
}

fn main_process(config_path: String, python_pkgdir: String, test_hooks: bool, fd: i32) {
    let python_pkgdir_cstr = std::ffi::CString::new(python_pkgdir).unwrap();
    let main_cstr = std::ffi::CString::new("MAIN").unwrap();
    let config_path_cstr = std::ffi::CString::new(config_path).unwrap();

    // unsafe {
    //     c::qd_python_lock();
    // }

    unsafe {
        dispatch = c::qd_dispatch(python_pkgdir_cstr.as_ptr(), test_hooks);
        check(fd);
        let log_source = c::qd_log_source(main_cstr.as_ptr()); /* Logging is initialized by qd_dispatch. */
        c::qd_dispatch_validate_config(config_path_cstr.as_ptr());
        check(fd);
        c::qd_dispatch_load_config(dispatch, config_path_cstr.as_ptr());
        check(fd);

        install_signal_handler(nix::sys::signal::SigHandler::Handler(handle_signal));

        // if (fd > 2) {               /* Daemon mode, fd is one end of a pipe not stdout or stderr */
        //     dprintf(fd, "ok"); // Success signal
        //     close(fd);
        // }

        c::qd_server_run(dispatch);

        c::qd_dispatch_free(dispatch);

        std::io::stdout().flush().unwrap();
        // if (exit_with_sigint) {
        //     signal(SIGINT, SIG_DFL);
        //     kill(getpid(), SIGINT);
        // }
    }
}

fn install_signal_handler(handler: nix::sys::signal::SigHandler) {
    use nix::sys::signal;

    let sig_action = signal::SigAction::new(
        signal::SigHandler::Handler(handle_signal),
        signal::SaFlags::empty(),
        signal::SigSet::empty());
    for s in [signal::SIGHUP, signal::SIGQUIT, signal::SIGTERM, signal::SIGINT] {
        unsafe {
            signal::sigaction(s, &sig_action)
                .expect("Calling sigaction failed");
        }
    }
}

fn daemon_process(config_path: String, python_pkgdir: String, test_hooks: bool, pidfile: Option<String>, user: Option<String>) {
    let mut pipefd: [i32; 2] = [0; 2];

    /*

    //
    // This daemonization process is based on that outlined in the
    // "daemon" manpage from Linux.
    //

    //
    // Create an unnamed pipe for communication from the daemon to the main process
    //
    */
    unsafe {
        if libc::pipe(pipefd.as_mut_ptr()) < 0 {
            let msg = std::ffi::CString::new("Error creating inter-process pipe").unwrap();
            libc::perror(msg.as_ptr());
            libc::exit(1);
        }
    }

    //
    // First fork
    //
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        //
        // Child Process
        //

        //
        // Detach any terminals and create an independent session
        //
        if unsafe { libc::setsid() < 0 } {
            fail(pipefd[1], "Cannot start a new session");
        }

        //
        // Second fork
        //
        let pid2 = unsafe { libc::fork() };
        if pid2 == 0 {
            unsafe { libc::close(pipefd[0]) }; // Close read end.

            //
            // Assign stdin, stdout, and stderr to /dev/null
            //
            unsafe {
                libc::close(2);
                libc::close(1);
                libc::close(0);
                let path = std::ffi::CString::new("/dev/null").unwrap();
                let fd = libc::open(path.as_ptr(), libc::O_RDWR);
                if fd != 0 {
                    fail(pipefd[1], "Can't redirect stdin to /dev/null");
                }
                if libc::dup(fd) < 0 {
                    fail(pipefd[1], "Can't redirect stdout to /dev/null");
                }
                if libc::dup(fd) < 0 {
                    fail(pipefd[1], "Can't redirect stderr /dev/null");
                }
            }
            //
            // Set the umask to 0
            //
            unsafe { libc::umask(0) };


            //
            // If config path is not a fully qualified path, then construct the
            // fully qualified path to the config file.  This needs to be done
            // since the daemon will set "/" to its working directory.
            //
            let config_path = std::path::PathBuf::from(config_path);
            let config_path_full = std::fs::canonicalize(config_path).expect("Unable to canonicalize config path");
            //
            // Set the current directory to "/" to avoid blocking
            // mount points
            //
            std::env::set_current_dir("/").expect("Can't chdir /");

            //
            // If a pidfile was provided, write the daemon pid there.
            //
            if let Some(pidfile) = pidfile.as_ref() {
                let mut pf = std::fs::File::create(pidfile).expect(&*format!("Can't write pidfile {}", pidfile));
                pf.write_all(format!("{}\n", std::process::id()).as_bytes());
            }

            //
            // If a user was provided, drop privileges to the user's
            // privilege level.
            //
            if let Some(user) = user {
                let user_cstr = std::ffi::CString::new(&*user).unwrap();
                let pwd = unsafe { libc::getpwnam(user_cstr.as_ptr()) };
                if pwd.is_null() { fail(pipefd[1], &*format!("Can't look up user {}", user)) };
                if unsafe { libc::setuid((*pwd).pw_uid) < 0 } {
                    fail(pipefd[1], &*format!("Can't set user ID for user {}, errno={}", user, unsafe { *libc::__errno_location() }));
                }
                //if (setgid(pwd->pw_gid) < 0) fail(pipefd[1], "Can't set group ID for user %s, errno=%d", user, errno);
            }

            main_process(config_path_full.to_string_lossy().to_string(), python_pkgdir, test_hooks, pipefd[1]);
        } else {
            //
            // Exit first child
            //
            unsafe { libc::exit(0) };
        }
    } else {
        unsafe {
            //
            // Parent Process
            // Wait for a success signal ('0') from the daemon process.
            // If we get success, exit with 0.  Otherwise, exit with 1.
            //
            libc::close(pipefd[1]); // Close write end.
            let mut fd = std::fs::File::from_raw_fd(pipefd[0]);

            let mut result = String::new();
            fd.read_to_string(&mut result).expect("Error reading inter-process pipe");

            if result == "ok" {
                std::process::exit(0);
            }
            println!("{}", result);
            std::process::exit(1);
        }
    }
}

// https://rust-cli.github.io/book/tutorial/cli-args.html
// https://github.com/DarthUDP/daemonize-me/tree/trunk/src




