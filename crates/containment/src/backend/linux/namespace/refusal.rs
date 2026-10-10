//! The seccomp notification path: what the workload hands the box, and what the box answers.
//!
//! The box only ever refuses. [`refusal_response`] is the one response builder, and it takes no
//! value a caller could use to continue a call or report a success.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::syscall::{MEDIATED, WORKLOAD_PERMITTED};
use crate::ContainmentError;

/// The tag on the message carrying the listener.
const OBSERVED: u8 = b'O';
/// The tag on the message saying the install fell back, followed by the errno.
const UNOBSERVED: u8 = b'U';

/// One refused call, as the kernel reports it to the listener.
#[derive(Debug, Clone, Copy)]
pub struct Notification {
    /// The kernel's cookie for this notification.
    pub id: u64,
    /// The caller's pid in the reader's PID namespace; 0 when it has none there.
    pub pid: u32,
    /// The syscall number.
    pub syscall: i64,
    /// The six raw argument registers.
    pub args: [u64; 6],
}

/// What [`Listener::next`] found.
#[derive(Debug)]
pub enum Next {
    /// A refused call is waiting for its answer.
    Notification(Notification),
    /// Nothing arrived within the timeout, or the caller went away before it could be read.
    Idle,
    /// No task is left under the filter.
    Ended,
}

/// The receiving end of one observed filter.
#[derive(Debug)]
pub struct Listener(pub(crate) OwnedFd);

impl Listener {
    /// Take ownership of a listener received from the workload.
    #[must_use]
    pub fn from_fd(descriptor: OwnedFd) -> Self {
        Self(descriptor)
    }

    /// Wait up to `timeout` for the next refused call.
    pub fn next(&self, timeout: Duration) -> std::io::Result<Next> {
        let mut poll = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one pollfd on the stack.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::Interrupted {
                Ok(Next::Idle)
            } else {
                Err(error)
            };
        }
        if ready == 0 {
            return Ok(Next::Idle);
        }
        if poll.revents & libc::POLLIN == 0 && poll.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(Next::Ended);
        }
        // SAFETY: the kernel requires a zeroed buffer; `seccomp_notif` is plain data.
        let mut notification: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: the ioctl writes one `seccomp_notif` into the buffer above.
        let received = unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                &mut notification,
            )
        };
        if received < 0 {
            let error = std::io::Error::last_os_error();
            // ENOENT: the caller died between poll and receive. EINTR: retry on the next call.
            return match error.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::EINTR) => Ok(Next::Idle),
                _ => Err(error),
            };
        }
        let mut args = [0u64; 6];
        args.copy_from_slice(&notification.data.args);
        Ok(Next::Notification(Notification {
            id: notification.id,
            pid: notification.pid,
            syscall: i64::from(notification.data.nr),
            args,
        }))
    }

    /// Whether `id` still names a waiting call, so what was read about its caller is current.
    #[must_use]
    pub fn still_valid(&self, id: u64) -> bool {
        let mut cookie = id;
        // SAFETY: the ioctl reads one u64.
        unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
                &mut cookie,
            ) == 0
        }
    }

    /// Answer `id` with `EPERM`, the answer the filter gave before notifications existed.
    pub fn refuse(&self, id: u64) -> std::io::Result<()> {
        let mut response = refusal_response(id);
        // SAFETY: the ioctl reads one `seccomp_notif_resp`.
        if unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &mut response,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// The one response this crate builds: refuse with `EPERM`, never continue.
pub(crate) fn refusal_response(id: u64) -> libc::seccomp_notif_resp {
    libc::seccomp_notif_resp {
        id,
        val: 0,
        error: -libc::EPERM,
        flags: 0,
    }
}

/// A refused call in an operator's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// The syscall's name, or `syscall_<nr>` when Box's tables do not name it.
    pub syscall: String,
    /// The decoded scalars an argument-scoped rule reads; `None` for any other call.
    pub arguments: Option<String>,
}

/// Describe one refused call from its number and raw arguments, without reading workload memory.
#[must_use]
pub fn describe(syscall: i64, args: &[u64; 6]) -> Description {
    let name = WORKLOAD_PERMITTED
        .iter()
        .map(|e| (e.number, e.name))
        .chain(MEDIATED.iter().map(|e| (e.number, e.name)))
        .find(|(number, _)| *number == syscall)
        .map_or_else(
            || format!("syscall_{syscall}"),
            |(_, name)| name.to_string(),
        );
    Description {
        syscall: name,
        arguments: arguments(syscall, args),
    }
}

fn arguments(syscall: i64, a: &[u64; 6]) -> Option<String> {
    let nr = |n: libc::c_long| n == syscall;
    if nr(libc::SYS_socket) {
        return Some(format!(
            "family={} type={}",
            family(a[0]),
            socket_type(a[1])
        ));
    }
    if nr(libc::SYS_socketpair) {
        return Some(format!("family={}", family(a[0])));
    }
    if nr(libc::SYS_mmap) || nr(libc::SYS_mprotect) || nr(libc::SYS_pkey_mprotect) {
        return Some(format!("prot={}", protection(a[2])));
    }
    if nr(libc::SYS_execveat) {
        return Some(format!("flags={}", at_flags(a[4])));
    }
    if nr(libc::SYS_setpgid) {
        return Some(format!("pid={} pgid={}", a[0] as i32, a[1] as i32));
    }
    if nr(libc::SYS_setresuid) || nr(libc::SYS_setresgid) {
        return Some(format!(
            "ids={},{},{}",
            a[0] as u32, a[1] as u32, a[2] as u32
        ));
    }
    None
}

fn family(value: u64) -> String {
    let name = match value as i32 {
        libc::AF_UNIX => "AF_UNIX",
        libc::AF_INET => "AF_INET",
        libc::AF_INET6 => "AF_INET6",
        libc::AF_NETLINK => "AF_NETLINK",
        libc::AF_PACKET => "AF_PACKET",
        libc::AF_VSOCK => "AF_VSOCK",
        libc::AF_BLUETOOTH => "AF_BLUETOOTH",
        libc::AF_ALG => "AF_ALG",
        libc::AF_KEY => "AF_KEY",
        libc::AF_XDP => "AF_XDP",
        libc::AF_CAN => "AF_CAN",
        libc::AF_TIPC => "AF_TIPC",
        _ => return (value as i32).to_string(),
    };
    name.to_string()
}

fn socket_type(value: u64) -> String {
    // SOCK_NONBLOCK and SOCK_CLOEXEC ride the same word; the type is the low nibble. Any other bit
    // makes the kernel refuse the call itself, so the raw number is the honest spelling.
    let flags = (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64;
    if value & !(0xf | flags) != 0 {
        return (value as i32).to_string();
    }
    let name = match (value as i32) & 0xf {
        libc::SOCK_STREAM => "SOCK_STREAM",
        libc::SOCK_DGRAM => "SOCK_DGRAM",
        libc::SOCK_RAW => "SOCK_RAW",
        libc::SOCK_SEQPACKET => "SOCK_SEQPACKET",
        libc::SOCK_RDM => "SOCK_RDM",
        _ => return (value as i32).to_string(),
    };
    name.to_string()
}

fn protection(value: u64) -> String {
    let named: Vec<&str> = [
        (libc::PROT_READ, "PROT_READ"),
        (libc::PROT_WRITE, "PROT_WRITE"),
        (libc::PROT_EXEC, "PROT_EXEC"),
    ]
    .iter()
    .filter(|(bit, _)| value & *bit as u64 != 0)
    .map(|(_, name)| *name)
    .collect();
    if named.is_empty() {
        "PROT_NONE".to_string()
    } else {
        named.join("|")
    }
}

fn at_flags(value: u64) -> String {
    let named: Vec<&str> = [
        (libc::AT_EMPTY_PATH, "AT_EMPTY_PATH"),
        (libc::AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"),
    ]
    .iter()
    .filter(|(bit, _)| value & *bit as u64 != 0)
    .map(|(_, name)| *name)
    .collect();
    if named.is_empty() {
        value.to_string()
    } else {
        named.join("|")
    }
}

/// The errno names an install failure can carry, for the control record and the stderr line.
// Used by the install path (next commit).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn errno_name(errno: i32) -> &'static str {
    match errno {
        libc::EBUSY => "EBUSY",
        libc::EINVAL => "EINVAL",
        libc::ENOSYS => "ENOSYS",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::ENOMEM => "ENOMEM",
        libc::EPERM => "EPERM",
        // Leaked once per distinct unknown errno, which a fallback reports at most once per launch.
        other => Box::leak(format!("errno_{other}").into_boxed_str()),
    }
}

/// Hand the listener to the box. The caller closes its own copy right after.
// Used by the install path (next commit).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn send_observed(
    control: &UnixStream,
    listener: &OwnedFd,
) -> Result<(), ContainmentError> {
    super::netns::send_tagged_descriptor(control, listener, OBSERVED)
}

/// Tell the box this launch fell back, and why.
// Used by the install path (next commit).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn send_unobserved(control: &UnixStream, errno: i32) -> Result<(), ContainmentError> {
    use std::io::Write as _;
    let mut message = [UNOBSERVED, 0, 0, 0, 0];
    message[1..].copy_from_slice(&errno.to_ne_bytes());
    (&*control)
        .write_all(&message)
        .map_err(|source| ContainmentError::ApplyFailed {
            backend: super::MECHANISM.to_string(),
            reason: format!("telling the box seccomp refusals are not observed: {source}"),
        })
}

/// What the workload handed over on `control` after the netns listeners: the listener, the
/// fallback's errno, or nothing (it never reached the install, or this launch has no box).
pub fn receive_handoff(control: &UnixStream) -> std::io::Result<Handoff> {
    let mut payload = [0u8; 5];
    let mut io = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut space = [0u64; 4];
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut io,
        msg_iovlen: 1,
        msg_control: space.as_mut_ptr().cast(),
        msg_controllen: std::mem::size_of_val(&space),
        msg_flags: 0,
    };
    // SAFETY: every pointer in `message` refers to a local that outlives the call.
    let received =
        unsafe { libc::recvmsg(control.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if received == 0 {
        return Ok(Handoff::Absent);
    }
    match payload[0] {
        OBSERVED => {
            // SAFETY: reading back the control message the kernel just wrote.
            let descriptor = unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                if header.is_null()
                    || (*header).cmsg_level != libc::SOL_SOCKET
                    || (*header).cmsg_type != libc::SCM_RIGHTS
                {
                    return Err(std::io::Error::other(
                        "the observed handoff carried no descriptor",
                    ));
                }
                std::ptr::read(libc::CMSG_DATA(header).cast::<libc::c_int>())
            };
            // SAFETY: SCM_RIGHTS installed a fresh descriptor this process now owns.
            Ok(Handoff::Observed(Listener(unsafe {
                OwnedFd::from_raw_fd(descriptor)
            })))
        }
        UNOBSERVED => {
            use std::io::Read as _;
            let mut errno = [0u8; 4];
            (&*control).read_exact(&mut errno)?;
            Ok(Handoff::Unobserved {
                errno: i32::from_ne_bytes(errno),
            })
        }
        other => Err(std::io::Error::other(format!(
            "unknown handoff tag {other:#x}"
        ))),
    }
}

/// What one launch's workload handed over.
#[derive(Debug)]
pub enum Handoff {
    /// The observed filter is installed; refusals arrive here.
    Observed(Listener),
    /// The install fell back to the refusing filters, for this errno.
    Unobserved {
        /// The errno the observed install failed with.
        errno: i32,
    },
    /// Nothing arrived before the peer closed.
    Absent,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **P2: the only response this crate can build refuses.** No argument reaches `val`,
    /// `error`, or `flags`, so no caller can continue a call or fake a success.
    #[test]
    fn the_response_always_refuses_with_eperm() {
        for id in [0, 1, u64::MAX] {
            let response = refusal_response(id);
            assert_eq!(response.id, id);
            assert_eq!(response.error, -libc::EPERM);
            assert_eq!(response.val, 0);
            assert_eq!(response.flags, 0);
        }
    }

    #[test]
    fn a_socket_refusal_names_its_family_and_type() {
        let d = describe(
            libc::SYS_socket,
            &[
                libc::AF_PACKET as u64,
                libc::SOCK_RAW as u64 | libc::SOCK_CLOEXEC as u64,
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(d.syscall, "socket");
        assert_eq!(
            d.arguments.as_deref(),
            Some("family=AF_PACKET type=SOCK_RAW")
        );
    }

    #[test]
    fn each_argument_scoped_refusal_decodes_its_scalars() {
        let wx = (libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        assert_eq!(
            describe(libc::SYS_mmap, &[0, 4096, wx, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("prot=PROT_WRITE|PROT_EXEC")
        );
        assert_eq!(
            describe(
                libc::SYS_mprotect,
                &[0, 4096, libc::PROT_EXEC as u64, 0, 0, 0]
            )
            .arguments
            .as_deref(),
            Some("prot=PROT_EXEC")
        );
        assert_eq!(
            describe(
                libc::SYS_execveat,
                &[3, 0, 0, 0, libc::AT_EMPTY_PATH as u64, 0]
            )
            .arguments
            .as_deref(),
            Some("flags=AT_EMPTY_PATH")
        );
        assert_eq!(
            describe(libc::SYS_socketpair, &[libc::AF_INET as u64, 1, 0, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("family=AF_INET")
        );
        assert_eq!(
            describe(libc::SYS_setpgid, &[0, 7, 0, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("pid=0 pgid=7")
        );
        assert_eq!(
            describe(libc::SYS_setresuid, &[1000, 0, u32::MAX as u64, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("ids=1000,0,4294967295")
        );
    }

    #[test]
    fn an_unknown_value_is_printed_as_a_number_and_an_unlisted_call_carries_no_arguments() {
        assert_eq!(
            describe(libc::SYS_socket, &[99, 99, 0, 0, 0, 0])
                .arguments
                .as_deref(),
            Some("family=99 type=99")
        );
        let bpf = describe(libc::SYS_bpf, &[0; 6]);
        assert_eq!(bpf.syscall, "bpf");
        assert_eq!(bpf.arguments, None);
        assert_eq!(describe(100_000, &[0; 6]).syscall, "syscall_100000");
    }

    #[test]
    fn the_handoff_round_trips_both_outcomes_and_eof() {
        use std::os::fd::AsRawFd as _;
        let (box_side, child_side) = UnixStream::pair().expect("pair");
        let sample = OwnedFd::from(std::fs::File::open("/dev/null").expect("dev null"));
        send_observed(&child_side, &sample).expect("send observed");
        send_unobserved(&child_side, libc::EBUSY).expect("send unobserved");
        drop(child_side);
        match receive_handoff(&box_side).expect("first") {
            Handoff::Observed(listener) => assert!(listener.0.as_raw_fd() >= 0),
            _ => panic!("first message is the descriptor"),
        }
        assert!(
            matches!(receive_handoff(&box_side).expect("second"), Handoff::Unobserved { errno } if errno == libc::EBUSY)
        );
        assert!(matches!(
            receive_handoff(&box_side).expect("eof"),
            Handoff::Absent
        ));
    }

    #[test]
    fn errno_names_cover_the_install_failures() {
        assert_eq!(errno_name(libc::EBUSY), "EBUSY");
        assert_eq!(errno_name(libc::EINVAL), "EINVAL");
        assert_eq!(errno_name(libc::ENOSYS), "ENOSYS");
        assert_eq!(errno_name(libc::EACCES), "EACCES");
        assert_eq!(errno_name(libc::EFAULT), "EFAULT");
        assert_eq!(errno_name(12345), "errno_12345");
    }
}
