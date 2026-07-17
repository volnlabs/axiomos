#![no_std]
#![no_main]

use minilib::*;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let pid = fork();

    if pid < 0 {
        // Fork failed
        exit(1);
    } else if pid == 0 {
        // Child process
        // We can't easily print strings without a proper allocator or simplified print function in minilib,
        // but let's assume we can use the write syscall wrapper we added.
        let msg = "Hello from child!\n";
        write(1, msg.as_bytes());
        exit(42);
    } else {
        // Parent process
        let msg = "Hello from parent, waiting for child...\n";
        write(1, msg.as_bytes());

        let mut status: i32 = 0;
        let reaped_pid = waitpid(pid, &mut status as *mut i32, 0);

        if reaped_pid == pid {
            // We can format the status if we had a formatter, but for now just exit.
            // status should be (42 << 8)
            if (status >> 8) == 42 {
                let msg = "Child exited with 42! Success.\n";
                write(1, msg.as_bytes());
                exit(0);
            } else {
                let msg = "Child exited with wrong code.\n";
                write(1, msg.as_bytes());
                exit(1);
            }
        } else {
            let msg = "Waitpid returned wrong PID.\n";
            write(1, msg.as_bytes());
            exit(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
