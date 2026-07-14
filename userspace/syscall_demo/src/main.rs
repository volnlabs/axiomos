#![no_std]
#![no_main]

use core::panic::PanicInfo;

use minilib::{abort, close, dup, dup2, exit, free, iovec, malloc, pipe, read, write, writev};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Test malloc
    let size = 128;
    let ptr = malloc(size);

    if ptr.is_null() {
        // Malloc failed
        let msg = "Malloc failed\n";
        write(1, msg.as_bytes());
        exit(1);
    }

    // 2. Write to allocated memory
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
    let message = "Hello from allocated memory!\n";
    for (i, b) in message.bytes().enumerate() {
        if i < size {
            slice[i] = b;
        }
    }

    // 3. Test writev
    let part1 = "Part 1: ";
    let part2 = "This is a ";
    let part3 = "scatter/gather write.\n";

    let iov = [
        iovec {
            iov_base: part1.as_ptr(),
            iov_len: part1.len(),
        },
        iovec {
            iov_base: part2.as_ptr(),
            iov_len: part2.len(),
        },
        iovec {
            iov_base: part3.as_ptr(),
            iov_len: part3.len(),
        },
        iovec {
            iov_base: ptr,
            iov_len: message.len(),
        }, // Print from heap
    ];

    let written = writev(1, &iov);

    if written < 0 {
        let msg = "Writev failed\n";
        write(1, msg.as_bytes());
        exit(1);
    }

    // 4. Test free
    free(ptr);
    let freed_iov = [iovec {
        iov_base: ptr,
        iov_len: 1,
    }];
    if writev(1, &freed_iov) >= 0 {
        write(1, "Freed mapping remained accessible\n".as_bytes());
        exit(1);
    }

    // 5. Test pipe
    let mut pipefd = [0i32; 2];
    if pipe(pipefd.as_mut_ptr()) < 0 {
        let msg = "Pipe failed\n";
        write(1, msg.as_bytes());
        exit(1);
    }

    let pipe_msg = "Hello through pipe!\n";
    write(pipefd[1], pipe_msg.as_bytes());

    let mut buf = [0u8; 32];
    let n = read(pipefd[0], &mut buf);
    if n > 0 {
        write(1, "Pipe read: ".as_bytes());
        write(1, &buf[..n as usize]);
    }

    close(pipefd[0]);
    close(pipefd[1]);

    // 6. Test dup
    let stdout_dup = dup(1);
    if stdout_dup < 0 {
        let msg = "Dup failed\n";
        write(1, msg.as_bytes());
        exit(1);
    }
    let dup_msg = "Hello from dup-ed stdout!\n";
    write(stdout_dup, dup_msg.as_bytes());
    close(stdout_dup);

    // 7. Test dup2
    // Duplicate stdout (1) to fd 10
    if dup2(1, 10) < 0 {
        let msg = "Dup2 failed\n";
        write(1, msg.as_bytes());
        exit(1);
    }
    let dup2_msg = "Hello from dup2-ed stdout (fd 10)!\n";
    write(10, dup2_msg.as_bytes());
    close(10);

    let msg = "All tests passed. Exiting successfully.\n";
    write(1, msg.as_bytes());

    exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    abort();
}
