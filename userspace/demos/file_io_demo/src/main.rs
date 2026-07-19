#![no_std]
#![no_main]

use minilib::{close, open, read, write, O_RDONLY, O_WRONLY};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print("=== File I/O Demo ===\n");

    // 1. Read Test (/bin/init)
    let path = "/bin/init";
    print("Opening ");
    print(path);
    print(" (Read-Only)...\n");

    let fd = open(path, O_RDONLY, 0);
    if fd < 0 {
        print("Error: Failed to open /bin/init\n");
    } else {
        print("File opened, fd: ");
        print_num(fd as u64);
        print("\n");

        let mut buffer = [0u8; 16];
        let read_bytes = read(fd, &mut buffer);
        if read_bytes < 0 {
            print("Error: Failed to read\n");
        } else {
            print("Read ");
            print_num(read_bytes as u64);
            print(" bytes: ");
            // Print hex
            for byte in buffer.iter().take(read_bytes as usize) {
                print_hex(*byte);
                print(" ");
            }
            print("\n");
        }
        close(fd);
    }

    // 2. Write Test (/dev/null)
    let path = "/dev/null";
    print("\nOpening ");
    print(path);
    print(" (Write-Only)...\n");

    let fd = open(path, O_WRONLY, 0);
    if fd < 0 {
        print("Error: Failed to open /dev/null\n");
    } else {
        print("File opened, fd: ");
        print_num(fd as u64);
        print("\n");

        let msg = "Hello, /dev/null!";
        let written = write(fd, msg.as_bytes());
        if written < 0 {
            print("Error: Failed to write\n");
        } else {
            print("Written ");
            print_num(written as u64);
            print(" bytes (should be discarded).\n");
        }
        close(fd);
    }

    print("\nDone. Sleeping...\n");
    loop {
        minilib::sleep(10);
    }
}

fn print(s: &str) {
    write(1, s.as_bytes());
}

fn print_num(mut n: u64) {
    if n == 0 {
        print("0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut j = 0;
    while j < i / 2 {
        buf.swap(j, i - 1 - j);
        j += 1;
    }
    write(1, &buf[..i]);
}

fn print_hex(n: u8) {
    let hex = b"0123456789ABCDEF";
    let high = (n >> 4) as usize;
    let low = (n & 0xF) as usize;
    let buf = [hex[high], hex[low]];
    write(1, &buf);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &::core::panic::PanicInfo) -> ! {
    print("Panic!\n");
    loop {}
}
