use alloc::sync::Arc;
use core::alloc::Layout;
use core::ffi::c_void;
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
use core::sync::atomic::{AtomicBool, Ordering};

use kernel_memapi::{Allocation, Guarded, Location, MemoryApi, UserAccessible};
use kernel_vfs::path::AbsolutePath;
use kernel_vfs::Stat;
use log::debug;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::model_specific::FsBase;
#[cfg(target_arch = "x86_64")]
use x86_64::registers::rflags::RFlags;
#[cfg(target_arch = "x86_64")]
use x86_64::structures::idt::InterruptStackFrameValue;

use super::executable::executable_layout;
#[cfg(target_arch = "aarch64")]
use super::image::with_process_address_space_active;
use super::image::{read_executable_file_into, trampoline_load_elf};
use crate::arch::{PageSize, Size4KiB, VirtAddr};
#[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
use crate::dbg_mark;
use crate::file::{vfs, OpenFileDescription};
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::fd::{FileDescriptor, FileDescriptorFlags};
use crate::mcore::mtask::task::Task;
use crate::mem::memapi::LowerHalfMemoryApi;
use crate::{U64Ext, UsizeExt};

#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_OPEN_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_READ_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_ELF_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_ENTER_USER_STAGE_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    target_arch = "aarch64",
    feature = "rpi5",
    feature = "bringup-diagnostics"
))]
static TRAMPOLINE_TTBR0_STAGE_SENT: AtomicBool = AtomicBool::new(false);

pub(super) extern "C" fn trampoline(_arg: *mut c_void) {
    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_MARKER_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'u' as u32);
    }

    log::info!("Trampoline started");
    let ctx = ExecutionContext::load();
    log::info!("Trampoline: context loaded");
    let current_process = ctx.current_process();
    log::info!("Trampoline: current process got");

    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_OPEN_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'q' as u32);
    }

    let executable_path = current_process
        .executable_path
        .as_ref()
        .expect("should have an executable path");
    log::info!("Trampoline: opening executable {:?}", executable_path);
    let node = vfs()
        .write()
        .open(executable_path)
        .unwrap_or_else(|_| Task::terminate_current(1, "failed to open executable"));
    log::info!("Trampoline: executable opened");
    let stat = {
        let mut stat = Stat::default();
        node.stat(&mut stat)
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to stat executable"));
        stat
    };
    log::info!("Trampoline: executable stated, size={}", stat.size);
    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_READ_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'r' as u32);
    }

    let mut memapi = LowerHalfMemoryApi::new(current_process.clone());

    log::info!("Trampoline: allocating memory for executable");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'A' as u32);
    let layout = executable_layout(stat.size)
        .unwrap_or_else(|error| Task::terminate_current(1, error.message()));
    let mut executable_file_allocation = memapi
        .allocate(Location::Anywhere, layout, UserAccessible::Yes, Guarded::No)
        .unwrap_or_else(|| Task::terminate_current(1, "failed to allocate executable file"));
    log::info!("Trampoline: memory allocated");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'B' as u32);

    #[cfg(target_arch = "aarch64")]
    with_process_address_space_active(&current_process, || {
        let buf = executable_file_allocation.as_mut();
        read_executable_file_into(&node, buf, stat.size, "Trampoline")
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to read executable file"));
    });
    #[cfg(not(target_arch = "aarch64"))]
    {
        let buf = executable_file_allocation.as_mut();
        read_executable_file_into(&node, buf, stat.size, "Trampoline")
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to read executable file"));
    }
    log::info!("Trampoline: executable read into memory");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'C' as u32);

    // Parse and load ELF while the file allocation is still writable (readable).
    // make_executable is deferred until after into_inner() releases the borrow.
    log::info!("Trampoline: parsing ELF");
    #[cfg(all(feature = "rpi5", feature = "bringup-diagnostics"))]
    dbg_mark(b'D' as u32);

    #[cfg(target_arch = "aarch64")]
    let (code_ptr, exec_allocs, mut ro_allocs, wr_allocs, tls_master) =
        match with_process_address_space_active(&current_process, || {
            // Keep all borrowed ELF reads in the active process address space.
            trampoline_load_elf(executable_file_allocation.as_ref(), memapi.clone())
        }) {
            Ok((code_ptr, (exec_allocs, ro_allocs, wr_allocs, tls_master))) => {
                log::info!("Trampoline: ELF loaded");
                (code_ptr, exec_allocs, ro_allocs, wr_allocs, tls_master)
            }
            Err(err) => {
                log::error!("Trampoline: {err}");
                Task::terminate_current(1, "ELF load failed");
            }
        };
    #[cfg(not(target_arch = "aarch64"))]
    let (code_ptr, exec_allocs, mut ro_allocs, wr_allocs, tls_master) =
        match trampoline_load_elf(executable_file_allocation.as_ref(), memapi.clone()) {
            Ok((code_ptr, (exec_allocs, ro_allocs, wr_allocs, tls_master))) => {
                log::info!("Trampoline: ELF loaded");
                (code_ptr, exec_allocs, ro_allocs, wr_allocs, tls_master)
            }
            Err(err) => {
                log::error!("Trampoline: {err}");
                Task::terminate_current(1, "ELF load failed");
            }
        };
    #[cfg(all(
        not(target_arch = "aarch64"),
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    dbg_mark(b'E' as u32);
    #[cfg(all(
        target_arch = "aarch64",
        feature = "rpi5",
        feature = "bringup-diagnostics"
    ))]
    if !TRAMPOLINE_ELF_STAGE_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b's' as u32);
    }

    // Now that the ELF borrow is released, make the file allocation executable for storage.
    #[cfg(target_arch = "aarch64")]
    let executable_file_allocation = with_process_address_space_active(&current_process, || {
        memapi
            .make_executable(executable_file_allocation)
            .unwrap_or_else(|_| Task::terminate_current(1, "failed to protect executable file"))
    });
    #[cfg(not(target_arch = "aarch64"))]
    let executable_file_allocation = memapi
        .make_executable(executable_file_allocation)
        .unwrap_or_else(|_| Task::terminate_current(1, "failed to protect executable file"));

    if let Some(ref master_tls) = tls_master {
        log::info!("Trampoline: setting up TLS");
        let mut tls_alloc = memapi
            .allocate(
                Location::Anywhere,
                master_tls.layout(),
                UserAccessible::Yes,
                Guarded::No,
            )
            .unwrap_or_else(|| Task::terminate_current(1, "failed to allocate executable TLS"));

        #[cfg(target_arch = "aarch64")]
        with_process_address_space_active(&current_process, || {
            let slice = tls_alloc.as_mut();
            slice.copy_from_slice(master_tls.as_ref());
        });
        #[cfg(not(target_arch = "aarch64"))]
        {
            let slice = tls_alloc.as_mut();
            slice.copy_from_slice(master_tls.as_ref());
        }

        #[cfg(target_arch = "x86_64")]
        FsBase::write(tls_alloc.start());
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: Writing to TPIDR_EL0 is safe in EL1.
            unsafe {
                let val = tls_alloc.start().as_u64();
                core::arch::asm!("msr tpidr_el0, {}", in(reg) val);
            }
        }

        ctx.with_current_task(|task| {
            let mut guard = task.tls().write();
            assert!(guard.is_none(), "TLS should not exist yet");
            *guard = Some(tls_alloc);
        });
    }

    // Store ELF segment allocations in the process so they survive and can be cloned during fork
    {
        let mut segs = current_process.elf_segments.write();
        segs.executable = exec_allocs;
        if let Some(tls) = tls_master {
            ro_allocs.push(tls);
        }
        segs.readonly = ro_allocs;
        segs.writable = wr_allocs;
    }

    log::info!("Trampoline: allocating user stack");
    let mut memapi = LowerHalfMemoryApi::new(current_process.clone());
    let ustack_allocation = memapi
        .allocate(
            Location::Anywhere,
            Layout::from_size_align(
                Size4KiB::SIZE.into_usize() * 256,
                Size4KiB::SIZE.into_usize(),
            )
            .unwrap(),
            UserAccessible::Yes,
            Guarded::Yes,
        )
        .unwrap_or_else(|| Task::terminate_current(1, "failed to allocate userspace stack"));

    let ustack_rsp = ustack_allocation.start() + ustack_allocation.len().into_u64();
    log::info!(
        "Trampoline: ustack_rsp={:#x}, entry_point={:#x}",
        ustack_rsp.as_u64(),
        code_ptr
    );
    ctx.with_current_task(|task| {
        let mut ustack_guard = task.ustack().write();
        assert!(ustack_guard.is_none(), "ustack should not exist yet");
        *ustack_guard = Some(ustack_allocation);
    });
    // assert!(ustack_rsp.is_aligned(16_u64));

    #[cfg(target_arch = "x86_64")]
    let sel = ctx.selectors();

    let _ = current_process
        .executable_file_data
        .write()
        .insert(executable_file_allocation);

    debug!("stack_ptr: {:p}", ustack_rsp.as_ptr::<u8>());
    debug!("code_ptr: {:p}", code_ptr as *const u8);

    {
        let mut guard = current_process.file_descriptors.write();

        let devnull = vfs()
            .read()
            .open(AbsolutePath::try_new("/dev/null").unwrap())
            .expect("should be able to open /dev/null");
        let devnull_ofd = Arc::new(OpenFileDescription::from(devnull));
        guard.insert(
            0.into(),
            FileDescriptor::new(0.into(), FileDescriptorFlags::empty(), devnull_ofd.clone()),
        );

        let devserial = vfs()
            .read()
            .open(AbsolutePath::try_new("/dev/serial").unwrap())
            .expect("should be able to open /dev/serial");
        let devserial_ofd = Arc::new(OpenFileDescription::from(devserial));
        guard.insert(
            1.into(),
            FileDescriptor::new(
                1.into(),
                FileDescriptorFlags::empty(),
                devserial_ofd.clone(),
            ),
        );
        guard.insert(
            2.into(),
            FileDescriptor::new(
                2.into(),
                FileDescriptorFlags::empty(),
                devserial_ofd.clone(),
            ),
        );
    }

    #[cfg(target_arch = "x86_64")]
    {
        let isfv = InterruptStackFrameValue::new(
            VirtAddr::new(code_ptr as u64),
            sel.user_code,
            RFlags::INTERRUPT_FLAG,
            ustack_rsp,
            sel.user_data,
        );
        // SAFETY: We have set up the user stack and code pointer correctly, and we are
        // performing a return to userspace (Ring 3) to start the process execution.
        unsafe { isfv.iretq() };
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: We have set up the user stack and code pointer correctly.
        // We are entering userspace (EL0).
        // Before entering, we must ensure the process's address space is active.
        unsafe {
            #[cfg(all(
                target_arch = "aarch64",
                feature = "rpi5",
                feature = "bringup-diagnostics"
            ))]
            if !TRAMPOLINE_ENTER_USER_STAGE_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b't' as u32);
            }
            #[cfg(all(
                target_arch = "aarch64",
                feature = "rpi5",
                feature = "bringup-diagnostics"
            ))]
            if !TRAMPOLINE_TTBR0_STAGE_SENT.swap(true, Ordering::Relaxed) {
                dbg_mark(b'0' as u32);
            }

            let ttbr0 = current_process.with_address_space(|as_| as_.ttbr0_value());
            crate::arch::aarch64::paging::set_ttbr0(ttbr0);

            #[cfg(all(
                target_arch = "aarch64",
                feature = "rpi5",
                feature = "bringup-diagnostics"
            ))]
            dbg_mark(b'Q' as u32);

            crate::arch::aarch64::context::enter_userspace(code_ptr, ustack_rsp.as_u64() as usize);
        }
    }
}
