use alloc::vec::Vec;
use core::mem::size_of;

use kernel_abi::{
    BpfAttr, BpfObjectInfo, BPF_MAP_CREATE, BPF_MAP_DELETE_ELEM, BPF_MAP_DESTROY,
    BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_OBJ_GET, BPF_OBJ_GET_INFO_BY_FD, BPF_OBJ_PIN,
    BPF_OBJ_UNPIN, BPF_PROG_ATTACH, BPF_PROG_DETACH, BPF_PROG_LOAD, BPF_PROG_LOAD_ELF,
    BPF_PROG_UNLOAD, BPF_RINGBUF_POLL, EBUSY, EINVAL, ENOENT, ENOMEM, EPERM,
};
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::execution::BpfError;
use zerocopy::IntoBytes;

use super::validation::{
    copy_from_userspace, copy_to_userspace, read_userspace_slice, read_userspace_string,
};
use crate::BPF_MANAGER;

fn bpf_error_errno(error: BpfError) -> isize {
    match error {
        BpfError::OutOfMemory | BpfError::ResourceLimit => -isize::from(ENOMEM),
        BpfError::ObjectBusy => -isize::from(EBUSY),
        BpfError::NotLoaded => -isize::from(ENOENT),
        BpfError::ReadOnlyMap | BpfError::SignatureRejected | BpfError::PermissionDenied => {
            -isize::from(EPERM)
        }
        _ => -isize::from(EINVAL),
    }
}

pub fn sys_bpf(cmd: usize, attr_ptr: usize, size: usize) -> isize {
    // Security Hardening: Validate the attribute size matches expected struct size
    // This prevents reading past the end of the userspace buffer.
    if size < size_of::<BpfAttr>() {
        log::error!(
            "sys_bpf: invalid attribute size {} (expected >= {})",
            size,
            size_of::<BpfAttr>()
        );
        return -1; // EINVAL
    }

    let cmd_u32 = cmd as u32;
    let owner = crate::mcore::context::ExecutionContext::load()
        .current_process()
        .pid()
        .as_u64();

    // These commands touch map backing storage that a running BPF program may
    // address through a raw helper-returned pointer. Serialize them with BPF
    // execution until map APIs carry an epoch/read guard themselves.
    let _runtime = matches!(
        cmd_u32,
        BPF_MAP_LOOKUP_ELEM
            | BPF_MAP_UPDATE_ELEM
            | BPF_MAP_DELETE_ELEM
            | BPF_MAP_DESTROY
            | BPF_RINGBUF_POLL
    )
    .then(crate::bpf::lock_runtime);

    match cmd_u32 {
        BPF_MAP_CREATE => {
            log::info!("sys_bpf: MAP_CREATE");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            // For MAP_CREATE, fields are:
            // prog_type -> map_type
            // insn_cnt -> key_size
            // insns (low u32) -> value_size
            // insns (high u32) -> max_entries
            let map_type = attr.prog_type;
            let key_size = attr.insn_cnt;
            let value_size = (attr.insns & 0xFFFFFFFF) as u32;
            let max_entries = ((attr.insns >> 32) & 0xFFFFFFFF) as u32;

            if let Some(manager) = BPF_MANAGER.get() {
                match manager.lock().create_map_for(
                    owner,
                    map_type,
                    key_size,
                    value_size,
                    max_entries,
                ) {
                    Ok(map_id) => map_id as isize,
                    Err(e) => {
                        log::error!("sys_bpf: MAP_CREATE failed: {}", e);
                        bpf_error_errno(e)
                    }
                }
            } else {
                -1
            }
        }
        BPF_MAP_LOOKUP_ELEM => {
            log::debug!("sys_bpf: MAP_LOOKUP_ELEM");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            let map_id = attr.map_fd;
            let key_ptr = attr.key as *const u8;
            let value_ptr = attr.value as *mut u8;

            if key_ptr.is_null() || value_ptr.is_null() {
                return -1;
            }

            if let Some(manager) = BPF_MANAGER.get() {
                let mgr = manager.lock();

                // Get map definition to determine key size
                let key_size = match mgr.get_map_def_for(owner, map_id) {
                    Ok(def) => def.key_size as usize,
                    Err(error) => return bpf_error_errno(error),
                };

                let key = match read_userspace_slice(key_ptr as usize, key_size) {
                    Ok(k) => k,
                    Err(_) => return -1,
                };

                match mgr.map_lookup_for(owner, map_id, &key) {
                    Ok(Some(value)) => {
                        if copy_to_userspace(value_ptr as usize, &value).is_err() {
                            return -1;
                        }
                        0
                    }
                    Ok(None) => -2,
                    Err(error) => bpf_error_errno(error),
                }
            } else {
                -1
            }
        }
        BPF_MAP_UPDATE_ELEM => {
            log::debug!("sys_bpf: MAP_UPDATE_ELEM");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            let map_id = attr.map_fd;
            let key_ptr = attr.key as *const u8;
            let value_ptr = attr.value as *const u8;
            let flags = attr.flags;

            if key_ptr.is_null() || value_ptr.is_null() {
                return -1;
            }

            if let Some(manager) = BPF_MANAGER.get() {
                let mgr = manager.lock();

                // Get map definition to determine sizes
                let (key_size, value_size) = match mgr.get_map_def_for(owner, map_id) {
                    Ok(def) => (def.key_size as usize, def.value_size as usize),
                    Err(error) => return bpf_error_errno(error),
                };

                let key = match read_userspace_slice(key_ptr as usize, key_size) {
                    Ok(k) => k,
                    Err(_) => return -1,
                };

                let value = match read_userspace_slice(value_ptr as usize, value_size) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };

                match mgr.map_update_for(owner, map_id, &key, &value, flags) {
                    Ok(_) => 0,
                    Err(e) => {
                        log::error!("sys_bpf: MAP_UPDATE failed: {}", e);
                        bpf_error_errno(e)
                    }
                }
            } else {
                -1
            }
        }
        BPF_MAP_DELETE_ELEM => {
            log::debug!("sys_bpf: MAP_DELETE_ELEM");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            let map_id = attr.map_fd;
            let key_ptr = attr.key as *const u8;

            if key_ptr.is_null() {
                return -1;
            }

            if let Some(manager) = BPF_MANAGER.get() {
                let mgr = manager.lock();

                // Get map definition to determine key size
                let key_size = match mgr.get_map_def_for(owner, map_id) {
                    Ok(def) => def.key_size as usize,
                    Err(error) => return bpf_error_errno(error),
                };

                let key = match read_userspace_slice(key_ptr as usize, key_size) {
                    Ok(k) => k,
                    Err(_) => return -1,
                };

                match mgr.map_delete_for(owner, map_id, &key) {
                    Ok(_) => 0,
                    Err(error) => bpf_error_errno(error),
                }
            } else {
                -1
            }
        }
        BPF_OBJ_PIN => {
            log::info!("sys_bpf: OBJ_PIN");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            let map_id = attr.map_fd;
            if attr.path_len == 0 || attr.path_len as usize > crate::bpf::BPF_PIN_PATH_MAX {
                return -22;
            }
            let path = match read_userspace_string(attr.pathname as usize, attr.path_len as usize) {
                Ok(path) => path,
                Err(_) => return -1,
            };

            if let Some(manager) = BPF_MANAGER.get() {
                match manager.lock().pin_map_for(owner, path, map_id) {
                    Ok(()) => 0,
                    Err(e) => {
                        log::error!("sys_bpf: OBJ_PIN failed: {}", e);
                        bpf_error_errno(e)
                    }
                }
            } else {
                -1
            }
        }
        BPF_OBJ_GET => {
            log::info!("sys_bpf: OBJ_GET");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            if attr.path_len == 0 || attr.path_len as usize > crate::bpf::BPF_PIN_PATH_MAX {
                return -22;
            }
            let path = match read_userspace_string(attr.pathname as usize, attr.path_len as usize) {
                Ok(path) => path,
                Err(_) => return -1,
            };

            if let Some(manager) = BPF_MANAGER.get() {
                match manager.lock().get_pinned_map_for(owner, &path) {
                    Ok(map_id) => map_id as isize,
                    Err(error) => bpf_error_errno(error),
                }
            } else {
                -1
            }
        }
        BPF_OBJ_GET_INFO_BY_FD => {
            log::debug!("sys_bpf: OBJ_GET_INFO_BY_FD");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            if attr.info == 0 || (attr.info_len as usize) < size_of::<BpfObjectInfo>() {
                return -1;
            }

            if let Some(manager) = BPF_MANAGER.get() {
                let info = match manager.lock().get_map_info_for(owner, attr.map_fd) {
                    Ok(info) => info,
                    Err(error) => return bpf_error_errno(error),
                };
                if copy_to_userspace(attr.info as usize, info.as_bytes()).is_err() {
                    return -1;
                }
                size_of::<BpfObjectInfo>() as isize
            } else {
                -1
            }
        }
        BPF_PROG_ATTACH => {
            log::info!("sys_bpf: PROG_ATTACH");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            log::info!(
                "sys_bpf: PROG_ATTACH attr: attach_btf_id={}, attach_prog_fd={}, map_fd={}",
                attr.attach_btf_id,
                attr.attach_prog_fd,
                attr.map_fd
            );

            let attach_type = attr.attach_btf_id;
            let prog_id = attr.attach_prog_fd;

            #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
            if attach_type == crate::bpf::ATTACH_TYPE_GPIO {
                // Use key as GPIO pin number, value as edge flags.
                // edge flags: 1 = rising, 2 = falling, 3 = both
                let pin = match u8::try_from(attr.key) {
                    Ok(pin) if pin < 28 => pin,
                    _ => {
                        log::warn!("sys_bpf: invalid GPIO pin {} (must be 0-27)", attr.key);
                        return -1;
                    }
                };
                let edge_flags = match u32::try_from(attr.value) {
                    Ok(flags) => flags,
                    Err(_) => {
                        log::warn!("sys_bpf: invalid GPIO edge flags {}", attr.value);
                        return -1;
                    }
                };
                let edge = kernel_bpf::attach::GpioEdge::from_flags(edge_flags);

                if let Some(manager) = BPF_MANAGER.get() {
                    match manager
                        .lock()
                        .attach_gpio_route_for(owner, 0, pin, edge, prog_id)
                    {
                        Ok(_) => {
                            log::info!(
                                "sys_bpf: attached prog {} to type {}",
                                prog_id,
                                attach_type
                            );

                            // SAFETY: Rp1Gpio::new() creates an interface to memory-mapped
                            // GPIO registers. This is safe because:
                            // 1. We are on aarch64 with rpi5 feature enabled (checked by cfg)
                            // 2. The GPIO base address is hardcoded for RPi5 platform
                            // 3. We have validated the pin number is in range 0-27
                            // 4. The kernel has exclusive access to GPIO hardware
                            let gpio = unsafe {
                                crate::arch::aarch64::platform::rpi5::gpio::Rp1Gpio::new()
                            };

                            gpio.configure_input(pin);

                            let rising = (edge_flags & 1) != 0;
                            let falling = (edge_flags & 2) != 0;
                            let (rising, falling) = if !rising && !falling {
                                (true, true)
                            } else {
                                (rising, falling)
                            };

                            gpio.enable_interrupt(pin, rising, falling);
                            log::info!(
                                "sys_bpf: enabled GPIO{} interrupt (rising={}, falling={})",
                                pin,
                                rising,
                                falling
                            );
                            return 0;
                        }
                        Err(e) => {
                            log::error!("sys_bpf: attach failed: {}", e);
                            return -1;
                        }
                    }
                } else {
                    return -1;
                }
            }

            if let Some(manager) = BPF_MANAGER.get() {
                let attach_result = manager.lock().attach_for(owner, attach_type, prog_id);
                match attach_result {
                    Ok(_) => {
                        log::info!("sys_bpf: attached prog {} to type {}", prog_id, attach_type);

                        // For PWM attach type, also configure hardware if needed
                        #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
                        if attach_type == crate::bpf::ATTACH_TYPE_PWM {
                            // key = chip_id (0 or 1), value = channel (0-3)
                            // In this simple implementation, we assume key/value are passed directly in attr.key/value
                            // which are u64 pointers. But wait, in the syscall handler above for GPIO
                            // we cast attr.key as u8 directly?
                            // Let's check the struct BpfAttr definition in kernel_abi.
                            //
                            // pub struct BpfAttr {
                            //    pub test: u32,
                            //    ...
                            //    pub key: u64,    // For map ops this is a pointer. For attach, it can be value?
                            //    pub value: u64,
                            // }
                            //
                            // Yes, in rk_cli/demos we are setting key/value to integer values for attach.

                            let chip_id = attr.key as u8;
                            let channel = attr.value as u8;

                            if chip_id <= 1 && channel <= 3 {
                                // SAFETY: Rp1Pwm::pwm0/1 accesses valid MMIO.
                                // The kernel has exclusive access.
                                let _pwm = unsafe {
                                    if chip_id == 0 {
                                        crate::arch::aarch64::platform::rpi5::pwm::Rp1Pwm::pwm0()
                                    } else {
                                        crate::arch::aarch64::platform::rpi5::pwm::Rp1Pwm::pwm1()
                                    }
                                };

                                // Enable the channel so BPF hooks can trigger
                                // We don't change frequency/duty here, just ensure it's active
                                // The user should configure it via PWM syscalls separately if they want output.
                                // But for *observation*, we might just need to ensure the driver knows we are watching.
                                // The driver triggers hooks in set_duty_cycle/etc.

                                log::info!(
                                    "sys_bpf: attached BPF to PWM chip={} channel={}",
                                    chip_id,
                                    channel
                                );
                            } else {
                                log::warn!(
                                    "sys_bpf: invalid PWM chip={} or channel={}",
                                    chip_id,
                                    channel
                                );
                            }
                        }
                        if attach_type == crate::bpf::ATTACH_TYPE_IIO {
                            log::info!(
                                "sys_bpf: attached BPF program {} to IIO sensor event",
                                prog_id
                            );
                            // In a full implementation, we would use attr.key and attr.value
                            // to identify the specific sensor device and channel to enable.
                        }

                        0
                    }
                    Err(e) => {
                        log::error!("sys_bpf: attach failed: {}", e);
                        -1
                    }
                }
            } else {
                -1
            }
        }
        BPF_PROG_DETACH => {
            log::info!("sys_bpf: PROG_DETACH");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            let attach_type = attr.attach_btf_id;
            let prog_id = attr.attach_prog_fd;

            if let Some(manager) = BPF_MANAGER.get() {
                match manager.lock().detach_for(owner, attach_type, prog_id) {
                    Ok(_) => {
                        log::info!(
                            "sys_bpf: detached prog {} from type {}",
                            prog_id,
                            attach_type
                        );

                        // For GPIO, we might want to disable hardware interrupt if no more
                        // programs are attached, but BpfManager doesn't track per-pin
                        // attachments yet. This is a known limitation.

                        0
                    }
                    Err(e) => {
                        log::error!("sys_bpf: detach failed: {}", e);
                        -1
                    }
                }
            } else {
                -1
            }
        }
        BPF_PROG_UNLOAD => {
            log::info!("sys_bpf: PROG_UNLOAD");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -14,
            };
            let Some(manager) = BPF_MANAGER.get() else {
                return -2;
            };
            match manager
                .lock()
                .unload_program_for(owner, attr.attach_prog_fd)
            {
                Ok(()) => 0,
                Err(error) => bpf_error_errno(error),
            }
        }
        BPF_MAP_DESTROY => {
            log::info!("sys_bpf: MAP_DESTROY");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -14,
            };
            let Some(manager) = BPF_MANAGER.get() else {
                return -2;
            };
            match manager.lock().destroy_map_for(owner, attr.map_fd) {
                Ok(()) => 0,
                Err(error) => bpf_error_errno(error),
            }
        }
        BPF_OBJ_UNPIN => {
            log::info!("sys_bpf: OBJ_UNPIN");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -14,
            };
            if attr.path_len == 0 || attr.path_len as usize > crate::bpf::BPF_PIN_PATH_MAX {
                return -22;
            }
            let path = match read_userspace_string(attr.pathname as usize, attr.path_len as usize) {
                Ok(path) => path,
                Err(_) => return -14,
            };
            let Some(manager) = BPF_MANAGER.get() else {
                return -2;
            };
            match manager.lock().unpin_map_for(owner, &path) {
                Ok(()) => 0,
                Err(error) => bpf_error_errno(error),
            }
        }
        BPF_PROG_LOAD => {
            log::info!("sys_bpf: PROG_LOAD");

            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            let insn_cnt = attr.insn_cnt as usize;
            let insns_ptr = attr.insns as *const BpfInsn;

            if insns_ptr.is_null() || insn_cnt == 0 || insn_cnt > 4096 {
                log::error!(
                    "sys_bpf: invalid instructions (ptr={:p}, cnt={})",
                    insns_ptr,
                    insn_cnt
                );
                return -1;
            }

            log::info!("sys_bpf: loading {} instructions", insn_cnt);

            let mut insns = Vec::with_capacity(insn_cnt);
            // safe cast because we validate the pointer below
            let insns_bytes_ptr = insns_ptr as usize;

            // Validate the entire instruction buffer first
            if read_userspace_slice(insns_bytes_ptr, insn_cnt * size_of::<BpfInsn>()).is_err() {
                log::error!("sys_bpf: invalid instruction buffer");
                return -1;
            }

            for i in 0..insn_cnt {
                match copy_from_userspace::<BpfInsn>(insns_bytes_ptr + i * size_of::<BpfInsn>()) {
                    Ok(insn) => insns.push(insn),
                    Err(_) => return -1,
                }
            }

            if let Some(manager) = BPF_MANAGER.get() {
                match manager.lock().load_raw_program_for(owner, insns) {
                    Ok(id) => {
                        log::info!("sys_bpf: program loaded with id {}", id);
                        id as isize
                    }
                    Err(e) => {
                        log::error!("sys_bpf: failed to load program: {}", e);
                        bpf_error_errno(e)
                    }
                }
            } else {
                log::error!("sys_bpf: BPF_MANAGER not initialized");
                -1
            }
        }
        BPF_PROG_LOAD_ELF => {
            log::info!("sys_bpf: PROG_LOAD_ELF");

            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            // reusing insn_cnt for file size and insns for file pointer
            let file_size = attr.insn_cnt as usize;
            let file_ptr = attr.insns as usize;

            if file_ptr == 0 || file_size == 0 || file_size > 1024 * 1024 {
                log::error!(
                    "sys_bpf: invalid ELF file (ptr={:#x}, size={})",
                    file_ptr,
                    file_size
                );
                return -1;
            }

            log::info!("sys_bpf: loading ELF file of {} bytes", file_size);

            let elf_bytes = match read_userspace_slice(file_ptr, file_size) {
                Ok(bytes) => bytes,
                Err(_) => {
                    log::error!("sys_bpf: failed to read ELF bytes from userspace");
                    return -1;
                }
            };

            if let Some(manager) = BPF_MANAGER.get() {
                match manager.lock().load_program_for(owner, &elf_bytes) {
                    Ok(id) => {
                        log::info!("sys_bpf: ELF program loaded with id {}", id);
                        id as isize
                    }
                    Err(e) => {
                        log::error!("sys_bpf: failed to load ELF program: {}", e);
                        bpf_error_errno(e)
                    }
                }
            } else {
                log::error!("sys_bpf: BPF_MANAGER not initialized");
                -1
            }
        }
        BPF_RINGBUF_POLL => {
            log::debug!("sys_bpf: RINGBUF_POLL");
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };

            // For RINGBUF_POLL:
            //   map_fd  -> map_id (which ringbuf to poll)
            //   key     -> buf_ptr (userspace buffer to write event data into)
            //   value   -> buf_size (capacity of the userspace buffer)
            let map_id = attr.map_fd;
            let buf_ptr = attr.key as usize;
            let buf_size = attr.value as usize;

            if buf_ptr == 0 || buf_size == 0 {
                return -1; // EINVAL
            }

            if let Some(manager) = BPF_MANAGER.get() {
                let mgr = manager.lock();
                match mgr.ringbuf_poll_for(owner, map_id) {
                    Ok(Some(data)) => {
                        if data.len() > buf_size {
                            log::warn!(
                                "sys_bpf: RINGBUF_POLL buffer too small ({} < {})",
                                buf_size,
                                data.len()
                            );
                            return -28; // ENOSPC
                        }
                        if copy_to_userspace(buf_ptr, &data).is_err() {
                            return -1; // EFAULT
                        }
                        data.len() as isize
                    }
                    Ok(None) => 0, // No event available
                    Err(error) => bpf_error_errno(error),
                }
            } else {
                -1
            }
        }
        // Verifier-cost instrumentation: time `runs` back-to-back executions
        // of a loaded program and emit an `AXIOM EXEC COST` serial marker.
        // Only compiled into measurement builds; absent the feature the
        // command falls through to "unknown" below. The program is cloned and
        // run with the manager lock released (helpers re-acquire it).
        #[cfg(feature = "verifier-cost")]
        kernel_abi::BPF_BENCH_EXEC => {
            let attr = match copy_from_userspace::<BpfAttr>(attr_ptr) {
                Ok(a) => a,
                Err(_) => return -1,
            };
            let prog_id = attr.attach_prog_fd;
            let runs = attr.attach_btf_id.max(1);

            let Some(manager) = BPF_MANAGER.get() else {
                return -1;
            };
            let program = match manager.lock().get_program_for(owner, prog_id) {
                Ok(program) => program,
                Err(error) => {
                    log::error!("sys_bpf: BENCH_EXEC denied for prog id {}", prog_id);
                    return bpf_error_errno(error);
                }
            };
            match crate::bpf::BpfManager::bench_execute(&program, prog_id, runs) {
                Ok(()) => 0,
                Err(e) => {
                    log::error!("sys_bpf: BENCH_EXEC prog {} failed: {}", prog_id, e);
                    -1
                }
            }
        }

        _ => {
            log::warn!("sys_bpf: Unknown command {}", cmd);
            -1
        }
    }
}
