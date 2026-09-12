//! RP1 PCIe MSI-X routing for Raspberry Pi 5.
//!
//! The Pi firmware leaves PCIe2 trained when `pciex4_reset=0`, but that does
//! not make an RP1 peripheral interrupt usable by itself. This module completes
//! the route for RP1 vector 0 (IO_BANK0):
//!
//! RP1 source -> RP1 MSI-X table -> BCM2712 MIP0 -> GIC SPI 128 (ID 160).

use core::ptr::{read_volatile, write_volatile};

use super::memory_map::{
    BCM2712_MIP0_BASE, BCM2712_MIP0_BASE_PHYS, BCM2712_PCIE2_BASE, RP1_PCIE_APBS_BASE,
    RP1_PERIPHERAL_BASE, RP1_PERIPHERAL_BASE_PHYS,
};

const RP1_VENDOR_DEVICE: u32 = 0x0001_1DE4;
const RP1_CHIP_ID: u32 = 0x2000_1927;
const PCI_CONFIG_READ_ERROR: u32 = 0xDEAD_DEAD;

const PCIE_LINK_STATUS: usize = 0x4068;
const PCIE_LINK_UP: u32 = (1 << 4) | (1 << 5);
const PCIE_OUT_WIN0_LO: usize = 0x400C;
const PCIE_OUT_WIN0_HI: usize = 0x4010;
const PCIE_OUT_WIN0_BASE_LIMIT: usize = 0x4070;
const PCIE_OUT_WIN0_BASE_HI: usize = 0x4080;
const PCIE_OUT_WIN0_LIMIT_HI: usize = 0x4084;
const PCIE_RC_BAR1_CONFIG_LO: usize = 0x402C;
const PCIE_RC_BAR1_CONFIG_HI: usize = 0x4030;
const PCIE_UBUS_BAR1_REMAP_LO: usize = 0x40AC;
const PCIE_UBUS_BAR1_REMAP_HI: usize = 0x40B0;
const PCIE_CONFIG_DATA: usize = 0x8000;
const PCIE_CONFIG_ADDRESS: usize = 0x9000;

const PCI_COMMAND_STATUS: usize = 0x04;
/// Type-1 header bus numbers: primary [7:0], secondary [15:8], subordinate
/// [23:16]. RP1 is the only device below PCIe2, so bus 1 is both the secondary
/// and the subordinate bus.
const PCI_PRIMARY_BUS: usize = 0x18;
const RC_BUS_NUMBERS: u32 = 0x0001_0100;
const RC_BUS_MASK: u32 = 0x00FF_FFFF;
const PCI_BAR0: usize = 0x10;
const PCI_BAR1: usize = 0x14;
const PCI_BAR2: usize = 0x18;
const PCI_CAP_PTR: usize = 0x34;
const PCI_COMMAND_MEMORY: u32 = 1 << 1;
const PCI_COMMAND_MASTER: u32 = 1 << 2;
const PCI_COMMAND_INTX_DISABLE: u32 = 1 << 10;
const PCI_CAP_ID_MSIX: u32 = 0x11;
const PCI_MSIX_FUNCTION_MASK: u32 = 1 << 30;
const PCI_MSIX_ENABLE: u32 = 1 << 31;

// axiomos owns this aperture after boot. Match the RP1 layout used by the
// official DT and by known bare-metal implementations: BAR1 peripherals at
// PCIe 0, BAR2 SRAM at 4 MiB, BAR0 MSI-X table at 8 MiB.
const RP1_BAR1_PCI: u32 = 0x0000_0000;
const RP1_BAR2_PCI: u32 = 0x0040_0000;
const RP1_BAR0_PCI: u32 = 0x0080_0000;
const RP1_OUTBOUND_SIZE_MIB: u32 = 9;

const RP1_IO_BANK0_OFFSET: usize = 0x000D_0000;
const RP1_IO_BANK0_PCIE_INTE: usize = 0x11C;
const RP1_IO_BANK0_ATOMIC_SET: usize = 0x2000;
const RP1_IO_BANK0_ATOMIC_CLEAR: usize = 0x3000;
const RP1_GPIO_CTRL: usize = 0x04;
const RP1_GPIO_STRIDE: usize = 0x08;
const RP1_GPIO_COUNT: usize = 28;
const RP1_GPIO_EVENT_ENABLE_MASK: u32 = 0xF << 20;
const RP1_GPIO_IRQRESET: u32 = 1 << 28;

const MIP_MESSAGE_ADDRESS: u64 = 0x00FF_FFFF_F000;
const MIP_INT_CFGL_HOST: usize = 0x20;
const MIP_INT_CFGH_HOST: usize = 0x30;
const MIP_INT_MASKL_HOST: usize = 0x40;
const MIP_INT_MASKH_HOST: usize = 0x50;
const MIP_INT_MASKL_VPU: usize = 0x60;
const MIP_INT_MASKH_VPU: usize = 0x70;

const MSIX_CFG_0: usize = 0x008;
const RP1_PCIE_REG_SET: usize = 0x800;
const RP1_PCIE_REG_CLEAR: usize = 0xC00;
const MSIX_CFG_ENABLE: u32 = 1 << 0;
const MSIX_CFG_IACK: u32 = 1 << 2;
const MSIX_CFG_IACK_ENABLE: u32 = 1 << 3;

const MSI_VECTOR_IO_BANK0: usize = 0;
const MSIX_ENTRY_SIZE: usize = 16;
const RP1_MSIX_BAR_SIZE: usize = 0x1_0000;

/// Readbacks proving that every programmable stage of the GPIO route accepted
/// its configuration.
#[derive(Debug, Clone, Copy)]
pub struct Rp1InterruptRoute {
    pub pcie_link_status: u32,
    pub vendor_device: u32,
    pub chip_id: u32,
    pub msix_cap_offset: u8,
    pub msix_table_size: u16,
    pub msix_control: u32,
    pub vector0_config: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rp1InterruptRouteError {
    PcieLinkDown(u32),
    RootBusReadback(u32),
    EndpointUnavailable(u32),
    MissingMsixCapability,
    InvalidMsixCapability(u32),
    InvalidBarConfiguration { bar0: u32, bar1: u32, bar2: u32 },
    InvalidMsixTable { bir: u8, offset: u32, size: u16 },
    Rp1BarUnavailable(u32),
    InboundWindowReadback,
    MipReadback,
    MsixTableReadback,
    Rp1VectorReadback(u32),
    GlobalMsixReadback(u32),
}

#[inline(always)]
fn device_sync() {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: This is an ordering barrier only; it does not access memory.
    unsafe {
        core::arch::asm!("dsb osh", options(nostack, preserves_flags));
    }
}

#[inline(always)]
fn read32(addr: usize) -> u32 {
    device_sync();
    // SAFETY: Every caller supplies an aligned address in a mapped device
    // aperture owned by this platform driver.
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn write32(addr: usize, value: u32) {
    // SAFETY: Every caller supplies an aligned address in a mapped device
    // aperture owned by this platform driver.
    unsafe { write_volatile(addr as *mut u32, value) };
    device_sync();
}

struct Rp1Config;

impl Rp1Config {
    #[inline]
    fn select() {
        // Bus 1, device 0, function 0, register 0. The register offset is
        // applied through PCIE_CONFIG_DATA below.
        write32(BCM2712_PCIE2_BASE + PCIE_CONFIG_ADDRESS, 1 << 20);
    }

    #[inline]
    fn read(offset: usize) -> u32 {
        Self::select();
        read32(BCM2712_PCIE2_BASE + PCIE_CONFIG_DATA + offset)
    }

    #[inline]
    fn write(offset: usize, value: u32) {
        Self::select();
        write32(BCM2712_PCIE2_BASE + PCIE_CONFIG_DATA + offset, value);
    }
}

fn find_msix_capability() -> Option<u8> {
    let mut offset = (Rp1Config::read(PCI_CAP_PTR) & 0xFC) as u8;
    // Standard PCI capabilities occupy 0x40..=0xfc and are 4-byte aligned.
    // Bound the walk so malformed firmware/device state cannot loop forever.
    for _ in 0..48 {
        if !(0x40..=0xFC).contains(&offset) || offset & 0x3 != 0 {
            return None;
        }
        let header = Rp1Config::read(offset as usize);
        if header == PCI_CONFIG_READ_ERROR || header == u32::MAX {
            return None;
        }
        if header & 0xFF == PCI_CAP_ID_MSIX {
            return Some(offset);
        }
        let next = ((header >> 8) & 0xFC) as u8;
        if next == 0 || next == offset {
            return None;
        }
        offset = next;
    }
    None
}

/// Give the root complex a bus range that contains RP1.
///
/// The Pi firmware trains PCIe2 but leaves the type-1 bus-number register at
/// zero, so the bridge's secondary/subordinate range is empty and every type-1
/// config access to bus 1 is dropped and reads back as all-ones. Nothing below
/// this bridge is reachable until the range is programmed.
fn configure_root_complex_buses() -> Result<(), Rp1InterruptRouteError> {
    let bus_numbers = read32(BCM2712_PCIE2_BASE + PCI_PRIMARY_BUS);
    if bus_numbers & RC_BUS_MASK != RC_BUS_NUMBERS {
        write32(
            BCM2712_PCIE2_BASE + PCI_PRIMARY_BUS,
            (bus_numbers & !RC_BUS_MASK) | RC_BUS_NUMBERS,
        );
    }

    // The bridge only forwards memory traffic once it owns the bus.
    let command_status = read32(BCM2712_PCIE2_BASE + PCI_COMMAND_STATUS);
    write32(
        BCM2712_PCIE2_BASE + PCI_COMMAND_STATUS,
        (command_status & 0xFFFF_0000)
            | (command_status & 0xFFFF)
            | PCI_COMMAND_MEMORY
            | PCI_COMMAND_MASTER,
    );

    let readback = read32(BCM2712_PCIE2_BASE + PCI_PRIMARY_BUS);
    if readback & RC_BUS_MASK != RC_BUS_NUMBERS {
        return Err(Rp1InterruptRouteError::RootBusReadback(readback));
    }
    Ok(())
}

fn configure_outbound_window() {
    let base_mib = (RP1_PERIPHERAL_BASE_PHYS >> 20) as u32;
    let limit_mib = base_mib + RP1_OUTBOUND_SIZE_MIB - 1;
    let base_limit = ((base_mib & 0xFFF) << 4) | ((limit_mib & 0xFFF) << 20);

    write32(BCM2712_PCIE2_BASE + PCIE_OUT_WIN0_LO, 0);
    write32(BCM2712_PCIE2_BASE + PCIE_OUT_WIN0_HI, 0);
    write32(BCM2712_PCIE2_BASE + PCIE_OUT_WIN0_BASE_LIMIT, base_limit);
    write32(
        BCM2712_PCIE2_BASE + PCIE_OUT_WIN0_BASE_HI,
        (base_mib >> 12) & 0xFF,
    );
    write32(
        BCM2712_PCIE2_BASE + PCIE_OUT_WIN0_LIMIT_HI,
        (limit_mib >> 12) & 0xFF,
    );
}

fn configure_rp1_bars() -> Result<(), Rp1InterruptRouteError> {
    let bar0 = Rp1Config::read(PCI_BAR0);
    let bar1 = Rp1Config::read(PCI_BAR1);
    let bar2 = Rp1Config::read(PCI_BAR2);
    // RP1 exposes three 32-bit memory BARs. Refuse to reinterpret an invalid
    // or unexpected header because bit 0 would turn the write into an I/O BAR.
    if [bar0, bar1, bar2]
        .iter()
        .any(|bar| *bar == PCI_CONFIG_READ_ERROR || *bar == u32::MAX || bar & 0x7 != 0)
    {
        return Err(Rp1InterruptRouteError::InvalidBarConfiguration { bar0, bar1, bar2 });
    }
    let bar0_flags = bar0 & 0xF;
    let bar1_flags = bar1 & 0xF;
    let bar2_flags = bar2 & 0xF;
    Rp1Config::write(PCI_BAR0, RP1_BAR0_PCI | bar0_flags);
    Rp1Config::write(PCI_BAR1, RP1_BAR1_PCI | bar1_flags);
    Rp1Config::write(PCI_BAR2, RP1_BAR2_PCI | bar2_flags);
    configure_outbound_window();

    let command_status = Rp1Config::read(PCI_COMMAND_STATUS);
    let command = ((command_status & 0xFFFF) | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER)
        & !PCI_COMMAND_INTX_DISABLE;
    Rp1Config::write(PCI_COMMAND_STATUS, (command_status & 0xFFFF_0000) | command);
    Ok(())
}

fn configure_mip_inbound_window() -> bool {
    // BCM2712 inbound BAR1: PCIe 0xff_ffff_f000 -> CPU 0x10_0013_0000,
    // 4 KiB. The non-linear size encoding for 4 KiB is 0x1c.
    let pci_low = (MIP_MESSAGE_ADDRESS as u32 & 0xFFFF_F000) | 0x1C;
    let pci_high = (MIP_MESSAGE_ADDRESS >> 32) as u32;
    let cpu_low = (BCM2712_MIP0_BASE_PHYS as u32 & 0xFFFF_F000) | 1;
    let cpu_high = (BCM2712_MIP0_BASE_PHYS >> 32) as u32;

    write32(BCM2712_PCIE2_BASE + PCIE_RC_BAR1_CONFIG_LO, pci_low);
    write32(BCM2712_PCIE2_BASE + PCIE_RC_BAR1_CONFIG_HI, pci_high);
    write32(BCM2712_PCIE2_BASE + PCIE_UBUS_BAR1_REMAP_LO, cpu_low);
    write32(BCM2712_PCIE2_BASE + PCIE_UBUS_BAR1_REMAP_HI, cpu_high);

    read32(BCM2712_PCIE2_BASE + PCIE_RC_BAR1_CONFIG_LO) == pci_low
        && read32(BCM2712_PCIE2_BASE + PCIE_RC_BAR1_CONFIG_HI) == pci_high
        && read32(BCM2712_PCIE2_BASE + PCIE_UBUS_BAR1_REMAP_LO) == cpu_low
        && read32(BCM2712_PCIE2_BASE + PCIE_UBUS_BAR1_REMAP_HI) == cpu_high
}

fn quiesce_io_bank0() {
    let io_bank0 = RP1_PERIPHERAL_BASE + RP1_IO_BANK0_OFFSET;
    write32(
        io_bank0 + RP1_IO_BANK0_ATOMIC_CLEAR + RP1_IO_BANK0_PCIE_INTE,
        (1 << RP1_GPIO_COUNT) - 1,
    );
    for pin in 0..RP1_GPIO_COUNT {
        let ctrl = pin * RP1_GPIO_STRIDE + RP1_GPIO_CTRL;
        write32(
            io_bank0 + RP1_IO_BANK0_ATOMIC_CLEAR + ctrl,
            RP1_GPIO_EVENT_ENABLE_MASK,
        );
        write32(io_bank0 + RP1_IO_BANK0_ATOMIC_SET + ctrl, RP1_GPIO_IRQRESET);
    }
}

fn configure_mip() -> bool {
    // Match the official bcm2712-mip initialization: host unmasked, VPU
    // masked, all MSI inputs edge-triggered. MSI-X entries other than vector 0
    // remain masked at the endpoint below.
    write32(BCM2712_MIP0_BASE + MIP_INT_MASKL_HOST, 0);
    write32(BCM2712_MIP0_BASE + MIP_INT_MASKH_HOST, 0);
    write32(BCM2712_MIP0_BASE + MIP_INT_MASKL_VPU, u32::MAX);
    write32(BCM2712_MIP0_BASE + MIP_INT_MASKH_VPU, u32::MAX);
    write32(BCM2712_MIP0_BASE + MIP_INT_CFGL_HOST, u32::MAX);
    write32(BCM2712_MIP0_BASE + MIP_INT_CFGH_HOST, u32::MAX);

    read32(BCM2712_MIP0_BASE + MIP_INT_MASKL_HOST) == 0
        && read32(BCM2712_MIP0_BASE + MIP_INT_MASKH_HOST) == 0
        && read32(BCM2712_MIP0_BASE + MIP_INT_MASKL_VPU) == u32::MAX
        && read32(BCM2712_MIP0_BASE + MIP_INT_MASKH_VPU) == u32::MAX
        && read32(BCM2712_MIP0_BASE + MIP_INT_CFGL_HOST) == u32::MAX
        && read32(BCM2712_MIP0_BASE + MIP_INT_CFGH_HOST) == u32::MAX
}

fn configure_msix_table(table_offset: usize, table_size: usize) -> bool {
    let table = RP1_PERIPHERAL_BASE + RP1_BAR0_PCI as usize + table_offset;

    // Mask every advertised RP1 vector before enabling MSI-X globally. This
    // kernel currently owns only vector 0.
    for vector in 0..table_size {
        write32(table + vector * MSIX_ENTRY_SIZE + 12, 1);
    }

    write32(table, MIP_MESSAGE_ADDRESS as u32);
    write32(table + 4, (MIP_MESSAGE_ADDRESS >> 32) as u32);
    write32(table + 8, MSI_VECTOR_IO_BANK0 as u32);
    write32(table + 12, 0);

    read32(table) == MIP_MESSAGE_ADDRESS as u32
        && read32(table + 4) == (MIP_MESSAGE_ADDRESS >> 32) as u32
        && read32(table + 8) == MSI_VECTOR_IO_BANK0 as u32
        && read32(table + 12) & 1 == 0
}

/// Complete and validate the RP1 IO_BANK0 -> MIP0 -> GIC MSI-X route.
pub fn initialize_gpio_route() -> Result<Rp1InterruptRoute, Rp1InterruptRouteError> {
    let pcie_link_status = read32(BCM2712_PCIE2_BASE + PCIE_LINK_STATUS);
    if pcie_link_status & PCIE_LINK_UP != PCIE_LINK_UP {
        return Err(Rp1InterruptRouteError::PcieLinkDown(pcie_link_status));
    }

    configure_root_complex_buses()?;

    let vendor_device = Rp1Config::read(0);

    if vendor_device != RP1_VENDOR_DEVICE {
        return Err(Rp1InterruptRouteError::EndpointUnavailable(vendor_device));
    }

    let msix_cap_offset =
        find_msix_capability().ok_or(Rp1InterruptRouteError::MissingMsixCapability)?;
    let initial_msix_control = Rp1Config::read(msix_cap_offset as usize);
    if initial_msix_control == PCI_CONFIG_READ_ERROR || initial_msix_control == u32::MAX {
        return Err(Rp1InterruptRouteError::InvalidMsixCapability(
            initial_msix_control,
        ));
    }

    // Stop message generation while BARs and the table move.
    Rp1Config::write(
        msix_cap_offset as usize,
        (initial_msix_control | PCI_MSIX_FUNCTION_MASK) & !PCI_MSIX_ENABLE,
    );
    configure_rp1_bars()?;

    let chip_id = read32(RP1_PERIPHERAL_BASE);
    if chip_id != RP1_CHIP_ID {
        return Err(Rp1InterruptRouteError::Rp1BarUnavailable(chip_id));
    }

    // The old BAR may have been absent before reconfiguration, so repeat the
    // warm-reboot quiesce against the now-validated IO_BANK0 aperture.
    quiesce_io_bank0();

    // Clear firmware/warm-reset leftovers, especially TEST, before the route is
    // connected to MIP0. The RP1 PCIe configuration block uses +0xc00 as its
    // atomic clear alias (unlike ordinary RP1 peripherals, which use +0x3000).
    write32(
        RP1_PCIE_APBS_BASE + RP1_PCIE_REG_CLEAR + MSIX_CFG_0,
        u32::MAX,
    );

    let table_info = Rp1Config::read(msix_cap_offset as usize + 4);
    let table_bir = (table_info & 0x7) as u8;
    let table_offset = (table_info & !0x7) as usize;
    let table_size = (((initial_msix_control >> 16) & 0x7FF) + 1) as u16;
    let table_end = table_offset.saturating_add(table_size as usize * MSIX_ENTRY_SIZE);
    if table_bir != 0 || table_size == 0 || table_size > 64 || table_end > RP1_MSIX_BAR_SIZE {
        return Err(Rp1InterruptRouteError::InvalidMsixTable {
            bir: table_bir,
            offset: table_offset as u32,
            size: table_size,
        });
    }

    if !configure_mip_inbound_window() {
        return Err(Rp1InterruptRouteError::InboundWindowReadback);
    }
    if !configure_mip() {
        return Err(Rp1InterruptRouteError::MipReadback);
    }
    if !configure_msix_table(table_offset, table_size as usize) {
        return Err(Rp1InterruptRouteError::MsixTableReadback);
    }

    // Enable RP1 vector 0 and its level-source acknowledge handshake.
    write32(
        RP1_PCIE_APBS_BASE + RP1_PCIE_REG_SET + MSIX_CFG_0,
        MSIX_CFG_ENABLE | MSIX_CFG_IACK_ENABLE,
    );
    let vector0_config = read32(RP1_PCIE_APBS_BASE + MSIX_CFG_0);
    if vector0_config == PCI_CONFIG_READ_ERROR
        || vector0_config & (MSIX_CFG_ENABLE | MSIX_CFG_IACK_ENABLE)
            != MSIX_CFG_ENABLE | MSIX_CFG_IACK_ENABLE
    {
        return Err(Rp1InterruptRouteError::Rp1VectorReadback(vector0_config));
    }

    // Enable MSI-X globally only after all downstream state is installed.
    Rp1Config::write(
        msix_cap_offset as usize,
        (initial_msix_control | PCI_MSIX_ENABLE) & !PCI_MSIX_FUNCTION_MASK,
    );
    let msix_control = Rp1Config::read(msix_cap_offset as usize);
    if msix_control & (PCI_MSIX_ENABLE | PCI_MSIX_FUNCTION_MASK) != PCI_MSIX_ENABLE {
        return Err(Rp1InterruptRouteError::GlobalMsixReadback(msix_control));
    }

    Ok(Rp1InterruptRoute {
        pcie_link_status,
        vendor_device,
        chip_id,
        msix_cap_offset,
        msix_table_size: table_size,
        msix_control,
        vector0_config,
    })
}

/// Acknowledge RP1 vector 0 after IO_BANK0's asserted sources are cleared.
#[inline]
pub fn acknowledge_gpio_vector() {
    write32(
        RP1_PCIE_APBS_BASE + RP1_PCIE_REG_SET + MSIX_CFG_0,
        MSIX_CFG_IACK,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_window_encodes_nine_mib_at_rp1_aperture() {
        let base_mib = (RP1_PERIPHERAL_BASE_PHYS >> 20) as u32;
        let limit_mib = base_mib + RP1_OUTBOUND_SIZE_MIB - 1;
        let encoded = ((base_mib & 0xFFF) << 4) | ((limit_mib & 0xFFF) << 20);
        assert_eq!(base_mib, 0x1F000);
        assert_eq!(limit_mib, 0x1F008);
        assert_eq!(encoded, 0x0080_0000);
    }

    #[test]
    fn mip_window_encoding_matches_bcm2712_register_format() {
        assert_eq!(
            (MIP_MESSAGE_ADDRESS as u32 & 0xFFFF_F000) | 0x1C,
            0xFFFF_F01C
        );
        assert_eq!((MIP_MESSAGE_ADDRESS >> 32) as u32, 0xFF);
        assert_eq!(
            (BCM2712_MIP0_BASE_PHYS as u32 & 0xFFFF_F000) | 1,
            0x0013_0001
        );
        assert_eq!((BCM2712_MIP0_BASE_PHYS >> 32) as u32, 0x10);
    }
}
