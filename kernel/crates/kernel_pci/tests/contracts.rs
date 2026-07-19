use std::sync::{Arc, Mutex};

use kernel_pci::PciAddress;
use kernel_pci::config::{ConfigKey, ConfigurationAccess, ReadConfig, WriteConfig};

#[derive(Debug, Default)]
struct Writes {
    u8_values: Vec<(PciAddress, ConfigKey<u8>, u8)>,
    u16_values: Vec<(PciAddress, ConfigKey<u16>, u16)>,
    u32_values: Vec<(PciAddress, ConfigKey<u32>, u32)>,
}

#[derive(Debug, Clone)]
struct ConfigFixture {
    header_type: u8,
    writes: Arc<Mutex<Writes>>,
}

impl ConfigFixture {
    fn new(header_type: u8) -> Self {
        Self {
            header_type,
            writes: Arc::new(Mutex::new(Writes::default())),
        }
    }
}

impl ReadConfig<u8> for ConfigFixture {
    fn read_config(&self, addr: PciAddress, config: ConfigKey<u8>) -> u8 {
        assert_eq!(addr, PciAddress::new(0x0a, 0x1f, 7));
        assert_eq!(config, ConfigKey::HEADER_TYPE);
        self.header_type
    }
}

impl ReadConfig<u16> for ConfigFixture {
    fn read_config(&self, addr: PciAddress, config: ConfigKey<u16>) -> u16 {
        assert_eq!(addr, PciAddress::new(0x0a, 0x1f, 7));
        if config == ConfigKey::VENDOR_ID {
            0x1af4
        } else if config == ConfigKey::DEVICE_ID {
            0x1042
        } else if config == ConfigKey::SUBSYSTEM_ID {
            0x1100
        } else {
            panic!("unexpected u16 configuration key: {config:?}");
        }
    }
}

impl ReadConfig<u32> for ConfigFixture {
    fn read_config(&self, addr: PciAddress, config: ConfigKey<u32>) -> u32 {
        assert_eq!(addr, PciAddress::new(0x0a, 0x1f, 7));
        let bars = [
            (ConfigKey::BAR0, 0x1000_0000),
            (ConfigKey::BAR1, 0x2000_0000),
            (ConfigKey::BAR2, 0x3000_0000),
            (ConfigKey::BAR3, 0x4000_0000),
            (ConfigKey::BAR4, 0x5000_0000),
            (ConfigKey::BAR5, 0x6000_0000),
        ];
        bars.into_iter()
            .find_map(|(key, value)| (config == key).then_some(value))
            .unwrap_or_else(|| panic!("unexpected u32 configuration key: {config:?}"))
    }
}

impl WriteConfig<u8> for ConfigFixture {
    fn write_config(&self, addr: PciAddress, config: ConfigKey<u8>, value: u8) {
        self.writes
            .lock()
            .unwrap()
            .u8_values
            .push((addr, config, value));
    }
}

impl WriteConfig<u16> for ConfigFixture {
    fn write_config(&self, addr: PciAddress, config: ConfigKey<u16>, value: u16) {
        self.writes
            .lock()
            .unwrap()
            .u16_values
            .push((addr, config, value));
    }
}

impl WriteConfig<u32> for ConfigFixture {
    fn write_config(&self, addr: PciAddress, config: ConfigKey<u32>, value: u32) {
        self.writes
            .lock()
            .unwrap()
            .u32_values
            .push((addr, config, value));
    }
}

#[test]
fn config_keys_enforce_width_alignment_and_offset_range() {
    assert_eq!(ConfigKey::<u8>::try_from(0x0e), Ok(ConfigKey::HEADER_TYPE));
    assert!(ConfigKey::<u8>::try_from(0xff).is_ok());
    assert_eq!(ConfigKey::<u8>::try_from(0x100), Err(0x100));

    assert_eq!(ConfigKey::<u16>::try_from(0x02), Ok(ConfigKey::DEVICE_ID));
    assert!(ConfigKey::<u16>::try_from(0xfe).is_ok());
    assert_eq!(ConfigKey::<u16>::try_from(0x03), Err(0x03));
    assert_eq!(ConfigKey::<u16>::try_from(0x100), Err(0x100));

    assert_eq!(ConfigKey::<u32>::try_from(0x10), Ok(ConfigKey::BAR0));
    assert!(ConfigKey::<u32>::try_from(0xfc).is_ok());
    assert_eq!(ConfigKey::<u32>::try_from(0x12), Err(0x12));
    assert_eq!(ConfigKey::<u32>::try_from(0x100), Err(0x100));
}

#[test]
fn pci_address_formats_and_reads_all_public_fields() {
    let addr = PciAddress::new(0x0a, 0x1f, 7);
    let config = ConfigFixture::new(0x80);

    assert_eq!(addr.to_string(), "0a:1f.7");
    assert_eq!(addr.vendor_id(&config), 0x1af4);
    assert_eq!(addr.device_id(&config), 0x1042);
    assert_eq!(addr.header_type(&config), 0x80);
    assert_eq!(addr.bar0(&config), 0x1000_0000);
    assert_eq!(addr.bar1(&config), 0x2000_0000);
    assert_eq!(addr.bar2(&config), 0x3000_0000);
    assert_eq!(addr.bar3(&config), 0x4000_0000);
    assert_eq!(addr.bar4(&config), 0x5000_0000);
    assert_eq!(addr.bar5(&config), 0x6000_0000);
    assert_eq!(addr.subsystem_id(&config), 0x1100);
    assert!(addr.is_multifunction(&config));

    assert!(!addr.is_multifunction(&ConfigFixture::new(0x7f)));
}

#[test]
fn boxed_configuration_access_forwards_reads_and_writes() {
    let addr = PciAddress::new(0x0a, 0x1f, 7);
    let fixture = ConfigFixture::new(0);
    let writes = Arc::clone(&fixture.writes);
    let access: Box<dyn ConfigurationAccess> = Box::new(fixture);

    assert_eq!(addr.vendor_id(&access), 0x1af4);
    access.write_config(addr, ConfigKey::INTERRUPT_LINE, 11_u8);
    access.write_config(addr, ConfigKey::COMMAND, 0x0007_u16);
    access.write_config(addr, ConfigKey::BAR0, 0xdead_beef_u32);

    let writes = writes.lock().unwrap();
    assert_eq!(
        writes.u8_values,
        vec![(addr, ConfigKey::INTERRUPT_LINE, 11)]
    );
    assert_eq!(writes.u16_values, vec![(addr, ConfigKey::COMMAND, 0x0007)]);
    assert_eq!(
        writes.u32_values,
        vec![(addr, ConfigKey::BAR0, 0xdead_beef)]
    );
}

#[test]
fn mutable_trait_object_forwarders_preserve_access() {
    let addr = PciAddress::new(0x0a, 0x1f, 7);
    let mut fixture = ConfigFixture::new(0);
    let writes = Arc::clone(&fixture.writes);

    {
        let reader: &mut dyn ReadConfig<u16> = &mut fixture;
        assert_eq!(
            <&mut dyn ReadConfig<u16> as ReadConfig<u16>>::read_config(
                &reader,
                addr,
                ConfigKey::VENDOR_ID,
            ),
            0x1af4
        );
    }
    {
        let writer: &mut dyn WriteConfig<u16> = &mut fixture;
        <&mut dyn WriteConfig<u16> as WriteConfig<u16>>::write_config(
            &writer,
            addr,
            ConfigKey::COMMAND,
            0x0005,
        );
    }

    assert_eq!(
        writes.lock().unwrap().u16_values,
        vec![(addr, ConfigKey::COMMAND, 0x0005)]
    );
}
