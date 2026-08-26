//! Pure FPGA configuration/runtime contract shared by target and host tests.

pub const FPGA_STORAGE_START: u32 = 0x1020_0000;
pub const FPGA_STORAGE_END: u32 = 0x1040_0000;

pub const STATUS_READY: u8 = 1 << 7;
pub const STATUS_COMMAND_VALID: u8 = 1 << 6;
pub const STATUS_WATCHDOG_EXPIRED: u8 = 1 << 5;
const STATUS_RESERVED: u8 = 0x1f;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitstreamManifest {
    pub offset: u32,
    pub length: u32,
    pub sha256: [u8; 32],
}

impl BitstreamManifest {
    fn valid(self) -> bool {
        self.offset == FPGA_STORAGE_START
            && self.length != 0
            && self
                .offset
                .checked_add(self.length)
                .is_some_and(|end| end <= FPGA_STORAGE_END)
            && self.sha256 != [0; 32]
    }
}

/// Hardware actions whose ordering is enforced by [`FpgaLifecycle`].
pub trait FpgaPlatform {
    type Error;

    /// Drive PWR/EN/PWM low and make CS inactive.
    fn force_safe(&mut self);
    fn bitstream_sha256(&mut self, offset: u32, length: u32) -> Result<[u8; 32], Self::Error>;
    fn begin_configuration(&mut self) -> Result<(), Self::Error>;
    fn stream_bitstream(&mut self, offset: u32, length: u32) -> Result<(), Self::Error>;
    fn ready_status(&mut self) -> Result<u8, Self::Error>;
    fn handoff_to_runtime(&mut self) -> Result<(), Self::Error>;
    fn runtime_transfer(&mut self, frame: &[u8; 12]) -> Result<u8, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError<E> {
    InvalidManifest,
    InvalidReadyBound,
    InvalidCommand,
    HashMismatch,
    ReadyTimeout,
    BadStatus,
    NotReady,
    Platform(E),
}

/// Fail-closed configuration-to-runtime owner.
pub struct FpgaLifecycle<P> {
    platform: P,
    runtime_ready: bool,
}

impl<P: FpgaPlatform> FpgaLifecycle<P> {
    #[must_use]
    pub fn new(mut platform: P) -> Self {
        platform.force_safe();
        Self {
            platform,
            runtime_ready: false,
        }
    }

    pub fn configure(
        &mut self,
        manifest: BitstreamManifest,
        ready_poll_limit: u32,
    ) -> Result<(), LifecycleError<P::Error>> {
        self.platform.force_safe();
        self.runtime_ready = false;
        if !manifest.valid() {
            return Err(LifecycleError::InvalidManifest);
        }
        if ready_poll_limit == 0 {
            return Err(LifecycleError::InvalidReadyBound);
        }

        let hash = match self
            .platform
            .bitstream_sha256(manifest.offset, manifest.length)
        {
            Ok(hash) => hash,
            Err(error) => return self.abort(LifecycleError::Platform(error)),
        };
        if hash != manifest.sha256 {
            return self.abort(LifecycleError::HashMismatch);
        }
        if let Err(error) = self.platform.begin_configuration() {
            return self.abort(LifecycleError::Platform(error));
        }
        if let Err(error) = self
            .platform
            .stream_bitstream(manifest.offset, manifest.length)
        {
            return self.abort(LifecycleError::Platform(error));
        }

        for _ in 0..ready_poll_limit {
            let status = match self.platform.ready_status() {
                Ok(status) => status,
                Err(error) => return self.abort(LifecycleError::Platform(error)),
            };
            if status == 0 {
                continue;
            }
            if status != STATUS_READY {
                return self.abort(LifecycleError::BadStatus);
            }
            if let Err(error) = self.platform.handoff_to_runtime() {
                return self.abort(LifecycleError::Platform(error));
            }
            self.runtime_ready = true;
            return Ok(());
        }
        self.abort(LifecycleError::ReadyTimeout)
    }

    pub fn runtime_command(
        &mut self,
        seq: u8,
        left: i16,
        right: i16,
        flags: u8,
    ) -> Result<(), LifecycleError<P::Error>> {
        if !self.runtime_ready {
            return self.abort(LifecycleError::NotReady);
        }
        if !(-800..=800).contains(&left) || !(-800..=800).contains(&right) || flags != 0 {
            return self.abort(LifecycleError::InvalidCommand);
        }
        let status = match self
            .platform
            .runtime_transfer(&runtime_frame(seq, left, right, flags))
        {
            Ok(status) => status,
            Err(error) => return self.abort(LifecycleError::Platform(error)),
        };
        if status & STATUS_READY == 0
            || status & STATUS_WATCHDOG_EXPIRED != 0
            || status & STATUS_RESERVED != 0
        {
            return self.abort(LifecycleError::BadStatus);
        }
        Ok(())
    }

    pub fn fail_safe(&mut self, _reason: &'static str) {
        self.platform.force_safe();
        self.runtime_ready = false;
    }

    #[must_use]
    pub const fn runtime_ready(&self) -> bool {
        self.runtime_ready
    }

    #[must_use]
    pub const fn platform(&self) -> &P {
        &self.platform
    }

    fn abort<T>(&mut self, error: LifecycleError<P::Error>) -> Result<T, LifecycleError<P::Error>> {
        self.platform.force_safe();
        self.runtime_ready = false;
        Err(error)
    }
}

/// Task 2's fixed SPI runtime frame.
#[must_use]
pub fn runtime_frame(seq: u8, left: i16, right: i16, flags: u8) -> [u8; 12] {
    let [left_lo, left_hi] = left.to_le_bytes();
    let [right_lo, right_hi] = right.to_le_bytes();
    let mut frame = [
        0x7e, 0x01, 0x01, 0x06, seq, left_lo, left_hi, right_lo, right_hi, flags, 0, 0,
    ];
    let crc = shrike_link::crc16(&frame[1..10]).to_le_bytes();
    frame[10..].copy_from_slice(&crc);
    frame
}
