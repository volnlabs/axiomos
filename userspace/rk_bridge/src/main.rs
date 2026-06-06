//! rk-to-ros: Bridge rkBPF kernel events to stdout or ROS2 topics
//!
//! This CLI tool resolves pinned rkBPF ring buffer objects through the Axiom
//! `sys_bpf` interface and publishes events to stdout or ROS2.
//!
//! # Usage
//!
//! ```bash
//! # Bridge live scheduler events to stdout
//! rk-to-ros --stdout --format text
//!
//! # Bridge a different pinned object path
//! rk-to-ros --map /sys/fs/bpf/maps/imu_events --event-kind legacy --stdout
//!
//! # With rate limiting
//! rk-to-ros --topic /rk/sched_switch --rate-limit 1000
//! ```

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rk_bridge::{
    event::RkEvent,
    input::StreamSource,
    publisher::{EventPublisher, OutputFormat, PublisherConfig, RosPublisher, StdoutPublisher},
    ringbuf::RingBufConsumer,
};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

#[derive(Parser, Debug)]
#[command(name = "rk-to-ros")]
#[command(author = "rkBPF Team")]
#[command(version = "0.1.0")]
#[command(about = "Bridge pinned rkBPF kernel events to stdout or ROS2 topics")]
#[command(long_about = r#"
rk-to-ros opens pinned rkBPF ring buffer objects through the Axiom BPF syscall
surface and forwards their events to stdout or ROS2 topics.

Examples:
  # Bridge the proven sched_switch pinned object to stdout
  rk-to-ros --stdout --format text

  # Bridge a different pinned object path using the legacy event parser
  rk-to-ros --map /sys/fs/bpf/maps/events --event-kind legacy --stdout --format text

  # Publish scheduler events to a ROS2 topic
  rk-to-ros --topic /rk/sched_switch
"#)]
struct Args {
    /// Path to the pinned rkBPF ring buffer map
    #[arg(short, long, default_value = "/sys/fs/bpf/maps/sched_switch_events")]
    map: PathBuf,

    /// ROS2 topic to publish events to. With the default `/rk/events`, ROS2 mode
    /// routes events to stable per-event topics such as `/rk/sched_switch`.
    #[arg(short, long, default_value = "/rk/events")]
    topic: String,

    /// Output to stdout instead of ROS2
    #[arg(long)]
    stdout: bool,

    /// Output format
    #[arg(short, long, default_value = "json-lines", value_enum)]
    format: FormatArg,

    /// Maximum events per second (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    rate_limit: u32,

    /// Poll interval in milliseconds
    #[arg(long, default_value = "10")]
    poll_interval: u64,

    /// Include timestamps in output
    #[arg(long, default_value = "true")]
    timestamps: bool,

    /// Run in demo mode with synthetic events
    #[arg(long)]
    demo: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Event payload kind expected in the ring buffer
    #[arg(long, default_value = "sched-switch", value_enum)]
    event_kind: EventKindArg,

    /// Read events from a JSON-lines stream instead of a pinned BPF object.
    /// This is the path used when running `rk-to-ros` on a host that doesn't
    /// have access to the Axiom BPF syscall — events arrive over UART from
    /// `rk_uart_forwarder`. Pipe them in with `socat` or similar.
    ///
    /// Currently supported: `stdin`. Serial-port support is a follow-up.
    #[arg(long)]
    input: Option<InputArg>,
}

#[derive(ValueEnum, Clone, Debug)]
enum InputArg {
    /// Read newline-delimited JSON from stdin.
    Stdin,
}

#[derive(ValueEnum, Clone, Debug)]
enum FormatArg {
    Json,
    JsonLines,
    Text,
}

#[derive(ValueEnum, Clone, Debug)]
enum EventKindArg {
    /// Parse events using the legacy EventHeader-discriminated format
    Legacy,
    /// Parse raw live scheduler switch events
    SchedSwitch,
}

impl From<FormatArg> for OutputFormat {
    fn from(arg: FormatArg) -> Self {
        match arg {
            FormatArg::Json => OutputFormat::Json,
            FormatArg::JsonLines => OutputFormat::JsonLines,
            FormatArg::Text => OutputFormat::Text,
        }
    }
}

/// Bridge that connects ring buffer to publisher.
struct Bridge {
    publisher: Box<dyn EventPublisher>,
    poll_interval: Duration,
    running: Arc<AtomicBool>,
    event_kind: EventKindArg,
}

impl Bridge {
    fn new(
        publisher: Box<dyn EventPublisher>,
        poll_interval: Duration,
        event_kind: EventKindArg,
    ) -> Self {
        Self {
            publisher,
            poll_interval,
            running: Arc::new(AtomicBool::new(true)),
            event_kind,
        }
    }

    /// Run the bridge with a real ring buffer.
    async fn run_with_ringbuf(&self, mut consumer: RingBufConsumer) -> Result<()> {
        let mut interval = interval(self.poll_interval);

        log::info!("Starting bridge, poll interval: {:?}", self.poll_interval);
        log::info!(
            "Opened pinned map fd={} type={} max_entries={}",
            consumer.map_fd(),
            consumer.info().map_type,
            consumer.info().max_entries
        );

        while self.running.load(Ordering::Relaxed) {
            interval.tick().await;

            // Poll for events
            for data in consumer.poll()? {
                let parsed = match self.event_kind {
                    EventKindArg::Legacy => RkEvent::from_bytes(&data),
                    EventKindArg::SchedSwitch => RkEvent::from_sched_switch_bytes(&data),
                };

                match parsed {
                    Ok(event) => {
                        if let Err(e) = self.publisher.publish(&event) {
                            log::warn!("Failed to publish event: {}", e);
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to parse event: {}", e);
                    }
                }
            }
        }

        let _ = self.publisher.flush();
        Ok(())
    }

    /// Run the bridge against a host-side JSON stream (e.g. UART-forwarded
    /// events from `rk_uart_forwarder`). The reader is consumed in a blocking
    /// task so we don't block the tokio runtime; the `running` flag is
    /// checked between events.
    async fn run_with_stream<R>(&self, reader: R) -> Result<()>
    where
        R: Read + Send + 'static,
    {
        log::info!("Starting bridge in stream-input mode");

        let publisher_running = self.running.clone();
        // The publisher is owned by `&self`, so the actual publish must happen
        // on this task. We use a channel from a blocking reader task to here.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<RkEvent>(256);

        let reader_running = self.running.clone();
        let read_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut source = StreamSource::new(reader);
            while reader_running.load(Ordering::Relaxed) {
                match source.next_event() {
                    Ok(Some(event)) => {
                        if tx.blocking_send(event).is_err() {
                            break; // receiver dropped
                        }
                    }
                    Ok(None) => break, // EOF
                    Err(e) => {
                        log::warn!("stream parse error: {}", e);
                        // Continue — a single malformed line shouldn't abort the bridge.
                    }
                }
            }
            Ok(())
        });

        while publisher_running.load(Ordering::Relaxed) {
            match rx.recv().await {
                Some(event) => {
                    if let Err(e) = self.publisher.publish(&event) {
                        log::warn!("Failed to publish event: {}", e);
                    }
                }
                None => break, // reader finished
            }
        }

        let _ = self.publisher.flush();
        let _ = read_task.await;
        Ok(())
    }

    /// Run the bridge in demo mode with synthetic events.
    async fn run_demo(&self) -> Result<()> {
        use rk_bridge::event::{EventHeader, ImuEvent, MotorEvent, SafetyAction, SafetyEvent, SafetyType};

        let mut interval = interval(Duration::from_millis(100));
        let mut counter = 0u64;

        log::info!("Starting demo mode");

        while self.running.load(Ordering::Relaxed) {
            interval.tick().await;
            counter += 1;

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;

            // Generate synthetic IMU event
            let imu_event = RkEvent::Imu(ImuEvent {
                header: EventHeader {
                    timestamp_ns: timestamp,
                    event_type: 1,
                    cpu: 0,
                    pid: std::process::id(),
                    _reserved: 0,
                },
                accel_x: (counter as f64 * 0.1).sin() as i32 * 100,
                accel_y: (counter as f64 * 0.1).cos() as i32 * 100,
                accel_z: 9800 + (counter % 10) as i32,
                gyro_x: ((counter % 20) as i32) - 10,
                gyro_y: ((counter % 15) as i32) - 7,
                gyro_z: ((counter % 10) as i32) - 5,
                temperature: 2500 + (counter % 100) as i32,
                sensor_id: 0,
            });

            if let Err(e) = self.publisher.publish(&imu_event) {
                log::warn!("Failed to publish IMU event: {}", e);
            }

            // Generate motor event every 5th iteration
            if counter % 5 == 0 {
                let motor_event = RkEvent::Motor(MotorEvent {
                    header: EventHeader {
                        timestamp_ns: timestamp,
                        event_type: 2,
                        cpu: 0,
                        pid: std::process::id(),
                        _reserved: 0,
                    },
                    channel: (counter % 4) as u32,
                    duty_cycle: ((counter * 100) % 65535) as u32,
                    period_ns: 20000,
                    polarity: 0,
                    enabled: 1,
                    _reserved: 0,
                });

                if let Err(e) = self.publisher.publish(&motor_event) {
                    log::warn!("Failed to publish motor event: {}", e);
                }
            }

            // Generate safety event every 50th iteration
            if counter % 50 == 0 {
                let safety_event = RkEvent::Safety(SafetyEvent {
                    header: EventHeader {
                        timestamp_ns: timestamp,
                        event_type: 3,
                        cpu: 0,
                        pid: std::process::id(),
                        _reserved: 0,
                    },
                    safety_type: SafetyType::ThresholdExceeded,
                    source_id: 1,
                    value: 9900,
                    action: SafetyAction::Alert,
                });

                if let Err(e) = self.publisher.publish(&safety_event) {
                    log::warn!("Failed to publish safety event: {}", e);
                }
            }
        }

        let _ = self.publisher.flush();
        Ok(())
    }

    /// Get the running flag for external use.
    fn running(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    log::info!("rk-to-ros starting");
    log::info!("Map path: {:?}", args.map);
    log::info!("Topic: {}", args.topic);
    log::info!("Event kind: {:?}", args.event_kind);

    // Create publisher configuration
    let config = PublisherConfig {
        topic: args.topic.clone(),
        rate_limit: args.rate_limit,
        buffer_size: 64,
        include_timestamps: args.timestamps,
        format: args.format.into(),
    };

    // Create publisher
    let publisher: Box<dyn EventPublisher> = if args.stdout {
        log::info!("Using stdout publisher");
        Box::new(StdoutPublisher::new(config))
    } else {
        log::info!("Using ROS2 publisher for topic: {}", args.topic);
        Box::new(RosPublisher::new(config)?)
    };

    // Create bridge
    let bridge = Bridge::new(
        publisher,
        Duration::from_millis(args.poll_interval),
        args.event_kind.clone(),
    );

    // Set up signal handler for graceful shutdown
    let running = bridge.running();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        running.store(false, Ordering::Relaxed);
    })?;

    // Run the bridge
    if args.demo {
        bridge.run_demo().await?;
    } else if let Some(input) = args.input.clone() {
        match input {
            InputArg::Stdin => {
                log::info!("Reading events from stdin (host-side ingest mode)");
                bridge.run_with_stream(io::stdin()).await?;
            }
        }
    } else {
        // Open the ring buffer
        let consumer = RingBufConsumer::open(&args.map).with_context(|| {
            format!(
                "Failed to open ring buffer at {:?}. Use --demo flag for synthetic events.",
                args.map
            )
        })?;
        bridge.run_with_ringbuf(consumer).await?;
    }

    log::info!("rk-to-ros shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_conversion() {
        assert!(matches!(OutputFormat::from(FormatArg::Json), OutputFormat::Json));
        assert!(matches!(
            OutputFormat::from(FormatArg::JsonLines),
            OutputFormat::JsonLines
        ));
        assert!(matches!(OutputFormat::from(FormatArg::Text), OutputFormat::Text));
    }
}
