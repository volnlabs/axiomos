#[path = "../src/board/shrike_lite_v1_r04.rs"]
mod profile;

#[test]
fn r04_assignments_match_the_vendor_interconnect_and_do_not_overlap() {
    assert_eq!(profile::FPGA_CONFIG, [0, 1, 2, 3]);
    assert_eq!(profile::FPGA_CONTROL, [12, 13]);
    assert_eq!(profile::FPGA_RUNTIME, [14, 15]);
    assert_eq!(profile::MCU_LED, 4);
    assert_eq!(profile::ESTOP_OBSERVE, 5);
    assert_eq!(profile::MOTOR_DIRECTION, [6, 7, 8, 9]);
    assert_eq!(profile::ULTRASONIC, [10, 11]);
    assert_eq!(profile::PI_UART, [16, 17]);
    assert!(!profile::pin_is_assigned(18));
    assert!(!profile::pin_is_assigned(19));
    assert!(profile::assignments_are_unique());
}
