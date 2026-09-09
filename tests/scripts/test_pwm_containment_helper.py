#!/usr/bin/env python3
"""Exercise production PWM helper validation/routing and bench correlation.

Host register/monitor substitutes test routing only, not physical containment.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


HARNESS = r'''
use std::sync::Mutex;
static CALLS: Mutex<Vec<(u32,u32,u32)>> = Mutex::new(Vec::new());
static RECORDS: Mutex<Vec<(u64,u32,u32,u32,i64)>> = Mutex::new(Vec::new());
mod actuation {
    pub fn is_motor_channel(chip:u8, channel:u8)->bool { chip==0 && channel==2 }
    pub fn guard_motor(_:u8,_:u8,_:i32)->i64 { -1 }
    pub fn guard_pwm(chip:u8, channel:u8, duty:u32)->i64 {
        super::CALLS.lock().unwrap().push((chip as u32,channel as u32,duty)); 0
    }
}
mod bench {
    pub fn pwm_request_sample_id()->u64 { 17 }
    pub fn report_pwm_request(id:u64,chip:u32,channel:u32,duty:u32,code:i64) {
        super::RECORDS.lock().unwrap().push((id,chip,channel,duty,code));
    }
}
fn main() {
    assert_eq!(bpf_pwm_write(0,1,u32::MAX),0);
    assert_eq!(bpf_pwm_write(0,3,u32::MAX),-1);
    assert_eq!(bpf_pwm_write(256,1,u32::MAX),-1);
    assert_eq!(bpf_pwm_write(0,2,u32::MAX),-1);
    assert_eq!(*CALLS.lock().unwrap(),vec![(0,1,u32::MAX)],"invalid or motor request reached local writer");
    assert_eq!(*RECORDS.lock().unwrap(),vec![
        (17,0,1,u32::MAX,0),(17,0,3,u32::MAX,-1),
        (17,256,1,u32::MAX,-1),(17,0,2,u32::MAX,-1)
    ],"every helper result must retain its request and IRQ identity");
    println!("PASS: PWM helper validates before narrowing; preserves routing and logs both outcomes");
}
'''

if __name__ == "__main__":
    source = (ROOT / "kernel/src/bpf/helpers.rs").read_text()
    methods = "\n".join(function(source, name) for name in (
        "fn valid_pwm_id(", "fn valid_pwm_channel(", 'pub extern "C" fn bpf_pwm_write('
    ))
    with tempfile.TemporaryDirectory(prefix="pwm-helper-test-") as directory:
        path = Path(directory)
        (path / "main.rs").write_text(HARNESS + methods)
        subprocess.run(["rustc", "--edition=2021", "--cfg", 'feature="bench-pwm-containment"', str(path / "main.rs"), "-o", str(path / "check")], check=True)
        subprocess.run([str(path / "check")], check=True)
