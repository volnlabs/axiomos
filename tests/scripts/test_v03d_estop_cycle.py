#!/usr/bin/env python3
"""Exercise the real unloaded e-stop runner with PTY UART and fake instruments."""
import os
from pathlib import Path
import pty
import signal
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SIGROK = r'''#!/usr/bin/env python3
import os, pathlib, sys, time, zipfile
assert '-t' not in sys.argv, 'continuous baseline required'
assert sys.argv[sys.argv.index('-l')+1] == '4'
p = pathlib.Path(sys.argv[sys.argv.index('-o')+1])
raw = bytes([3]*32 + [2,0,1,3]*99 + [2,0])
with zipfile.ZipFile(p, 'w') as z:
 z.writestr('metadata','[device 1]\ncapturefile=logic-1\ntotal probes=8\nsamplerate=24 MHz\nunitsize=1\nprobe1=D0\nprobe2=D1\n')
 z.writestr('logic-1-1',raw)
pathlib.Path(os.environ['TEST_EVENTS']).open('a').write('analyzer_ready\n')
print('Received SR_DF_LOGIC', flush=True)
time.sleep(1)
'''
MPREMOTE = r'''#!/usr/bin/env python3
import os, pathlib, sys
assert 'resume' in sys.argv and sys.argv.index('resume') < sys.argv.index('exec')
code=sys.argv[sys.argv.index('exec')+1]
compile(code,'stimulus','exec')
p=pathlib.Path(os.environ['TEST_EVENTS'])
if 'V03D_PRESS_START' in code:
 assert 'analyzer_ready' in p.read_text()
 assert 'finally:' in code
 p.open('a').write('press\n')
 print('V03D_PRESS_START\nV03D_PRESS_DONE 0 0')
elif 'GPIO_READY' in code:
 p.open('a').write('init\n'); print('GPIO_READY 0 1')
else:
 assert 'value=0' in code
 p.open('a').write('safe\n'); print('GPIO_SAFE 0 0')
'''

class HarnessTests(unittest.TestCase):
 def run_case(self, missing_signed=False, loss=False):
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp); bindir=d/'bin'; bindir.mkdir(); events=d/'events'; events.touch()
   for name,source in [('sigrok-cli',SIGROK),('mpremote',MPREMOTE)]:
    f=bindir/name; f.write_text(source); f.chmod(0o755)
   master,slave=pty.openpty(); uart=os.ttyname(slave)
   shrike=d/'shrike'; shrike.touch(); run=d/'run'
   env=dict(os.environ, PATH=f'{bindir}:{os.environ["PATH"]}', MPREMOTE=str(bindir/'mpremote'),
    PI_UART=uart,SHRIKE_UART=str(shrike),RUN_DIR=str(run),TEST_EVENTS=str(events),
    ACTUATORS_MOTORS_DISCONNECTED='YES',LOGIC_CONN='fx2lafw',PRESS_COUNT='100',
    PRESS_LOW_MS='1',REARM_HIGH_MS='1',FINAL_LOW_MS='1',UART_SECONDS='5',READY_TIMEOUT='1')
   # Close the slave so the script's existing-reader check remains meaningful.
   os.close(slave)
   proc=subprocess.Popen([str(ROOT/'scripts/hil/v03d-estop-cycle.sh')],cwd=tmp,env=env,
     stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
   def feed():
    deadline=time.monotonic()+3
    while time.monotonic()<deadline and not list(run.glob('*-uart.log')): time.sleep(.01)
    time.sleep(.05)
    try:
     os.write(master,b'PI5_BENCH_READY\nPI5_BENCH_LOG_MODE deferred=true\nPI5_V03D_READY output=gpio auto_rearm=true\nPI5_OUT_ARM mode=gpio gpio=12 code=0 estop_asserted=false\n')
     time.sleep(.25)  # signed load really arrives after BENCH_READY
     if not missing_signed: os.write(master,b'SIGNED_BPF_LOAD_OK\n')
     if loss: os.write(master,b'PI5_BENCH_LOG_LOSS dropped_records=1\n')
     while time.monotonic()<deadline and 'press\n' not in events.read_text(): time.sleep(.01)
     if 'press\n' in events.read_text():
      for i in range(1,101):
       os.write(master,f'PI5_MB sample_id={2*i-1} ns=100\n'.encode())
       if i<100: os.write(master,f'PI5_ESTOP_REARM sample_id={2*i-1} mode=gpio code=0\n'.encode())
    except OSError: pass
   t=threading.Thread(target=feed); t.start()
   try: output,_=proc.communicate(timeout=8)
   except subprocess.TimeoutExpired:
    os.killpg(proc.pid,signal.SIGKILL); output,_=proc.communicate(); self.fail(output)
   finally: t.join(); os.close(master)
   return proc.returncode,output,events.read_text()
 def test_full_capture_waits_for_delayed_signed_load_and_real_analyzer(self):
  code,out,events=self.run_case()
  self.assertEqual(code,0,out); self.assertIn('VERDICT: PASS',out)
  self.assertLess(events.index('analyzer_ready'),events.index('press\n'))
  self.assertTrue(events.endswith('safe\n'),events)
 def test_missing_signed_load_cleans_low_without_press(self):
  code,out,events=self.run_case(missing_signed=True)
  self.assertNotEqual(code,0,out); self.assertNotIn('press\n',events)
  self.assertTrue(events.endswith('safe\n'),events)
 def test_log_loss_aborts_and_cleans_low(self):
  code,out,events=self.run_case(loss=True)
  self.assertNotEqual(code,0,out); self.assertNotIn('press\n',events)
  self.assertTrue(events.endswith('safe\n'),events)

if __name__=='__main__': unittest.main()
