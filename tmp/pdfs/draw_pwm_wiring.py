from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, white
from pathlib import Path
out=Path('/home/utkarsh/Work/axiomOS/output/pdf/axiomos-pwm-wiring.pdf')
c=canvas.Canvas(str(out),pagesize=(1000,760)); c.setTitle('axiomos - unloaded Pi 5 PWM test wiring')
ink='#183047'; gray='#52616F'; red='#B93142'; blue='#2367A4'; green='#21744C'
def text(x,y,s,size=11,color=ink,bold=False):
 c.setFillColor(HexColor(color)); c.setFont('Helvetica-Bold' if bold else 'Helvetica',size); c.drawString(x,y,s)
def box(x,y,w,h,fill='#F1F5F8',stroke='#CCD6DE'):
 c.setFillColor(HexColor(fill)); c.setStrokeColor(HexColor(stroke)); c.setLineWidth(1); c.roundRect(x,y,w,h,9,fill=1,stroke=1)
def line(points,color=ink,width=2):
 c.setStrokeColor(HexColor(color)); c.setLineWidth(width); p=c.beginPath();p.moveTo(*points[0])
 for pt in points[1:]:p.lineTo(*pt)
 c.drawPath(p)
def dot(x,y,color):
 c.setFillColor(HexColor(color));c.circle(x,y,3.5,stroke=0,fill=1)
def resistor(x,y,color):
 line([(x,y),(x+12,y)],color);c.setStrokeColor(HexColor(color));c.setFillColor(white);c.rect(x+12,y-6,48,12,fill=1,stroke=1);line([(x+60,y),(x+72,y)],color);text(x+15,y+14,'220 ohm',10,color)
text(34,723,'axiomos / PWM carrier + sensor-stop test',25,bold=True)
text(34,700,'Pi 5 + Shrike stimulus + logic analyzer + Debug Probe  |  No motors, motor drivers or actuators',12)
box(34,647,932,36,'#FFF1D8','#E3BC72');text(47,660,'WIRE WITH BOTH BOARDS UNPOWERED.  All GPIO signals are 3.3 V.  Do not connect a power rail to GPIO24.',11,bold=True)
text(34,628,'Signal diagram - functional layout, not board orientation. Pi labels are PHYSICAL header pin numbers.',10,gray)
box(34,340,212,251);text(50,567,'SHRIKE',17,bold=True);text(50,547,'Use printed GP21 / GP22 labels',10,gray)
box(500,340,226,251);text(516,567,'RASPBERRY PI 5',17,bold=True);text(516,547,'40-pin GPIO header',11,gray)
box(811,340,155,251);text(826,567,'ANALYZER',16,bold=True);text(826,546,'Case labels 1-8',10,gray)
text(53,501,'GP21: e-stop stimulus',11,red,bold=True);dot(246,505,red)
line([(246,505),(298,505)],red);resistor(298,505,red);line([(370,505),(500,505)],red)
dot(480,437,blue);line([(480,437),(480,606),(790,606),(790,505),(811,505)],blue)
text(518,500,'Pin 18 / GPIO24',13,red,bold=True);text(518,483,'LOW = asserted',10,red)
text(595,611,'D0 taps GPIO23 on the PI SIDE of its resistor',10,blue,bold=True)
text(825,500,'Input 1 = D0',12,blue,bold=True)
text(52,433,'GP22: sensor stimulus',11,blue,bold=True);dot(246,437,blue)
line([(246,437),(298,437)],blue);resistor(298,437,blue);line([(370,437),(500,437)],blue)
text(518,432,'Pin 16 / GPIO23',13,blue,bold=True);text(518,416,'One automatic HIGH pulse',10,gray)
# GPIO12 output sits on the right side, separate from the sensor connection.
line([(726,465),(811,465)],green);dot(726,465,green)
text(592,467,'Pin 32 / GPIO12',11,green,bold=True);text(825,460,'Input 2 = D1',12,green,bold=True)
text(52,372,'GND',12,bold=True);line([(246,377),(500,377)],ink);text(518,372,'Pin 20 / GND',12,bold=True)
text(614,354,'Pin 14 / GND',11,bold=True);line([(726,359),(811,359)],ink);text(825,354,'GND',12,bold=True)
text(34,318,'CHANGE FROM E-STOP TEST: input 1 / D0 moves from pin 18 to pin 16. Input 2 / D1 stays on pin 32.',11,red,bold=True)
text(34,299,'Dots join wires; crossings without dots do not. Pi pins 14 and 20 share ground internally.',10,gray)
box(34,175,932,108)
text(50,259,'USB, UART, SD and power',13,bold=True)
text(50,239,'Host USB  ->  Shrike USB                         Host USB  ->  Logic analyzer USB',11)
text(50,219,'Host USB  ->  Debug Probe USB  ->  probe UART port (U)  ->  Pi dedicated 3-pin UART connector',11)
text(50,199,'Keep the existing keyed UART cable unchanged; do not move it to GPIO14/15 on the 40-pin header.',10,gray)
text(50,183,'SD card  ->  Pi microSD slot                     Pi USB-C power supply  ->  Pi power port (OFF until script prompt)',10)
text(34,150,'Power-on order',13,bold=True)
text(34,130,'1. Pi power OFF + Shrike USB unplugged: insert the prepared SD and make the wiring above.',11)
text(34,111,'2. Connect Shrike USB, analyzer USB and Debug Probe USB. Leave Pi power OFF.',11)
text(34,92,'3. Run the PWM capture script. Power the Pi ONLY at "UART RECORDING - POWER ON THE PI NOW".',11)
text(34,73,'4. Keep hands off during the automatic sensor pulse. Power off Pi at completion. Do not attach actuators.',11)
text(34,47,'Test image: bench-pwm. Requested 10 kHz / 50% PWM; sensor requests duty zero. No automatic rearm. No FPGA in this test.',9,gray)
text(34,30,'Source: campaign wiring + scripts/hil/shrike-gpio23-pulse.sh (OUTPUT_MODE=pwm); Pi pin numbering / debug header: official Raspberry Pi documentation.',8,gray)
c.linkURL('https://www.raspberrypi.com/documentation/computers/raspberry-pi.html',(34,24,965,40),relative=0)
c.showPage()
text(34,723,'Pin-by-pin check before power-on',25,bold=True)
text(34,697,'Physical pin numbers below refer to the Pi 40-pin header, not BCM GPIO numbers.',12)
box(34,640,932,38,'#FFF1D8','#E3BC72')
text(48,654,'Find the actual pin-1 end before counting. This is a numbering map, not an orientation drawing of the board.',11,bold=True)
text(80,609,'Pi header numbering',15,bold=True)
text(80,589,'Pin-1 end at top in this map',10,gray)
for row in range(20):
 y=563-row*22
 for col in range(2):
  pin=2*row+col+1; x=126+col*80
  color={14:ink,16:blue,18:red,20:ink,32:green}.get(pin,'#CCD6DE')
  c.setStrokeColor(HexColor(color)); c.setFillColor(HexColor(color) if pin in (14,16,18,20,32) else white)
  c.circle(x,y,8,fill=1,stroke=1)
  text(x-32 if col==0 else x+17,y-4,str(pin),10,ink,pin in (14,16,18,20,32))
text(290,606,'Every connection',15,bold=True)
rows=[
 ('Shrike GP22','220 ohm resistor -> Pi pin 16 / GPIO23',blue),
 ('Analyzer input 1 / D0','Same pin-16 node, after the GP22 resistor',blue),
 ('Shrike GP21','220 ohm resistor -> Pi pin 18 / GPIO24',red),
 ('Analyzer input 2 / D1','Pi pin 32 / GPIO12 (PWM output)',green),
 ('Shrike GND','Pi pin 20 / GND',ink),
 ('Analyzer GND','Pi pin 14 / GND',ink),
]
for i,(a,b,color) in enumerate(rows):
 y=567-i*56
 text(290,y,a,12,color,True);text(290,y-19,b,12)
box(290,131,676,78)
text(304,187,'Expected capture',13,bold=True)
text(304,166,'D0: LOW -> HIGH -> LOW, one sensor pulse.',12,blue)
text(304,146,'D1: PWM carrier before the pulse, then stable LOW after the stop.',12,green)
text(34,77,'Leave all unlisted header pins unconnected for this test. Do not connect Pi and Shrike 3.3 V or 5 V rails.',11,bold=True)
text(34,56,'Use the printed Shrike GP21 / GP22 labels; they are GPIO identities, not Pi-style physical pin numbers.',10,gray)
text(34,35,'Retain the existing Debug Probe keyed UART cable to the Pi dedicated 3-pin UART connector.',10,gray)
c.save();print(out)
