import sys
sys.path.insert(0, '/tmp/axiomos-wiring-pdf-deps')
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import A4
from pathlib import Path
out = Path(__file__).resolve().with_name('axiomos-test-01-pi5-uart-wiring.pdf')
c = canvas.Canvas(str(out), pagesize=A4)
c.setTitle('AxiomOS | Test 01 | Pi 5 boot and serial wiring')
c.setAuthor('AxiomOS engineering')
W,H=A4
ink=HexColor('#182536'); muted=HexColor('#526477'); blue=HexColor('#2366A5'); teal=HexColor('#13776B')
def text(x,y,s,size=10,color=ink,font='Helvetica'):
 c.setFillColor(color); c.setFont(font,size); c.drawString(x,y,s)
def lines(x,y,ss,size=10,leading=15,color=ink,font='Helvetica'):
 for s in ss: text(x,y,s,size,color,font); y-=leading
 return y
def box(x,y,w,h,fill,stroke=None):
 c.setFillColor(fill); c.setStrokeColor(stroke or fill); c.roundRect(x,y,w,h,8,fill=1,stroke=bool(stroke))
def centered(x,y,s,size=10,color=ink,font='Helvetica'):
 c.setFont(font,size);c.setFillColor(color);c.drawCentredString(x,y,s)
def wire(x1,y1,x2,y2,color=blue):
 c.setStrokeColor(color);c.setLineWidth(2);c.line(x1,y1,x2,y2)
def arrow(x1,y,x2,color=teal):
 wire(x1,y,x2,y,color); c.setFillColor(color)
 p=c.beginPath();p.moveTo(x2,y);p.lineTo(x2-5,y+3);p.lineTo(x2-5,y-3);p.close();c.drawPath(p,fill=1,stroke=0)

text(36,802,'AXIOMOS  /  BENCH GUIDE',10,teal,'Helvetica-Bold')
text(36,768,'01  Pi 5 boot + serial capture',25,ink,'Helvetica-Bold')
text(36,743,'Wiring sheet for the official Raspberry Pi Debug Probe',11,muted)
box(36,685,523,39,HexColor('#FFF0CD'))
text(49,701,'STOP POINT: keep Pi USB-C power unplugged until capture is ready.',11,HexColor('#754800'),'Helvetica-Bold')
text(36,659,'CONNECT THESE TWO CABLES',10,muted,'Helvetica-Bold')
# Connector-level schematic; no assumed pin orientation.
for x,w,title,sub in [(36,126,'COMPUTER','USB port'),(218,151,'DEBUG PROBE','U / UART port'),(430,129,'RASPBERRY PI 5','Dedicated UART')]:
 box(x,558,w,78,HexColor('#EEF4FA'),HexColor('#B8CBDE'))
 centered(x+w/2,613,title,10,ink,'Helvetica-Bold')
 centered(x+w/2,588,sub,11,blue,'Helvetica-Bold')
wire(162,582,218,582);centered(190,598,'USB',9,muted)
wire(369,582,430,582);centered(399,607,'3-pin',9,muted);centered(399,594,'JST-SH',9,muted)
text(36,539,'Use the supplied UART cable with a small white 3-pin plug at each end.',10)
text(36,523,'Match the keyed plugs gently. Use U / UART on the probe; leave D unused.',10)

text(36,491,'FIND THE PI CONNECTOR',10,muted,'Helvetica-Bold')
text(36,472,'The small connector labelled UART is between the two micro-HDMI ports.',10)
for x,w,label in [(118,103,'micro-HDMI'),(240,115,'UART'),(374,103,'micro-HDMI')]:
 box(x,426,w,29,HexColor('#DAF0E9') if label=='UART' else HexColor('#F0F2F5'))
 centered(x+w/2,436,label,10,teal if label=='UART' else muted,'Helvetica-Bold')
centered(W/2,411,'Location guide only - not a scaled board drawing.',8,muted)

text(36,382,'WHAT THE THREE WIRES CARRY',10,muted,'Helvetica-Bold')
text(36,364,'Logical signals only; this is not connector pin order or cable colour coding.',9,muted)
for y,l,r in [(338,'Probe TX','Pi RX'),(316,'Probe RX','Pi TX'),(294,'Probe GND','Pi GND')]:
 text(125,y,l,10,ink,'Helvetica-Bold');text(387,y,r,10,ink,'Helvetica-Bold')
 if y==338:arrow(220,y+3,368)
 elif y==316:
  wire(220,y+3,368,y+3);c.setFillColor(teal);p=c.beginPath();p.moveTo(220,y+3);p.lineTo(225,y+6);p.lineTo(225,y);p.close();c.drawPath(p,fill=1,stroke=0)
 else:wire(220,y+3,368,y+3,muted)

box(36,151,523,119,HexColor('#F2F6F8'))
text(49,250,'CHECK BEFORE WE CONTINUE',10,ink,'Helvetica-Bold')
items=[
 'Pi and probe were unpowered when the UART cable was fitted.',
 'Probe U / UART connects to the Pi dedicated UART socket.',
 'Probe USB connects to the computer; Pi USB-C power stays unplugged.',
 'Shrike, logic analyzer and motors remain disconnected.'
]
for i,s in enumerate(items):
 y=230-i*20;c.setStrokeColor(muted);c.setLineWidth(0.7);c.rect(50,y-1,8,8,fill=0,stroke=1);text(65,y,s,10)
text(36,128,'NEXT: identify the serial port and verify the boot SD card, then start capture.',10,blue,'Helvetica-Bold')
text(36,112,'Expected console setting: 115200 baud, 8 data bits, no parity, 1 stop bit.',9,muted)
text(36,85,'Sources / verified 2026-09-09',8,muted,'Helvetica-Bold')
for y,label,url in [
 (70,'Raspberry Pi: Debug Probe connections','https://www.raspberrypi.com/documentation/microcontrollers/debug-probe.html'),
 (57,'Raspberry Pi: Pi 5 dedicated UART10 header','https://www.raspberrypi.com/documentation/computers/configuration.html#primary-and-secondary-uarts')]:
 text(36,y,label,8,blue);c.linkURL(url,(36,y-2,350,y+9),relative=0)
text(36,40,'AxiomOS console: kernel/src/arch/aarch64/platform/rpi5/uart.rs @ 34fe92c',8,muted)
text(521,25,'1 / 1',8,muted)
c.showPage();c.save()
print(out)
