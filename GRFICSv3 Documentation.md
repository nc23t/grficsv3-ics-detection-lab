

# GRFICSv3 Documentation


# Stage 1: Reconnaissance & Environment Mapping

## Topology

I was able to create a topology of the lab after scanning the two different subnets and figuring out what systems were on each subnet. As well as which ports each system was running on.
	![[Pasted image 20260617124242.png|585]]


## Understanding the ICS Chemical Process

Now I will be getting into the process of the **ICS** and will explain how it works.
 
**A Healthy Operating System**	
![[Pasted image 20260617132252.png]]

The variables being displayed are units of measurement which tells the user how much of each element is moving through the pipes.

The unit of measurement for how much *substance* (liquid, gas, or vapor) is moving through the valves is **kMol/h**. Now **kMol/h** stands for *kilomole per hour*, a unit of **molar flow rate** which is commonly used in chemical engineering and process simulation software. One **kilomole** is equal to *1000 moles*. So **1 kMol/h** just represents a flow of 1000 **moles** of substance an hour.



By taking a look at the process simulation on the HMI, I can see that a normal rate of **moles** through the **Feed 1** valve would be 500.0 **kMol/h**. 
	![[Pasted image 20260617125641.png]]


For the **Product** valve, it can get as low as below 10 and as high as 212.5 **kMol/h**. 
	![[Pasted image 20260617125740.png]]

This steady rate of the **Feed 1** valve makes sense since this is the valve which inputs the *A chemical* to be used, while the **Product** valve is responsible for dispensing the *finished product*. It is normal behavior for the **Product** flow valve to spike to around 212.5 **kMol/h** and drop back down to single digit numbers slowly. Inputting a chemical into the process will be much more steady than dispensing the *finished product*. 


It is common for the valve controlling and dumping the pressure from the *Reactor vessel* to reach a max of 500 **kMol/h** very quickly and then drop down quickly to 0 **kMol/h** for a  couple of seconds. This valve only activates when the pressure is getting too high inside the *Reactor vessel* and needs to release some pressure.
	![[Pasted image 20260617125936.png]]
	![[Pasted image 20260617125948.png]]



**kPa** is a unit of measurement for pressure. **kPa** stands for **kilopascal** which is equal to 1000 **pascals**. It is defined as *one newton of force per square meter*. It is commonly used to measure tire pressure, atmospheric pressure, and blood pressure. Some simple conversions are: 
	**1 kPa** ~ 0.145 *psi*
	**1kPa** ~ 0.01 *bar*
	
> The unit is named after the French mathematician and physicist **Blaise Pascal**

For the *Reactor vessel* itself, the pressure rarely gets above 2702.2 **kPa**. When the *Reactor vessel* gets to this pressure amount, the **Purge** valve kicks in and dumps some *purged vapor byproduct* of the chemical process. 2696.2 **kPa** seems to be the lowest number for pressure I have seen the *Reactor vessel* reach.
	![[Pasted image 20260617130559.png]]


Lastly, for some reason the **Feed 2** valve seems to never turn on. This may be a limitation of the simulation itself, but this valve never displayed any movement or activity throughout my testing.

>Something worth mentioning is the actual sensors themselves in the walk-around simulation, read from *0-100*, while the engineering values on the HMI graphical interface read in *0-3000+*. The reason for this is because the sensors are calibrated to a **specified range** not the **actual engineering value**.
  Every sensor is calibrated for a specific range, so for example, the *Reactor vessel* sensor could be calibrated from **0-3000 kPa**, however, the physical sensor does not output this number, instead it outputs a **raw signal proportional to where the reading falls within its range**. 
  0-100% of the total range.

The sensor is not able to output any more than 100% of its range. So if a sensor is calibrated for 0-500 **kMol/h** but the process is actually receiving 505 **kMol/h**, the sensor would still read 100. Which is why **Safety Instrumented Systems or SIS**, would need to be involved, these systems *use sensors with ranges that extend well beyond normal operating conditions specifically to avoid this blind spot*




# Stage 2: Modbus Protocol Analysis

## Capturing Traffic from HMI

Using the `arpspoof` tool in order to send packets destined for the **HMI** to Kali.
	![[Pasted image 20260617142221.png]]


Using the `tcpdump` tool to capture the packets that **Kali** is receiving.
	![[Pasted image 20260617142310.png]]


Opening the *.pcap* file containing the captured packets.
	![[Pasted image 20260617142450.png]]


Filtering by the *modbus* protocol
	![[Pasted image 20260617142549.png]]


### Analyzing Modbus Traffic

Now that I have captured some modbus traffic from the **HMI** we can dissect the packets. It is worth knowing what we are looking at though. **Modbus** uses function codes to speak to and from the *PLC* and the *field devices*. These function codes tell the device what to send back or do. Here is a layout and explanation of those function codes.

Codes 1–4 are **reads** (reconnaissance). An attacker uses these to understand the process before striking:

- **1**: Read Coils (digital on/off outputs)
- **2**: Read Discrete Inputs (digital on/off inputs)
- **3**: Read Holding Registers (analog output values, setpoints)
- **4**: Read Input Registers (analog sensor readings)

Codes 5, 6, 15, 16 are **writes** (this is where attacks happen):

- **5**: Write Single Coil (flip one digital output on/off)
- **6**: Write Single Register (change one analog value)
- **15**: Write Multiple Coils (flip many digital outputs at once)
- **16**: Write Multiple Registers (change many analog values at once)

What are **coils**? **Coils** are just memory addresses in the **PLC**s output table. The difference between **coils** and *registers* are that coils simply store an on/off state while *registers* store 16 bits of data.  When** the **HMI** sends a **FC1** request to the **PLC**, it is asking to PLC to "*give me the current on/off state of these specific outputs*". Then the **PLC** responds with a series of bits, 1 meaning on and 0 meaning off.

Just from the process simply running, a lot of **FC 1**  and **4** are being captured. These are to be expected. 

**FC1** is basically asking "is this valve open?" while **FC4** is asking "what is the sensor reading right now?"


>**FC1: Read Coils**: "is the valve open?" → yes/no answer (digital output states)
  **FC2: Read Discrete Inputs**: "is the limit switch triggered?" → yes/no answer (digital input states from field devices, like a high-level alarm contact)
  **FC3: Read Holding Registers**: "what is the setpoint configured to?" → a number (operator-configurable values like target pressure, target temperature, valve position percentage)
  **FC4: Read Input Registers**: "what is the sensor reading right now?" → a number (live measurements coming in from field instruments). This is what your screenshot shows: the PLC sending the HMI current sensor data.


The way that Modbus function codes work is a bit weird. So lets say that we would like to write an "on" command to a field device to turn on a pump. The process would look like this
1. The **FC5** command gets sent from the **HMI** to the **PLC**. 
2. The **PLC** dissects the packet and finds the *coil*. A coil is just a virtual address
3. The **PLC** then goes to that virtual address (the *coil*), and writes the number 1 there, in memory, 1 means on
4. Now that the address has the value of *1* which means "on", the wiring on the **PLC** which is connected to the device, which we want to turn on, becomes energized and power flows through it to turn on that field device. 
5. There's an **output module** sitting between the memory and the wire. The **PLC's** processor writes the *1* to memory, then the output module reads that memory location and handles the actual electrical switching on the physical terminal.
	![[Pasted image 20260618190846.png]]

The important thing to get right here is to remember that *coils* are just virtual address. Places where we can write data to in order to **change** the state or read the **state** of the field devices


In my packet capture, I am reading mainly **FC1** and **FC4**. These are *Read Coils* and *Read Input registers* respectively. Now the reason for this is very important. Think of the **HMI** as just an observer of the process. The **HMI** is constantly polling the **PLC** for information on the system such as sensor readings and current on/off state. This is so that the operator is aware of what is happening currently in the process.

Now you may be wondering why you do not see any other **FC** codes such as 5,6 or the other *write* ones. The reason for this is because the **PLC** is the brains of the operation. The **PLC** receives all the data from the field devices and decides whether or not to close or open a valve, or start/stop a pump, and it makes these decisions all on its own hardware, which is the reason why you don't normally see these **FC** commands in a packet capture, they do not go over the network. 

> This logic is all happening on the **PLC**, thus it does not generate any network traffic.

The only time that you would see these commands over the network is when something *external* wants to override the autonomous decisions of the **PLC**.
The operator basically says, "I know the PLC's logic says this valve should be closed, but I'm forcing it open."



Lets get back to what we see actually in the lab now. So I noticed the **HMI** is polling the **PLC** on **FC1 & 4**, and it does this 2 times every single second. 


![[Pasted image 20260618193741.png]]
Looking at this packet we can see that there are 13 *registers*. What are *Registers*? *Registers* are a memory location on the **PLC** which stores data from a *field device*. So for example, the **HMI** says, "send me the registers 0-12 all at once", and since we know that *registers* hold the different data points from the process, we know that this really means, send me all the data from the 13 *field devices*.

Each *register* is mapped to a specific field device. Some field devices might need to use 2 registers, the reason for this is because a *register* has a maximum value of an **16 BIT UNSIGNED INTEGER**, which is 65535. So, if a field device needs to store a number higher than this number, it would make use of 2 *registers*. The maximum number of *registers* that can be in a **Modbus** packet is ==125==.


Say Register 11 is a pressure transmitter calibrated for **0–3000 kPa**, and the raw UINT16 range is **0–65535**:

Engineering value = (raw / 65535) × (range max − range min) + range min
Engineering value = (966 / 65535) × (3000 − 0) + 0
Engineering value = 0.01474 × 3000
Engineering value = 44.2 kPa



**Figuring out the register readings**
I took a look at the registers from the packets and upon inspection I saw that register 0 & 1 were at a max value of 65535. I was confused as to what this value represented according to the process so the way I think I figured it out was to turn on the process and see if it changed.
	![[Pasted image 20260619181617.png]]



Before turning off the process, I noticed that the only thing running at maximum capacity was the valve for *Chemical A* (my assumption) . This valve was,  and does run at 100 percent. So I figured that maybe these 2 registers were to represent that valve. So I went and turned off the entire system from the **HMI** and turned it back on after a couple of seconds.
	![[Pasted image 20260619181947.png]]

I then looked at a packet coming from **AFTER** turning off the process and inspected registers 0 & 1. And what do you know, those both showed the value of 0. 
	![[Pasted image 20260619181711.png]]

This does not exactly prove to me that these *Registers* hold the data from from *Chemical A*'s valve, but this is my best guess.


Something that I found which gives more credit to my assumption is when I turn off the system the only **field device** that goes to zero is actually *Chemical A*'s valve. All the other ones such as the **purge** valve and the **product** valve stay at a value above 0. In fact, when I turn the process off, the **purge** valve stays at a constant 500 **kMol/h** or *100%* and the **product** valve also stays at a constant *100%* or around 100-130 **kMol/h**. As the **purge** valve continues to stay open the pressure in the *Chemical reactor* drops significantly to around 99.8 **kPa** or *41.1%*.


My explanation of the *registers* is this. A register holds the raw *count* (0-65535), and this raw count is then divided by 65535 (the max the **UINT16** can hold), in order to figure out the **percentage**. An example is, lets say *register* 1 has a value of 32768 (roughly half the value of the max, 65535).  The register value is literally half of the max it could be, so we know that the percentage is 50%. Now if we take all these values and plug them into the *linear scaling* formula, we can then find the **engineering** value.


> [!info] A register holds a *raw* count (0–65535); dividing by the full-scale max (65535 for UINT16) expresses it as a fraction, ×100 for a percentage; and feeding that fraction together with the device's *calibrated* min and max into the *linear scaling* formula yields the engineering value.



The single best technique for discovering which **field devices** belong to which *registers* is **correlation by manipulation**. Being able to turn on and off the valves and see values change is easiest to map which belongs to which. However, you cannot just do this in a live system. So the process that I will be using to using the data gathered by the **HMI** and correlating that with the register values. I will run the raw *register* values through the linear scaling formula and figure out the actual values, and match that with what the **HMI** is showing me as well.

I should be able to find which **field devices** are storing their data in which *registers*.


#### Dissecting the Registers  

I think that a register in this scenario is holding the value of how open/close one of the valves are such as the purge valve, but another register is being used to store the **kMol/h** that is in the pipe itself. This means **TWO separate field devices** are used to store flow and valve openness.

I think *registers* 4 & 5 are the **purge** valve and *registers* 6 & 7 are the **product** valve. My reasoning is simple. After turning off the process, *registers* 4 & 5 hit 0 instantly, and in the physical simulation, the purge valve hit 0 instantly as well, meaning the valve is all the way closed and no **purge** is coming through the valve. This information came from the first couple of packets. 

As I waited, i noticed the **Product** valve slowly dwindling down in value on the sensor reading, and  as the later packets came, the **product** valve slowly went to 0, meaning that the openness of the valve and the **product** flowing through slowly declined. I saw this in the packets. The later packets that came eventually stopped showing a high value for *register* 6 & 7 and instead showed 0. And when looking at the physical simulation, the **Product** valve sensor was now displaying 0. 

![[Pasted image 20260620154158.png]]

This is my assumption as to which **field device** stores their data in which register. I think that the registers 4 & 5 belong to the **Purge Process**, and I think that  *register* 6 & 7 belong to the **Product Process**.



I am lead to believe that *registers* 0 & 1 are in use for the *Chemical A* process. These two *registers* are constantly at 100% or 65535 while the process is running with precisely zero change. When I look at the simulation, I also see that the only thing that is running at 100% every single second of the process being up is the *Chemical A* part.

So one *register* is holding the value of how open the valve is while the other *register* is holding the value of how much substance is coming through, **kMol/h**. When I turn off the process, these both drop instantly to 0. I can look at the simulation at the same exact time and see that the *Chemical A* process is at 0 (displayed on the sensor). This gives me some confidence in saying that these *registers* belong to the *Chemical A* process, however, the evidence only confirms both are *Chemical A* devices, not specifically which two quantities they represent.



I'm thinking Register 8 is the reactor pressure. I turned of the system for a while and watched the packets as the pressure decreased slowly, and register 8 is the only register which has a dramatic decrease over time.
![[Pasted image 20260622162734.png]]

> It is hard to see but it goes from 38564 -> 9463 -> 6521. Obviously the gap from 38564 and 9463 is because it how many packets later I looked for the value but the point stands.



**A clearer transformation**
	![[Pasted image 20260622163637.png]]
	![[Pasted image 20260622163645.png]]
	![[Pasted image 20260622163654.png]]



Then when I turn the process back on, *register* 8 slowly goes back up.
	![[Pasted image 20260622162957.png]]
	![[Pasted image 20260622163009.png]]
	![[Pasted image 20260622163039.png]]



Something to note is the other *registers*, 9, 10, 11, & 12, ALL seem to just hover around the same numerical value with no big swings. To show this here are 2 packets, one if from the set of 7000+ packets, and another is from 9000+, so these packets are roughly 2000+ packets apart. And here is the numerical difference 
	![[Pasted image 20260622163340.png]]
	![[Pasted image 20260622163353.png]]

#### Organizing The Register Map


Register 0 & 1 = **Chemical A Process**

Register 4 & 5 = **Purge Process**

Registers 6 & 7 = **Product Process**

Register 8 = **Reactor Pressure**







# Stage 3: Attack Execution


## Wireshark arpspoof Attack

> [!info] A note on interface names: everywhere in Stage 3 you'll see `-i eth0`, this is the network interface **on the Kali attacker VM**, the one Kali uses to reach the lab subnets. It has nothing to do with `eno1`, which shows up starting in Stage 4, that's the **host machine's** physical NIC, used for the Suricata macvlan setup. Two different machines, two different interfaces, same-looking name.

Blew up the reactor by disabling the "**Chemical Reactor**"program on **Open PLC**. I found out how to access the **OpenPLC web portal** by using the command 

```
sudo arpspoof -i eth0 192.168.90.107
```

Which sent all the traffic destined for the HMI to my Kali linux machine. This way I was able to use Wireshark and sniff the packets and figure out that one of the ICS devices with an IP address of `192.168.95.2` was making a lot of traffic.
	![[Pasted image 20260610182115.png]]
	![[Pasted image 20260610182138.png]]
	![[Pasted image 20260610182159.png]]
I then used Nmap to scan that device IP address and found an open port of 8080, by combining the IP and port together I was able to find the web portal login for OpenPLC.
	![[Pasted image 20260610182349.png]]

`192.168.95.2:8080`

From here I just used the documented default OpenPLC credentials (`openplc`/`openplc`) and logged into the portal. I then navigated to the system programs and shutdown the "**Chemical reactor**" program which then caused the pressure in the reactor to build and eventually **blow it up**.
	![[Pasted image 20260610182602.png]]
	![[Pasted image 20260610182635.png]]









## Register Manipulation Attack w/ MITM


This section will go over how to do a **MITM** attack on **modbus**. First we need to understand how the *arpspoof* command even works.

*Arpspoof* is a utility which allows us to do MITM attacks. When you run arpspoof, you send forged **ARP** replies that poison the **ARP** table(s) of one or more devices on the network. In the targeted form shown below, the `-t` flag poisons one specific device's table; without `-t`, arpspoof broadcasts the lie to the entire subnet.

```
arpspoof -i eth0 -t 192.168.90.107 192.168.90.200
```


- `sudo`: arpspoof needs root to forge ARP packets.
- `arpspoof`: the ARP cache poisoning tool.
- `-i eth0`: interface to send from (your Kali NIC on the supervisory net; confirm the name with `ip a`).
- `-t 192.168.90.107`: target: the HMI. You're poisoning _its_ ARP table.
- `192.168.90.200`: the host you're impersonating _to_ the HMI: the router/gateway. So the HMI now thinks "the route to the PLC is via Kali."

This command tells the HMI that **the IP `192.168.90.200` (the router) now maps to Kali's MAC address** in its ARP table. So, I ran this command on the Kali linux machine, meaning I am telling the **HMI**, through its **ARP** table, that the router is now at the **MAC** address of Kali. The IP never changes in an **ARP** spoof attack, only the **MAC** address does.


So now, whenever the **HMI** looks to send traffic to the **PLC**, it goes into its ARP table, sees that the address 192.168.90.200 has Kali's MAC address, and send the packet to Kali, instead of the actual router. From here, Kali sees the packet and forwards the packet to the **PLC**.

The thing is, we can only see the traffic in this direction. **This is because we only poisoned the HMI's table, so only the HMI is fooled into sending its outbound traffic to Kali. The router's table is still honest, so when the PLC's response comes back through the router headed for the HMI, the router looks up the HMI's real MAC and delivers it straight there, bypassing Kali entirely.** To capture the PLC→HMI responses, we'd need to poison the router's table as well. Which is where the next command comes into play, after running the previous command, we run this one in another terminal.


```
sudo arpspoof -i eth0 -t 192.168.90.200 192.168.90.107
```

Same flags, but now `-t` the router and impersonate the HMI, poisoning the _router's_ table so replies headed to the HMI come through Kali too. Bidirectional position established.

![[Pasted image 20260624180922.png]]


With both these *arpspoof* commands running, the **HMI**'s ARP table is now poisoned as well as the routers. We can now see the request for information from the **HMI** and the response from the **PLC**.

After this, I ran the python script with the following command. This script intercepts a packet that is being transmitted by the **PLC** to the **HMI**, before that packet gets to the **HMI** my script rewrites the register value to 65535 (max value) making the **HMI** think that the reactor is at max pressure when in reality, everything is normal.

```
sudo python3 /root/modbus_mitm_conceal.py
```
![[Pasted image 20260624181320.png]]

The Script File
[modbus_mitm_conceal.py](modbus_mitm_conceal.py)






### Port Forwarding Traffic

Now that we have both the endpoints spoofed and the script running, we have to port forward ipv4 traffic to make Kali behave like a router and forward the packets to the HMI or router after inspecting them.

```
sudo iptables -I FORWARD -p tcp --sport 502 -j NFQUEUE --queue-num 1
```

- `-I FORWARD`: insert into the FORWARD chain (traffic passing _through_ Kali, your relayed MITM traffic).
- `--sport 502`: match packets whose **source** port is 502, i.e. responses coming _from_ the PLC's Modbus service. (HMI requests go _to_ 502, so they don't match. You deliberately grab only the response direction.)
- `-j NFQUEUE --queue-num 1`: instead of forwarding immediately, divert matching packets to user space queue 1, where the script intercepts them.

This **intercepts and holds** packets (unlike Wireshark, which only copies), which is necessary because to modify a packet you must stop the real one, edit it, then release it.

>[!info] A **chain** is an ordered list of firewall rules a packet is checked against. The **FORWARD chain** handles packets that are merely _passing through_ the machine (not to it, not from it). Because ARP spoofing makes HMI↔PLC traffic transit Kali on its way to its real destination, that traffic hits the FORWARD chain, which is why the interception rule is inserted there.



In order to turn off the process the correct way is...

Turn it OFF: 

```
sudo iptables -D FORWARD -p tcp --sport 502 -j NFQUEUE --queue-num 1
```

```
sudo pkill arpspoof
```

```bash
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward                        # back to normal endpoint
```




### **Removing rules**

|Flag|Name|Action|Needs full rule spec?|
|---|---|---|---|
|`-I`|Insert|Add rule at the **top** of the chain (turns the rule **on**)|Yes, you write the full rule|
|`-A`|Append|Add rule at the **bottom** of the chain|Yes, you write the full rule|
|`-D`|Delete|Remove **one** specific rule (turns that rule **off**)|Yes, describe it exactly|
|`-F`|Flush|Remove **all** rules in a chain at once|No, just name the chain|
|`-L`|List|Show current rules (add `-n` for numeric/faster)|No|

The only difference between the "turning it on" command and "turning it off" command are the *-D* and *-I* flags.

With the *-D* flag, we are removing the rule we previously put in place which took all the packets passing through (*the ones which matched our rules e.g modbus port 502 and tcp*) our Kali machine and held them in a queue in order to be modified.

### Result


Before
	![[Pasted image 20260624181357.png]]
	![[Pasted image 20260624181428.png]]

After 
	![[Pasted image 20260624181506.png]]
	![[Pasted image 20260624181518.png]]


As you can see, the script makes it seem like the process is melting down, when in reality, everything is working just fine. I changed the value of register 8 with a max value of 65535 and this triggered the **HMI** to show cautions all over the process.

This is very dangerous in the real world because this could be reversed to where a meltdown is ACTUALLY happening and the attacker spoofs the registers to make it seem normal to the **HMI**. This is why firewall rules and networking monitoring are very important in *ICS*.


















## Coil Manipulation Attack


I need to layout some terms before we get into this attack. In this attack we will be acting as a *modbus client* (master) in order to send commands to the **PLC** aka the **slave**.

- **Modbus master = Modbus client** (same thing, two names: the asker/commander)
- **Modbus slave = Modbus server** (same thing: the responder/data-holder, i.e. the PLC)

So a **modbus** client is any program that can speak **modbus** as the *master*. It knows how to format the "tell me X" and "set Y" messages over the network to the **PLC**. 

The thing that I will be taking advantage of in **modbus** is the fact that ANYONE can create a **modbus** client, and if you point that client at the **PLC**, the **PLC** will listen to that client. There are no passwords and no authentication. The **PLC** cannot tell the difference.

`mbtget` is a tool, a specific modbus client program. The whole point of this tool is to enable you to *read/write* a **PLC** from the command line.

`pymodbus` is just another tool which is used to speak to a **PLC** as a **modbus** client (master). 

Remember that a modbus coil is a virtual address which holds a 1 bit value, *on* or *off*, *0* or *1*. We will be writing to this coil to either turn something off, like a pump, or turn something on like a pressure release valve.

The conversation:

- **Me** **(running a Modbus client)**: "PLC, send me the on/off state of coils 0 through 15." (an FC1 message)
- **PLC (the server):** "Here: coil 0 is on, coil 1 is off, coil 2 is on..." (the reply)


### Starting the Attack

To start the attack I had to install `pymodbus` in order to actually create a **modbus** client/master. 

```
sudo pip install pymodbus --break-system-packages
```

- `pip install pymodbus`: the Python Modbus library, gives us clean read/write functions.
- `--break-system-packages`: required on Kali's externally-managed Python (same as the netfilterqueue install).


### Scanning The ICS

After I installed the tool, the next step is to read what the current coils are at this moment. By using the **pymodbus** tool, we can query the **PLC** and see which *coils* are in the on or off state.

``` python
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); r=c.read_coils(0,count=100); print('Coils:', r.bits if not r.isError() else r); c.close()"
```

- `python3 -c "..."`: run the Python code in the quotes directly.
- `from pymodbus.client import ModbusTcpClient`: import the Modbus TCP client class.
- `c=ModbusTcpClient('192.168.95.2',port=502)`: create a client pointed at the PLC on the Modbus port.
- `c.connect()`: open the TCP connection to the PLC.
- `c.read_coils(0,count=100)`: **FC1 read**: read 100 coils starting at address 0. This is _read-only_: it just asks "what state are these coils in?" Nothing is changed.
- `r.bits`: the list of True/False (on/off) values returned, one per coil.
- `if not r.isError()`: only print the bits if the read succeeded; otherwise print the error.
- `c.close()`: close the connection cleanly.



![[Pasted image 20260624193728.png]]

From running the command, we see almost every single *coil* is off. However, if you look closely, *coil* 40 shows True. My hypothesis is that this *coil* is the *Chemical A* process, because as I discovered earlier in my documentation, the *Chemical A* process is always on.

We want to make sure that this reading is stable and does not fluctuate, so I ran this command 2 more times and got back the "True" reading both times. Validating that this *coil* is stable.


### Writing The Command

Now that we have the *coil* which we want to attack, we can write a command to send to the **PLC** to turn the *coil* off. The command looks like this

``` python
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); r=c.write_coil(40,False); print('Write result:', 'OK' if not r.isError() else r); c.close()"
```

- `python3 -c "..."`: run the inline Python.
- `from pymodbus.client import ModbusTcpClient`: import the client class.
- `c=ModbusTcpClient('192.168.95.2',port=502)`: point the client at the PLC on the Modbus port.
- `c.connect()`: open the TCP connection.
- `c.write_coil(40,False)`: **this is the attack.** ***FC5*** "Write Single Coil": set coil **40** to **False** (off). This is the first time we _change_ something rather than read. The PLC receives this from Kali (an IP that has no business commanding it) and complies, because Modbus has no authentication.
- `'OK' if not r.isError()`: print OK if the PLC accepted the write, otherwise the error.
- `c.close()`: close cleanly.

To restore the process, all I did was tweak the command section where it says "False" and put "True" in its place. This resets the coil back to its previous state.


### Result

Before manipulating the coil
	![[Pasted image 20260624200214.png]]
	![[Pasted image 20260624200256.png]]


After Manipulating the Coil
	![[Pasted image 20260624200457.png]]
	![[Pasted image 20260624200337.png]]
	![[Pasted image 20260624200358.png]]


As we can see, after sending the malicious packet, the **PLC** takes it and runs the command with no second thoughts, because of there being no authentication on **modbus**, and my hypothesis was correct. *Coil* 40 is indeed responsible for the *Chemical A* process, when the command was sent the process was stopped and the **HMI** view also showed 0% for **Feed 1**.
 
In order to restore the process, I ran the tweaked command I mentioned earlier, the value of "False" was just set to "True" in order to revert the coil to its previous state.

``` python
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); r=c.write_coil(40,True); print('Write result:', 'OK' if not r.isError() else r); c.close()"
```
![[Pasted image 20260624200854.png]]


And as expected, the *Chemical A* process turns on once again to 100% and the process is back to normal.


>[!info] **Detection note:** In normal operation, coils are flipped internally by the PLC's own logic. FC5 write commands don't traverse the network. So an FC5 "Write Single Coil" arriving from an unauthorized IP (here, Kali at 192.168.90.6) is a high-fidelity attack indicator. This is the basis for a Stage 4 Suricata rule: alert on any Modbus FC5/FC15 write from a source that isn't the legitimate controller










## Injected Structured Text (ST) Attack



### Overview of Structured Text 


Again, I will go over some terminology and concepts for the purpose of remembering how this attack works.

**Structured Text (ST)** is one of the 5 **PLC** programming languages . **Structured Text**  looks very similar to python or Pascal it also works similarly with variables, assignments, IF statements and function calls.


**1. The assignment operator `:=`**

This is the single most important symbol to internalize.

```
product_flow_setpoint := 30000;
```

`:=` means **"gets assigned the value of."** So this reads: _"product_flow_setpoint gets set to 30000."_ The left side is the variable being changed; the right side is the value going into it.

Why `:=` and not just `=`? In ST, `=` is reserved for **comparison** ("are these equal?"), while `:=` is **assignment** ("make this equal to"). Mixing them up is a classic bug. (Same convention as Pascal.)


**2. Variables**

Names like `pressure`, `purge_valve_pos`, `level_sp`, `run_bit` are variables: named storage holding a value. In a PLC, these aren't abstract; each one is wired to something real:

- `pressure`: holds the live reactor pressure reading (from a sensor).
- `purge_valve_pos`: holds the purge valve's current position.
- `pressure_sp`: holds the pressure _setpoint_ (`sp` = setpoint, the desired target).
- `run_bit`: a boolean (true/false) saying whether the process should be running.

The convention you'll see throughout: `_sp` = setpoint (desired value), `_pos` = position, `_flow` = flow rate. Reading those suffixes tells you what each variable _is_.


**3. Function calls**

```
purge_valve_sp := control(
     current_value := pressure,
     setpoint := pressure_sp,
     current_pos := purge_valve_pos,
     k := -20.0,
     rmax := 3200.0,
     rmin := 0.0);
```

`control(...)` is a **function**, a reusable block of logic defined elsewhere in the project. You _call_ it with named inputs (`current_value := pressure`, etc.) and it _returns_ a value, which gets assigned to `purge_valve_sp`.

Note the named-argument style: instead of `control(pressure, pressure_sp, ...)` relying on position, ST lets you write `current_value := pressure` so each input is labeled. The `:=` inside the call is assigning each input parameter. This makes the code self-documenting: you can see exactly what's being fed in.

So this whole block reads: _"Call the control function, feeding it the current pressure, the target pressure, the valve's current position, a gain of −20, and output limits 0–3200. Take whatever it returns and store it as the purge valve's new setpoint."_


**4. The `IF ... THEN ... END_IF` conditional**

```
IF NOT run_bit THEN
   f1_valve_sp := 0;
   f2_valve_sp := 0;
   purge_valve_sp := 65535;
   product_valve_sp := 65535;
END_IF;
```

Standard conditional logic:

- `IF`: start a condition.
- `NOT run_bit`: the condition: `NOT` flips a boolean, so this is true when `run_bit` is **false** (process is NOT supposed to run).
- `THEN`: if the condition holds, do what follows.
- The four assignments: cut both feeds to 0, open purge and product valves fully (65535 = max).
- `END_IF;`: marks the end of the conditional block. ST uses explicit `END_IF` rather than indentation (unlike Python) to know where the block stops.

Plain English: _"If the process is not running, shut off the feeds and open the relief valves fully"_, the safe-shutdown interlock.



**5. Built-in functions like `LIMIT`**

```
f1_valve_pos := LIMIT(0, f1_valve_pos, 65535);
```

`LIMIT(min, value, max)` is a standard ST function that **clamps** a value between bounds. It returns: `min` if the value is below min, `max` if above max, otherwise the value unchanged. So this reads: _"Constrain f1_valve_pos to stay between 0 and 65535."_

Why? Those are the valid bounds for a 16-bit value (remember UINT16 maxes at 65535 from my register work). This prevents the variable from going out of range, a safety/sanity guard. The big block of `LIMIT` lines is the program defensively clamping every variable to legal bounds each scan.

**6. The semicolon `;`**

Every statement ends with `;`. It tells the compiler "this instruction is complete." Missing semicolons are a common syntax error. You'll see it terminating every assignment and after `END_IF`.


 What makes PLC code different from a normal program is **it doesn't run once top to bottom and stop.** Remember the scan cycle from my earlier notes: Read inputs → Execute logic → Write outputs → repeat, every few milliseconds.

So this entire `main1` program runs **start to finish, then immediately runs again**, forever, dozens of times per second. Each pass:

1. Reads fresh sensor values into `pressure`, `level`, etc.
2. Runs all the `control(...)` loops to compute new valve setpoints.
3. Clamps everything with `LIMIT`.
4. Checks the `run_bit` interlock.
5. Writes the new valve setpoints out to the physical actuators.
6. Starts over.


### Understanding the Chemical Program

Some information on how this "Chemical" program works, the program that I found on the Engineering Workstation. Will be explained right here.

From watching the simulation for a little while, I noticed that the reactor stays around 2700 **kPa**. In the code, there is no line telling the reactor to stay around this number, Instead it is a number that is constantly trying to be caught by the program if you will.

This number is a result of a control loop constantly correcting toward a specific *setpoint*. The variable `pressure_sp` corresponds to ~2700 **kPa**, and the loop perpetually nudges the purge valve to close the gap.

**PLC**'s continuously correct the error toward a setpoint.

Looking at one of the files in the *Chemical* program named *control*, I see this logic.


```
current_value_real := scale_to_real(raw_input_value := current_value, real_max := rmax, real_min := rmin);

setpoint_real := scale_to_real(raw_input_value := setpoint, real_max := rmax, real_min := rmin);

pos_update_real := (setpoint_real - current_value_real) * k;

valve_pos_real := scale_to_real(raw_input_value := current_pos, real_max := 100.0, real_min := 0.0);

valve_pos_limited := LIMIT(0.0, valve_pos_real + pos_update_real, 100.0);


control := scale_to_uint(real_in:= valve_pos_limited);

``` 

![[Pasted image 20260625180138.png]]


From here, we can see that there are multiple variables which gather different data points for the code to actually work. Lets say that the current pressure of the reactor is at 3000 **kPa**, but the *setpoint* in our code says it should be 2700 **kPa**. This means that we are above our *setpoint* by +300. This is where the variable`pos_update_real` comes into play.

This variable subtracts the *setpoint* of 2700 **kPa** from our current pressure of 3000 **kPa**. It then multiplies that output by *k*, and from looking at the *main1* file, we know that the *k* for purge is **-20.0**.

> [!Note] The real function scales the raw register values to engineering units first via `scale_to_real`; I'm using the engineering values directly here to keep the math readable.

![[Pasted image 20260625180620.png]]

`pos_update_real := (2700 - 3000) * -20.0`

Lets stop right here. What is *k* ? *k* is the "gain" or more specifically, how aggressive or gentle the correction to a certain process should be. In this case of the **purge** valve, we will see why *k* is a negative number (-20.0)

Continuing the math from earlier 

`pos_update_real := (2700 - 3000) * -20.0`

`pos_update_real := 6000`

What does *6000* have to do with anything? Well something important to know is that if the output of this math is positive, this means we are nudging the valve **MORE** open. And since the output is positive and a massive number, we are slamming open this valve, but wait, I thought valves could only be **0-100%** ? So how can the number **6000** be used here? well yes valves can only be **0-100%** this is correct. Here is the explanation.

If the valve were already at **80%** and you got a small negative update of **−10**, the valve goes to **70%**, it "closes" in the sense of _moving toward closed_, not slamming fully shut. With our huge 6000-magnitude numbers it usually does hit the rails, but the underlying logic is "*nudge the position by this signed amount*," which is why it's _added_ to the current position rather than replacing it

Now think of our **6000** number, if the valve was at **80%**, this **6000** number would fully and rapidly open the valve, pegging it at 100% once `LIMIT` clamps the result. What is `LIMIT`, well this is a built-in **ST** function that *clamps* a value so it can never fall outside a defined range.

> [!info] It takes three arguments in the form `LIMIT(min, value, max)`: if the value is below the minimum, it returns the minimum; if it's above the maximum, it returns the maximum; otherwise it returns the value unchanged. In our case, the valve position runs through `LIMIT(0.0, valve_pos_real + pos_update_real, 100.0)`. This takes the valve's current position, adds our update to it (`80 + 6000 = 6080`), and then clamps that result between 0 and 100. Since 6080 is far above the maximum of 100, `LIMIT` returns 100, fully open. This is exactly why a massive update like 6000 doesn't break anything: the valve can't physically open beyond 100%, and `LIMIT` enforces that ceiling, catching the overshoot and capping it at fully open. The same protection works on the low end too: if the math ever produced a large negative result, `LIMIT` would floor it at 0 rather than letting the valve go to an impossible negative position.


### Wrong Value of K

IF the value of *k* was a positive number what would happen to our process? Well lets think back, I said earlier that a positive number that comes from the math of the `pos_update_real` variable means we are opening or nudging a valve more towards being fully open. But if *k* was positive in our **purge** function, what would the outcome be? Lets find out.

Lets take our *current* pressure and our *setpoint* pressure and plug those into our function. Remember, our current pressure is **ABOVE** our *setpoint*, which is bad, we do not want to have our current higher than our setpoint.

`pos_update_real := (2700 - 3000) * k`

Doing the math we get

`pos_update_real := (-300) * k`

We are 300 above our setpoint, meaning we have to open this valve in order to release pressure (so we need a positive output from this math). But, lets continue the math.

`pos_update_real := (-300) * 20.0`

`pos_update_real := -6000`

Can you spot the issue yet? The result of our math with a positive *k*, gives us a negative result. And if you remember what I said previously, a negative result means we close or nudge a valve towards being more closed.

So, we know that our *current* pressure is higher than our *setpoint* which is undesirable, however, with the wrong *k* value, nothing gets done to fix it, actually something worse happens. We actively build **pressure** into the reactor by **slamming** the valve SHUT.


### Starting The Attack

By now anyone could see how our attack is most likely going to work. It is very simple. We will change the value of *k* from being *negative* to being *positive*, this will ensure that no pressure would be able to escape the reactor.

> [!warning] I identified that inverting the purge valve's gain sign (−20 → +20) would defeat the pressure-relief control loop, since the corrective math would close the valve precisely when pressure exceeded setpoint. Critically, the GRFICS control program contains no safeguard against this: the `LIMIT` clamps bound values but not control direction, and there is no logic-integrity check. In a real facility, this class of attack is mitigated not by the control PLC itself but by independent layers: Safety Instrumented Systems, mechanical relief devices, and program-change detection. This demonstrates why ICS defense-in-depth never relies on the control logic to police itself


Now I am on the **EWS** looking at the application OpenPLC editor, I currently have a program open that was already on this system and I am editing the *k* value.
	![[Pasted image 20260626183636.png]]


We already know somewhat of how the logic in this program works from the previous dive into why the value of *k* matters. So I will just show me changing the value to positive.
	![[Pasted image 20260626183748.png]]


Once you make any changes to the program in OpenPLC editor, you have to hit the "*Generate Program for OpenPLC runtime*", doing this is critical because it compiles the entire program and ensures that everything is working. 

"*Generate Program*" in the **OpenPLC Editor** does the **first** compile step: it takes your visual/source project and **translates it into a single Structured Text `.st` file**. If there were any syntax or logic errors, they would be caught here.

After hitting this button, it will ask for a name, then a location. The name should be *plc.st*, the .st is important and NEEDS to be added. *.st* files are the ones which we upload to the OpenPLC website.

I named mine the same as the previous which is just *plc.st* and replaced the old. The directory was `engineer/Desktop/chemical (copy 1)/ build`. 
	![[Pasted image 20260626184141.png]]
Now everything in this folder is updated with the change so we can proceed to uploading the malicious program.


The current running program is "*Chemical Reactor*" on the OpenPLC website. I am going to upload my malicious program into OpenPLC and run it to see how it reacts.

OpenPLC is at `192.168.95.2:8080`

From here, I navigate to 'Programs' and browse, then select my malicious program (*"chemical"*. 
	![[Pasted image 20260625185416.png]]

Looking at the 'chemical' folder, which is my program, I open it and see these options
	![[Pasted image 20260625185226.png]]

I then chose 'build' and see these options.
	![[Pasted image 20260625185241.png]]

I finally chose *plc.st*. Here is the reasoning.


 **Why `plc.st` and not the others**
- **`chemical/`**: your project folder (the whole OpenPLC project).
- **`chemical.st`** (on the Desktop, Image 1): likely an export or a copy, not the compiled runtime file.
- **`build/`**: this is the compiled output folder. When OpenPLC Editor compiles your program, the runtime-ready files land here.
- Inside `build/` (Image 3):
    - **`plc.st`** (7.4 kB): **this is the one.** This is the compiled Structured Text file that OpenPLC Runtime loads and executes. From my earlier notes, I already documented that OpenPLC's compiled `.st` lives in the project's `build/` folder as `plc.st`, this matches.
    - **`generated_plc.st`** (7.1 kB): an intermediate generated file, not the one you upload.

So: **`plc.st`** is the runtime program. That's what gets loaded onto the PLC.



I now am going to hit "*Upload Program*" to upload my malicious program.
![[Pasted image 20260625185653.png]]



![[Pasted image 20260626185715.png]]
![[Pasted image 20260626185739.png]]
When you upload the `.st` to OpenPLC **Runtime**, the Runtime does its _own, second_ compile, it takes the `.st` and compiles it into **C code, then into a native executable** the PLC actually runs. This is a separate compilation, happening on the Runtime side, in a different environment.


My new program is now on the list with the others. All that is left to do is run it.
	![[Pasted image 20260626185927.png]]


![[Pasted image 20260626190006.png]]
The program I edited is now running.



### The Result

![[Pasted image 20260626183457.png]]


![[Pasted image 20260626183503.png]]

As we can see, by simply changing the value of *k* from a negative to a positive, the logic now works in the reverse . The **purge** valve does not open when *current* pressure is above *setpoint* pressure, instead it fully closes and holds all the pressure inside.

A blown up reactor is the result. But this is a good learning moment, from this attack that I carried out, I now understand the different ways in which I can protect the system from being compromised.

Not allowing new programs to be uploaded unless verified, firewall rules which can detect nmap scanning and attacker probing the *ICS*, etc.


Something interesting that I found which would've been pretty useful had I put the pieces together earlier, was a full list of the slave devices and their addresses.
	![[Pasted image 20260627103141.png]]

As we know OpenPLC is acting as a *Modbus Master* to the 6 slave devices. Each device has it's data mapped into specific OpenPLC addresses. This chart is the *I/O* mapping, input and output. It states which devices data lives at which address.

- **DI** = Discrete Inputs (on/off inputs): all show `-` (none used). This matches my finding that discrete inputs read all False!
- **DO** = Discrete Outputs (on/off outputs): also all `-` (none used).
- **AI** = **Analog Inputs** (`%IW` = Input Word): these are the _sensor readings coming IN_ from each device.
- **AO** = **Analog Outputs** (`%QW` = Output Word): these are the _commands going OUT_ to each device.


### The device-to-address map

Here's what each slave uses:

| Device   | Analog In (sensors) | Analog Out (commands) |
| -------- | ------------------- | --------------------- |
| Feed 1   | %IW100–%IW101       | %QW100                |
| Feed 2   | %IW102–%IW103       | %QW101                |
| Purge    | %IW104–%IW105       | %QW102                |
| Product  | %IW106–%IW107       | %QW103                |
| Tank     | %IW108–%IW109       | %QW104                |
| Analyzer | %IW110–%IW112       | %QW105                |

Each device reports 2 analog **input words**, as you can see for any of the devices, you see a range of 2. For example **Feed 1** is *%IW100–%IW101*, read it as 100-101. That is 2 **input words**. This is almost certainly valve position and flow rate for that device.

Let me explain all the terminology behind this to get a grip on the idea. So these names for the table such as *%IW100–%IW101*, follow the **IEC 61131-3** addressing standard, which is the same standard that defines **Structured Text**. Every address has 3 parts: a `%`, then *two letter codes*, then a *number*.


Taking *%IW100* lets dissect it.

**Part 1: `%`** : Just a marker that says "this is a hardware/memory address." Every **IEC** address starts with it. Ignore it as meaningful, it's punctuation.

**Part 2: first letter: the _location/direction_** :
- **`I`** = **Input**: data coming **INTO** the **PLC** (from sensors/field devices). The **PLC** reads these.
- **`Q`** = **Output**: data going **OUT** of the **PLC** (commands to actuators). The **PLC** writes these. (Q is used because "O" looks too much like zero.)
- (`M` = internal memory, but you won't see that here.)

**Part 3: second letter: the _size_** :
- **`X`** = a single **bit** (1 on/off value): used for *coils* and *discrete I/O*.
- **`W`** = a **Word** (16 bits): used for **analog values** (my *registers*). A "word" is 16 bits = one UINT16, exactly the register size I've been working with.
- (`B` = byte/8 bits, `D` = double word/32 bits, not used here.)

**Part 4: the number** : which specific address in that category.
So **`%IW100`** reads as: **`%`** (address) + **`I`** (input, coming in) + **`W`** (word, 16-bit analog) + **`100`** (number 100) = **"Analog Input Word #100"**: a 16-bit sensor reading coming into the **PLC** at address 100.

And **`%QW100`** = **`Q`** (output) + **`W`** (word) + **`100`** = **"Analog Output Word #100"**: a 16-bit command going out of the **PLC** at address 100.


The way the ranges work is just as you would expect.

So for *Feed 1*:
- **`%IW100 to %IW101`** = two analog input words = **two sensor readings** coming in (your position + flow pair).
- **`%QW100 to %QW100`** = a range that starts and ends at the same number = **just one** word (%QW100) = **one command** going out (the valve setpoint).


**Feed 1: AI %IW100–%IW101, AO %QW100–%QW100** reads as:

- "**Feed 1** sends the **PLC** *two analog* sensor readings (input words 100 and 101), and the **PLC** sends **Feed 1** *one analog* command (output word 100)."



The reason that the command output or *%QW100-%QW100* is just a single value, not an actual range as the *%IW100-%IW101*, is because the **PLC** needs 2 sensor readings, the current valve position and the current flow rate, with this information, the **PLC** then can tell the valve to increase or decrease the valve position. This single piece of info that the **PLC** tells the *Field Device* can be done in one command,  **valve setpoint**.


>[!info] The IEC address encodes everything: `%` + direction (`I`=in/`Q`=out) + size (`X`=bit/`W`=word) + number. So `%IW100` = analog sensor reading #100 coming in; `%QW100` = analog command #100 going out. This process uses only word-sized (analog) I/O (no discrete bits), confirming it's a fully analog, modulating-valve process, which is why register manipulation (not coil toggling) is the real attack surface.









## Replay Attack

What is a replay attack? A replay attack is where you capture a packet that is sent to an endpoint, and replay that old packet at a later time. In my case, I will be capturing a **write single coil (FC5)*** packet, **FC5** turns on/off a single *coil*.

For transparency I will note that this is not a 'true' replay attack in the context that the packet that I am going to be capturing is not a natural packet that just happened to be sent to the **PLC** from the **HMI**. I will be on the **HMI'**s website and send the **FC5** command. Reason being is that the *Chemical A process* will never turn off so this command would never be sent if I don't send it.

The overview is this. I am going to *arpspoof* both the **HMI** and the **router** so that I can capture the **FC5** 'off' packet going to the **PLC** as well as the response to the **HMI**. Now that the process is off, I will turn it back on shortly after. From here I will download the pcap file and replay the captured **FC5** packet and watch to see if the **PLC** turns off the entire process again.



*The refined Plan* 
- **Establish MITM position**: ARP spoof both directions + `ip_forward=1`, so HMI↔PLC traffic routes through Kali (you've done this multiple times now).
- **Start a capture** filtered for Modbus writes, saving to a pcap.
- **Hit the "turn off" button on the HMI**: generating the real write command, which now transits Kali and gets captured.
- **Stop the capture.** You now have a pcap containing the HMI's legitimate "turn off" write.
- **Turn the process back on** via the HMI (clean state).
- **Tear down the MITM** (you don't need the spoof for the replay itself, the replay opens its own connection to the PLC).
- **Replay** the captured write and watch whether the PLC turns off again.



### Arpspoofing


1st Spoof
	![[Pasted image 20260627115033.png]]


2nd Spoof
	![[Pasted image 20260627115115.png]]


I *arpspoofed* both endpoints, the **HMI** and the **router** in order to capture the packet being send to the **PLC** and the response back. Technically I do not need to *arpspoof*the router since all I need is the **HMI**s 'off' packet, but I did just to engrave this into memory.


Now that these endpoints are both spoofed and I can see the packets traversing the network, time to capture the **FC5** packet.

I set up a filter in WireShark in order to only capture **FC5** packets. I am listening to the packets on the interface used in my *arpspoof* command from earlier, interface *eth0*.
	![[Pasted image 20260627115857.png]]


I am now going to turn off the process from the **HMI** located at `192.168.90.107` and we will see the **FC5** packet in WireShark.
	![[Pasted image 20260627120052.png]]

We know have what we need to complete the attack. The process is back on. I then saved this .pcap file to my machine and named it *replayAttack.pcapng*. I had to convert this file from .pcapng to pcap in order for `tcpreplay` to use it. Using this command in the directory of the file
```
editcap replayAttack.pcapng replayAttack.pcap
```


> [!info] An **FC5** packet has a byte value inside of it, if the **FC5** is a "turn off" command, the byte value would be *0000*, if it was a "turn on" command, the byte value would be *ff00*, as shown below.

Off
	![[Pasted image 20260627120526.png]]

On
	![[Pasted image 20260627120540.png]]


### Replaying The Packet (Method A)

I can turn off the *arpspoof* for the replay part of this attack as it is not needed. In order to replay a packet we have to use a tool called `tcpreplay`.


 **Method A:  Raw packet replay with** `tcpreplay`

**What `tcpreplay` is:** a tool that reads a pcap file and re-injects the **raw packets exactly as captured**: byte for byte, including all the original headers (Ethernet, IP, TCP, and the Modbus payload). It's the most literal form of "replay": it doesn't understand or change anything, it just blasts the saved packets back onto the wire.

**The command:**

```bash
sudo tcpreplay -i eth0 /full/path/to/replayAttack.pcap
```

- `sudo`: injecting raw packets requires root.
- `tcpreplay`: the replay tool.
- `-i eth0`: the **interface** to send the packets out of (my ICS network interface, where the PLC is reachable).
- `replayAttack.pcap`: the file containing my captured "turn off" command.

**What this does:** reads every packet in the pcap and re-sends it out eth0, exactly as it was recorded.

**Why it will probably FAIL** . My captured packets contain the **original TCP sequence numbers** from the _original_ connection,  a connection that's long since closed. When I replay these raw packets:

- The PLC's TCP stack receives a packet with sequence numbers that don't match any active connection.
- TCP says "I have no open connection with these sequence numbers, this is garbage" and **drops it.**
- The Modbus command inside never gets processed, because TCP rejected the envelope before the PLC's Modbus layer ever saw it.

So the process **won't** turn off.  **TCP's statefulness provides accidental, partial protection against naive replay.** But, we will still try to see if it works nevertheless.




So here is the command again (in the directory where replayAttack.pcap is located)

```bash
sudo tcpreplay -i eth0 replayAttack.pcap
```


Before
	![[Pasted image 20260627121946.png]]


After
	![[Pasted image 20260627123957.png]]
	![[Pasted image 20260627124015.png]]

As you can see, it did not work. This is a lesson though and something to take note of. As mentioned earlier, TCP has its own built in defense against replay attacks. The PLC's TCP stack receives a packet with sequence numbers that don't match any active connection so the **PLC TCP** stack  drops the packet.

You can also see from my screenshot of the terminal that I am getting a lot of errors/warnings. This points out another thing about `tcpreplay`. This tool in the way that I used it, just shoots every single packet I captured in that "*replayAttack.pcap*" file I had from WireShark earlier, not just the **FC5** packet I was actually looking to replay.



>[!Note] Raw replay via **tcpreplay** proved impractical for three reasons: **(1)** it replays the entire pcap indiscriminately, flooding the network with hundreds of irrelevant captured packets rather than the single target command; **(2)** capture artifacts from NIC offloading (oversized logical packets exceeding the 1500-byte MTU) failed to transmit; and **(3)** even successfully transmitted packets carried stale TCP sequence numbers the PLC rejected. This motivated an application-layer replay (Method B), which surgically re-sends only the captured Modbus payload over a fresh, valid TCP connection.





### Replaying The Packet (Method B)

Since the use of the tool `tcpreplay` failed, I will be using  method that will actually work to replay the packet I want. I want to note that this way works because i will be establishing a new TCP connection, then sending that old packet content through that new TCP connection.


In order to do this new method, I need the bytes of the packet which I want to replay. So, I go to the packet I want, the **FC5** off command, right-click the **"Modbus"** (or "Modbus/TCP") layer in the detail tree → **Copy → ...as Hex Stream**. That gives you the Modbus payload as a hex string:

```
163800000006010500280000
```

*Decoded*

- **`1638`**: **Transaction ID** (MBAP header). This is a per-request identifier the client picks; here it's 0x1638. (In the example I gave earlier it was `0001`, mine is just a different transaction number, which is completely normal. Each request gets its own ID.)
- **`0000`**: **Protocol ID.** Always `0000` for Modbus. ✓ Confirms this is genuine Modbus.
- **`0006`**: **Length.** Says 6 bytes follow (the Unit ID + function code + address + value = 1+1+2+2 = 6). ✓
- **`01`**: **Unit ID.** The target unit/slave identifier on the PLC. ✓
- **`05`**: **Function Code 5 (Write Single Coil).** ✓ This is your write command: exactly what you want to replay.
- **`0028`**: **Coil address.** 0x28 = **40** in decimal. ✓ **Coil 40: your Chemical A process enable.** This is the right packet.
- **`0000`**: **The value.** `0000` = **OFF**. (`FF00` would be ON.) ✓ So this command says "set coil 40 to OFF": your "turn off" command.


I have to use a python script in order to do this attack using the HEX I captured. It will look similar to the one used in the *Registration Manipulation w/ MITM Attack* that I did earlier.


**The Replay Command line by line**

```
python3 -c "
import socket
captured = bytes.fromhex('163800000006010500280000')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.95.2', 502))
s.sendall(captured)
resp = s.recv(1024)
print('Replayed bytes :', captured.hex())
print('PLC response   :', resp.hex())
s.close()
"
```


- **`python3 -c "..."`**: runs the multi-line Python inside the quotes directly, no script file needed. The `-c` flag means "execute this code string."
- **`import socket`**: loads Python's `socket` module, the low-level networking library. We use a **raw socket** deliberately: it lets us send the _exact_ bytes we choose with nothing in between interpreting, validating, or rebuilding them. This is the entire reason it counts as a _replay_: pymodbus would _construct_ a command from parameters; a raw socket just _ships the bytes you hand it._
- **`captured = bytes.fromhex('163800000006010500280000')`**: the heart of the replay. `bytes.fromhex(...)` takes my captured hex string and converts it into the literal raw bytes those hex digits represent. The variable is named `captured` to be explicit: this is my recorded packet's payload, untouched. 
- **`s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)`**: creates the socket object.
    - `socket.AF_INET`: **A**ddress **F**amily **INET** = IPv4. Tells the socket to use IPv4 addressing.
    - `socket.SOCK_STREAM`: the socket type for **TCP** (a reliable, connection-oriented stream). The alternative, `SOCK_DGRAM`, would be UDP, but Modbus runs over TCP, so we use STREAM.
    - Together: "make me a TCP/IPv4 socket."
- **`s.connect(('192.168.95.2', 502))`**: opens a **fresh, brand-new TCP connection** to the PLC.
    - `'192.168.95.2'`: the PLC's IP.
    - `502`: the Modbus TCP port.
    - This line is _why Method B works where tcpreplay failed._ The OS performs a real TCP handshake here and assigns **valid, current sequence numbers**. The stale sequence numbers that doomed Method A never enter the picture: this is a legitimate, live connection. The "new envelope" for my captured "letter."
- **`s.sendall(captured)`**: pushes my captured bytes into the open connection. `sendall` keeps sending until every byte is delivered (vs. plain `send`, which might send only part). We send `captured`, the recording itself, not a constructed command. This is the replay actually happening.
- **`resp = s.recv(1024)`**: reads the PLC's reply, up to 1024 bytes, storing it in `resp`. After a write, the PLC sends back an acknowledgment; this captures it so we can see whether it accepted or rejected the command.
- **`print('Replayed bytes :', captured.hex())`**: prints what I sent, as hex, for your records/evidence. `.hex()` converts the raw bytes back to a readable hex string.
- **`print('PLC response :', resp.hex())`**: prints what the PLC sent back, as hex. This is the line that tells you accept vs. reject.
- **`s.close()`**: closes the TCP connection cleanly, freeing the socket.

Running the command
	![[Pasted image 20260627131118.png]]



### The Result

![[Pasted image 20260627131109.png]]
![[Pasted image 20260627131129.png]]


As we can see, the *Chemical A process* valve is turned off. In order to reverse this, I can do the same exact process but with the "on" **FC5** packet I captured earlier as well.




### Replay Attack: Wrap Up

So to sum up the whole replay attack, I tried two different ways to do it. The first way with `tcpreplay` (Method A) failed, and the second way with the python script and a fresh TCP connection (Method B) is what actually worked.

The reason Method A didn't work comes down to TCP. `tcpreplay` just shoots the raw captured packets back onto the wire exactly as they were, original sequence numbers and all. But those sequence numbers belonged to a connection that closed a long time ago, so the PLC's TCP stack looks at them and goes "I don't have a connection matching these numbers" and drops the packet before the Modbus command inside ever gets read. On top of that, it floods the network with every single packet in the pcap instead of just the one I wanted, and some of those packets were too big to even send because of the NIC offload capture artifacts.

Method B worked because instead of replaying the whole packet with its dead sequence numbers, I pulled out just the Modbus payload bytes (`163800000006010500280000`) and sent them through a brand new TCP connection I opened myself. The fresh handshake gives me valid, current sequence numbers, so TCP has no reason to reject anything, and the PLC happily processes the old "turn coil 40 off" command like it was legit.

The big takeaway is that Modbus has no protection against this at all. There's no sequence numbers, timestamps, nonces, or sessions at the Modbus layer, so it has no way of knowing a command is a recording instead of a real one. The only thing that even slowed me down was TCP's statefulness, and that's not a Modbus defense at all, it's just an accidental side effect of the transport layer that I got around the second I opened a new connection. That's exactly why replay detection for Stage 4 has to happen at the network monitoring level instead of relying on the protocol to defend itself.










## Holding Register Write Attack


This attack is different from the last register attack because this attempts to change the actual process, and whether it holds depends on whether I hit a setpoint the loop chases or a command it recomputes. The other register attack I did only made it **seem** like the process was being affected, when in reality, it was just fine.

The way I am going to carry out this attack is pretty similar to the other one. First, I am going to conduct recon and figure out which holding *registers* exist and hold meaningful writable values. Then I am going to correlate one of those *registers* to the process and write to it.

### Holding Register Explanation

Something I didn't explain earlier was there are 2 types of *registers*. **Holding** and **Input**. **Input registers** are where sensors store their values, meaning they cannot be overwritten. When a sensor detects the pressure in the Reactor to be 2700 **kPa**, this gets stored inside an **input register**

A **holding register** is writable on the other hand, a **holding register** can express a range or a degree, for example, "valve a is 50% open", this value is held in a **holding register**. If I was to change the value of that number in that *register* to lets say  65535, the valve would be 100% open (**assuming the scaling is 0-65535**). This is true because if we think back to my earlier documentation, these *registers* are 16 bit numbers (0-65535).

Here is a visual to help grasp the concept of **holding register**, **input registers**, **coils**, and **discrete inputs**.
	![[Pasted image 20260703185922.png]]

The four boxes are four separate storage areas inside the PLC. Two hold single bits (Coils, Discrete Inputs), two hold 16-bit words (Input Registers, Holding Registers). My coil attack hit the top-left box. My pressure mapping was the bottom-left box. This attack targets the **bottom-right box**.

Holding *registers* are rarely seen on the wire (the **HMI** mostly polls input *registers* via **FC4** for its gauges, and only touches holding *registers* on a control action), which is why my Wireshark captures didn't catch any. 

The [Coil Manipulation Attack](#coil-manipulation-attack) that I did, was on the *Chemical A* process. Now this process specifically, is controlled by a **coil**, on or off. BUT, the **purge valve** is controlled by a *register*. Its not confined to being just open or just closed, it can be in between. This is a key concept to understand.


> [!info] Depending on the **field device**, *coils* or *registers* will be used to control the device. For example, the *Chemical A* process in this simulation is controlled by a *coil (on or off)*, while the *purge valve* is controlled by a *register* because it's a *modulating* valve, its position is a value anywhere from fully closed to fully open, not just on/off.. Something do take into account is that a process can be controlled by **BOTH** registers and coils if need be.


### Capturing Holding Register Traffic

Since I have never even seen **holding registers** yet, I will generate that traffic in order to get a grasp of how it works and looks like.

First I will capture traffic with WireShark on the interface `eth0`, the interface Kali uses from my Kali machine.

Then I will run the command in the terminal which will send an **FC3** command to the **PLC** which requests the current holdings of *registers* 0-124.

 After, I will dissect the packet that gets captured in WireShark to see how **holding registers** look like.

The command for querying the **PLC** for **holding registers** is

``` python
python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('192.168.95.2',port=502); c.connect(); r=c.read_holding_registers(0,count=125); print('Holding regs 0-124:', r.registers if not r.isError() else r); c.close()"
```

- `python3 -c "..."`: run the inline Python.
- `from pymodbus.client import ModbusTcpClient` - import the Modbus TCP client class.
- `c=ModbusTcpClient('192.168.95.2',port=502)` - client aimed at the PLC on the Modbus port.
- `c.connect()` - open the TCP connection.
- `c.read_holding_registers(0,count=125)` - **FC3 read**: read 125 holding registers starting at address 0. 125 is the protocol max per request, so this sweeps the widest allowed block in one shot. This is the packet you'll watch appear in Wireshark.
- `r.registers` - the list of returned 16-bit values.
- `if not r.isError()` - print values on success, else the error object.
- `c.close()` - close cleanly.

I can see that most of the *holding registers* are 0, but there are some that have a value above 0.
	![[Pasted image 20260703193923.png]]


Now lets check WireShark
	![[Pasted image 20260703194056.png]]
There it is! A packet containing the *holding registers*. Lets dissect the packet.


I see that there are *registers* 0-124. Again, some with value others with no value.
	![[Pasted image 20260703194151.png]]

### Dissecting The Registers


I was wondering why there was so many *registers*. The reason is because most of them are unused, they're just there in case they need to become of use. It is not a list of active devices. Also, the reason why we see so many at once in this packet is because my command specified to get all 125 *registers*, I could've asked for 10 if I wanted to.

Since *registers* 100 and 103 are the only ones with values, I am going to run a new scan which only scans for those, and does it 10 times right after each scan. Just to see how these behave while the process is running.
	![[Pasted image 20260703200019.png]]

The command used is
```
python3 -c "
from pymodbus.client import ModbusTcpClient
import time
c = ModbusTcpClient('192.168.95.2', port=502)
c.connect()
for i in range(10):
    r = c.read_holding_registers(100, count=4)
    if not r.isError():
        print(f'read {i}: reg100={r.registers[0]}  reg103={r.registers[3]}')
    else:
        print(f'read {i}: ERROR {r}')
    time.sleep(1)
c.close()
"
```
- `for i in range(10):` - loop ten times. `i` counts 0 through 9. Ten samples over ten seconds is enough to see drift without waiting forever.
- `r = c.read_holding_registers(100, count=4)` -**FC3 read**: read 4 holding registers starting at address 100. That grabs registers 100, 101, 102, 103 in one request. We read the small span 100–103 rather than all 125 because those are the only addresses in play, and reading 4 is faster and cleaner than re-sweeping 125 each loop.
- `if not r.isError():` - only process the values if the read succeeded.
- `r.registers[0]` - the first register in the returned list, which is address **100** (since we started at 100). Index 0 = first one read.
- `r.registers[3]` - the fourth register returned, which is address **103** (100 + 3). Index 3 = fourth one read.
- `print(f'read {i}: reg100={...} reg103={...}')` -print each sample labeled with its loop number so you can watch the sequence. The `f'...'` is an f-string, it drops the variable values into the text.
- `else: print(... ERROR ...)` -if any read fails, print the error instead of crashing.
- `time.sleep(1)` - pause 1 second between reads. This spacing is what lets you _see_ drift, if you hammered with no delay, the loop might not have recomputed between samples. One second gives the PLC's control loop time to adjust the values if it's going to.
- `c.close()` - close the connection cleanly after all ten reads.


Interesting, *register* 100 is staying at a max value of 65535, this makes me think it is the *Chemical A* valve.  

I want to take a moment to think about what "**Chemical A feed**" actually needs: an on/off _enable_ (are we feeding at all?) and potentially a _rate/position_ (how much are we feeding / how open is the valve?). Those are two different control signals for one device:
- **The coil (coil 40)** = the on/off _enable_ bit. "Feed enabled" vs "feed disabled." Binary. This is what you flipped in your coil attack to stop the process.
- **The holding register (register 100)** = the _valve position / output magnitude_. When the feed is enabled and running normally, the valve is commanded fully open, hence **65535 (100%)**, always maxed, exactly as you noticed.

My hypothesis is that the *Chemical A* process is controlled by both a **coil** AND a *register*. Another thing I am assuming, is that the *register* 103 is the **product valve**. Why? This is because when I ran this command to scan the 2 *registers* 10 times, I was watching the actual simulation, and during the 10 scans, I saw the **product valve** consistently increasing in value, when I tabbed back to the terminal to see the scan, the *register* 103 value was also increasing. At the same time the only other device that had a reading was the **purge valve**, but this valve was going down in value not up.

This leads me to believe that *register* 103 is the **product valve**. 



### Finding The Purge Valve Register


In order to figure out which *register* belongs to the **purge valve** that I want to attack, I am going to run a scan which only prints the *registers* with a value to the terminal. This way, I can watch the **HMI** on one screen and the terminal on my other screen and correlate the two with each other. The command is as follows,

```
python3 -c "
from pymodbus.client import ModbusTcpClient
import time
c = ModbusTcpClient('192.168.95.2', port=502)
c.connect()
for i in range(15):
    r = c.read_holding_registers(0, count=125)
    if not r.isError():
        nonzero = {addr: val for addr, val in enumerate(r.registers) if val != 0}
        print(f'read {i}: {nonzero}')
    else:
        print(f'read {i}: ERROR {r}')
    time.sleep(1)
c.close()
"
```

- `for i in range(15):` - loop 15 times (a few more samples than last time, to give a slow-moving or currently-zero register more chances to show a value).
- `r = c.read_holding_registers(0, count=125)` - **FC3 read** of the full 0-124 block each pass, not just 100-103. This is the widening: you re-sweep everything every second so nothing hides.
- `nonzero = {addr: val for addr, val in enumerate(r.registers) if val != 0}` - this is the key new line, a **dictionary comprehension** that builds a filtered view showing only the registers that aren't 0.
    - `enumerate(r.registers)` - pairs each register value with its address index (0, 1, 2, ...). `enumerate` hands you both the position and the value as it walks the list.
    - `for addr, val in ...` - unpacks each pair into `addr` (the register number) and `val` (its value).
    - `if val != 0` - keeps only the ones with a nonzero value, filtering out the sea of empty slots.
    - `{addr: val ...}` - collects the survivors into a dictionary like `{100: 65535, 103: 52700}`, address mapped to value.
    - Net effect: each line prints _only the registers that currently hold a value_, so if a third register (the purge valve) blinks on at any point during the 15 passes, it appears.
- `print(f'read {i}: {nonzero}')` - prints the filtered dict per pass, labeled by pass number.



OUTPUT
![[Pasted image 20260706191509.png]]

When correlating the the physical process itself with the output from the terminal, I noticed that as the **purge valve** was going down, the *register* 102 would go down as well, and eventually when the **purge valve** was at 0, *register* 102 would not longer show up in the terminal anymore. Then, when the **purge valve** would increase, I saw *register* 102 pop up in the terminal output again. This leads me to believe that *register* 102 is the **purge valve**. 

The only way to know for sure it so attack it though. Here is where I am at.

- **Register 100** = Chemical A valve position (pinned at 65535 / max when enabled)
- **Register 102** = **purge valve** reading (erratic, high-gain, overcompensating, matches k=−20; later found to be a mirror, not the actuator)
- **Register 103** = product valve (smooth glide)

Now, since *register* 102 overcompensates, I cannot just do an attack that sends a single command, I need to hammer this valve closed with many commands so that it will override the **PLC**'s constant scanning and re-evaluating.

The **PLC** runs a scan cycle: read inputs, compute logic (including recomputing valve 102 from the pressure error and the aggressive k=−20 gain), write outputs, repeat. Each cycle it overwrites 102 with its own calculated value. A single write from me loses instantly because the very next scan stomps it. This is the reason I have to send lots of commands constantly, not just one. This is where my "**hammer**" comes into play.

Instead of one write, I fire writes in a tight endless loop as fast as possible. It is a race. If I write my value more often than the **PLC** recomputes it, then most of the time the register holds my value instead of the **PLC**'s. I am not stopping the **PLC**'s logic, I am flooding the *register* faster than it can overwrite me. My script is just `write_register(102, ...)` inside a `while True:` loop with no delay. It sent over 260,000 writes before I stopped it.

I can run the attack right now, but I would like to have a baseline to see how the attack works throughout time. To do this, I need to use a command which can print the values of the **pressure** in the *chemical reactor*. I thought from my previous *register* mapping, that *register* 8 was pressure for the reactor, however now things are different.

I realized *register* 8 wasn't pressure anymore, so I swept the **input registers** and found the live sensor cluster up at addresses 106 through 112. To pin down which one was reactor pressure, I toggled the process off (pressure falling) then back on (pressure rising) to create a known trend, then watched which *register* reversed direction at the exact moment I flipped it. **Register 108** was the only one that reversed in lockstep with my toggling, so 108 is the *reactor* pressure *register*. Its raw value sits around 55000.

With pressure identified, I went after the **purge valve** (register 102). My first hammer attempt failed, partly because Suricata wasn't even running at the time, and partly because I was writing the value 0, which is camouflaged by the loop's own natural swings through 0. So I switched to hammering register 102 with the value **1** instead. Value 1 is functionally closed, but the control loop never produces exactly 1 on its own, so it became a marker: any time I saw 102 read 1, I knew my write had won, not the loop.

**Hammering register command**
```
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('192.168.95.2', port=502)
c.connect()
print('[*] Hammering register 102 -> 1 (closed). Ctrl+C to stop.')
count = 0
try:
    while True:
        c.write_register(102, 1)
        count += 1
        if count % 500 == 0:
            print(f'[*] {count} writes')
except KeyboardInterrupt:
    print(f'\n[*] Stopped after {count} writes.')
    c.close()
"
```
![[Pasted image 20260706204946.png]]



I ran the hammer in one terminal and a monitor in another, reading pressure (108) and the purge valve (102) side by side. The monitor showed purge = 1 for about 30 straight reads, roughly 15 seconds unbroken. **I won the write-race and pinned the purge valve command to closed.** Beating the **PLC**'s constant scan-and-recompute is the thing I set out to do, and the steady stream of 1's proved I did it.
	![[Pasted image 20260706205048.png]]



### What happened 

Two surprises came out of it.

First, pressure never moved. *Register* 108 held flat at about 55200 the entire time the valve command read 1. So pinning the purge valve closed did **not** raise reactor pressure the way I expected.

Second, while my terminal showed 102 = 1 (closed), I looked at the 3D simulation and saw the purge valve **actively venting**, clearly open. The register said one thing, the physics showed another.

Putting it together, I landed on 2 findings

1. I can beat a live PLC control loop with a write flood. The pinned 1's prove it.
2. *Register* 102 is a **window onto the valve, not the valve's actual actuator**. I pinned the register *to* closed, but the physical valve kept venting and pressure stayed flat. If 102 truly commanded the valve, one of those two things would have changed. The most likely explanation is that **GRFICSv3** actuates the **purge valve** from an internal program variable, and register 102 is just a **Modbus**-exposed mirror of that variable. I can write it and hold it, but the physics engine doesn't read it to move the valve. I was writing to the speedometer, not the accelerator.

The big lesson: **the value I can read and write over Modbus is not guaranteed to be the value that physically controls the equipment.** The network layer and the physical layer can be decoupled. An attacker who writes a register and sees it stick can wrongly think they've seized control while the plant runs fine. That is exactly what makes ICS security hard, and I demonstrated it by accident.

One thing that did work cleanly: once Suricata was actually running, the hammer threw hundreds of rule 1000002 alerts. So the detection half of this attack, which is the real point of Stage 4, was a full success.

### Conclusion

This attack did not achieve a physical impact, but figuring out _why_ taught me more than a clean success would have.

I set out to close the **purge valve** by writing to *register* 102 and watch *reactor* pressure climb. After identifying pressure at *register* 108 and confirming the **purge valve** at *register* 102, I hammered *register* 102 with the value 1 (closed) and won the write race against the **PLC**'s control loop. My monitor read 102 as a steady 1 for about 15 seconds, which proved my writes were beating the PLC's constant recomputing. But pressure (*register* 108) never moved, and when I looked at the 3D simulation, the **purge valve** was still actively venting even though the *register* said it was closed.

That contradiction is the actual finding, **the value I can read and write over Modbus is not always the value that physically controls the equipment.** My best explanation is that *GRFICSv3* actuates the purge valve from an internal program variable, and register 102 is only a Modbus-exposed mirror of that variable. I can write it and hold it, but the simulation's physics does not read it to move the valve. I was writing to the speedometer, not the accelerator.

This also explains the difference between this attack and my earlier [Injected Structured Text (ST) Attack](#injected-structured-text-st-attack), the one that actually exploded the reactor. The ST attack won because it changed the **logic the PLC runs**, so the valve genuinely stayed closed and pressure genuinely built. My hammer only changed a **register value over the network**, and the physics ignored that *register*. The ST attack controlled the program. My hammer controlled a number the program does not act on. Same lesson from two sides: network values and physical control can be decoupled.

The most important takeaway for the defense side of this project is that even though my writes never moved the valve, **every one of them was still detected.** Once *Suricata* was running live, the hammer threw hundreds of rule 1000002 alerts. An unauthorized **FC6** write is malicious traffic whether or not it succeeds, and a good IDS flags the _attempt_. A defender never gets to assume an attacker's writes will fail, so detecting the attempt is the right way to go about it. That is the point of Stage 4, and this attack confirmed the rule works.

> [!note] Open thread  
> Getting a real physical pressure change is still possible, most likely by attacking the product valve (register 103), which draws mass out of the reactor, rather than the purge valve. Closing product draw should trap mass and raise pressure. I am leaving this as a future experiment and moving on to build out the rest of my detection rules, since the detection goal for this attack is already met.





























# Stage 4: Detection and Defense


## Setup


To setup *Suricata* rules for this simulation, I had to install *Suricata* on my system and then install *Wazuh*. The reason I am installing *Wazuh* is because it will be able to make sense of all the logs that *Suricata* will generate, it will aggregate them and show me a clean visual.

After installing both, I have to configure *Suricata* to be pointed at the correct network interface in order for it to capture the simulation's traffic and from there I can confirm that is is 'logging' traffic to `eve.json`.  I will get more into the specifics down below but lets start the process.


### Figuring out the Network 


First I have to figure out which interface my *GRFICSv3* containers are talking on so I know which interface to point at. To do this I inspected every docker network on my system with the command 

```
docker network ls
```

This shows a table with columns stating the different networks and more specifically, the networks that *GRFICSv3* made.

From here I inspect each one by using the NETWORK ID given for each network in this command 

```
docker network inspect <NETWORK_NAME_OR_ID>
```


After inspecting the networks that *GRFICSv3* created and the IPs inside them, I realize that two of the critical networks are running on a **macvlan**
	![[Pasted image 20260629201332.png]]

This is going to be trouble, and I will explain why. A normal docker _bridge_ works like a switch sitting on your host. The traffic between each container physically passes through a virtual interface on the host, so _Suricata_ running on the host would be able to see that traffic.


**Macvlans** work differently from this. A **macvlan** gives each container its own virtual MAC address and attaches it directly to a physical interface on your host. The containers appear as separate physical machines hanging off of your real NIC, each with its own MAC.


Because of this, the host itself cannot talk to or see its own **macvlan** container traffic through the normal stack. **Macvlan** purposely isolates the parent host from the **macvlan** interfaces. This is why running `ip link show type bridge` only showed me the admin bridge and not the ICS or DMZ networks. There simply is no bridge interface for them to watch.
	![[Pasted image 20260629202111.png]]
To wrap this all up in a nice gift box with a bow, the **Modbus** traffic that I want to inspect is flowing over a physical interface (in my case `eno1`) at the MAC layer, but my host's normal view can't pick it cleanly off a tidy bridge device.


The solution is to point _Suricata_ at the `eno1` interface, since this is the only option that captures both the ICS and DMZ net traffic in one place (both macvlans share `eno1` as their parent). It also mirrors how a real network IDS sensor is deployed, watching a physical link rather than a virtual one.





### Installing Suricata


Now that I know where *Suricata* is going to be monitoring, I can get into the process of installing and setting up.

``` 
sudo apt update && sudo apt install suricata -y
```


Now after that finishes, it is time to configure it. Really quick its good to make sure that the interface is up and running and its the exact name *Suricata* will expect.
	![[Pasted image 20260629210629.png]]
It's up an running all good.




The way that *Suricata* controls everything such as what interface to watch, what protocols to decode, what rules to load, where to write alerts etc, is all through a **YAML** file, this is the config file. It will be at `/etc/suricata/suricata.yaml`

I have to tell it about my labs address space so that is knows what is "inside" the network and what is "outside" the network. Near the top of the config there's a `vars` section defining `HOME_NET` (the networks *Suricata* considers "ours" and protects) and `EXTERNAL_NET` (everything else). By default `HOME_NET` is set to generic private ranges so I need to change this scope to the two lab subnets, `192.168.95.0/24` (ICS) and `192.168.90.0/24` (DMZ), so *Suricata*'s notion of "inside" matches my lab.

After that I have to confirm that the **Modbus** parser is enabled. This will let me write rules that references **Modbus** function codes instead of just matching raw bytes.


### Configuration

Before editing the config file, I will create a backup.

```
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
```

Now I will go into the config file and change the network to the values that they need to be for the simulation.
```
sudo nano /etc/suricata/suricata.yaml
```
![[Pasted image 20260629211743.png]]

Breaking down what I see here this is what it all means in the `vars` group.
- `vars`: a section for variables *Suricata* reuses across rules. Define a value once here, reference it everywhere.
- `address-groups`: variables that hold sets of IP addresses/subnets.
- `HOME_NET`: the networks *Suricata* treats as "the things I'm protecting": your turf. Rules constantly reference `$HOME_NET` to mean "my side." Default is the three RFC 1918 private ranges (the `192.168.x`, `10.x`, `172.16–31.x` blocks), which is a catch-all so *Suricata* works out of the box on any home network.
- `EXTERNAL_NET`: defined as `!$HOME_NET`, where `!` means "not." So external is literally "everything that isn't home." This is what lets a rule say "alert when something from **EXTERNAL_NET** writes to my **PLC**": *Suricata* computes that as "anything not in **HOME_NET**."

I then changed what the `HOME_NET` value was, I put it as the subnet from the *GRFICSv3* simulation
	![[Pasted image 20260629212203.png]]


`192.168.95.0/24` - the *ICS* network, where the **PLC** lives at `.2`

`192.168.90.0/24` - the *DMZ* network, where the HMI lives at `.107`


To summarize what I did here, I created a backup of the config file that *Suricata* uses for its behavior, just in case something went wrong. Then I editing the `vars` section of the config file to change the network in which *Suricata* considers "mines to protect" to the *ICS* and *DMZ* networks from the simulation.


Now I just hit save on the file. Ctrl+O + Ctrl+X. Optionally, test the newly saved config

```
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

- `-T`: test mode. This is the important one: it tells Suricata to load and validate the entire config and ruleset, confirm everything parses, then exit _without actually capturing traffic_. It's a dry run, a syntax and sanity check. This is exactly how you catch a broken edit before it matters.
- `-c /etc/suricata/suricata.yaml`: `-c` specifies the config file to use. You're pointing it at the file you just edited.
- `-v`: verbose. Prints more detail as it runs, so if something's wrong you get a useful message about what and where, not just a silent failure.





## What are Rules?


What is a *Suricata* rule? A *Suricata* rule is a single line of text following a strict grammar. It says, in effect, "if you see a packet matching this description, do this thing." Here's the anatomy, because it'll make everything below concrete:

```
action  header                               options
alert   tcp  $EXTERNAL_NET any -> $HOME_NET 502   (msg:"..."; sid:1000001; rev:1;)
```
- **action**: what to do on a match. `alert` is the one you'll use (generate an alert). Others exist (`drop`, `pass`), but for IDS mode you're alerting.
- **header**: the "who and where": protocol (`tcp`), source IP and port, direction (`->`), destination IP and port. This is where your `$HOME_NET` and `$EXTERNAL_NET` variables get used. `502` is the Modbus port.
- **options**: everything in the parentheses: the human-readable message (`msg`), the unique rule ID (`sid`), the revision number (`rev`), and the actual matching logic (like "Modbus function code equals 5").


> [!info] A *ruleset* is just thousands of these lines stacked up. Something important to understand is that *Suricata* operates on **two layers**.
> **Layer 1** is *community rules* you download and manage with a tool.  
**Layer 2** is *custom rules* you author by hand.

The reason that two layers exist is because some rules are generic and true for every *Suricata* user on earth, there is a giant community which builds these alerts for others to download and use. "Alert on known malware command-and-control traffic," "alert on this published exploit signature," "alert on traffic matching this CVE." Everyone could use these rules as they are very general. Now in my case, I want a rule that says. **"Alert when a Modbus write hits my PLC from anything that isn't my EWS at `192.168.95.5`."**

No community ruleset on earth can write this for me, because nobody else knows that my *EWS* is at that address or that I have decided only it should issue writes. That knowledge lives in my head and my topology. The solution is two layers, once for custom rule sets and the other for community rules.

The reason they're separate is because community rules get refreshed, I can re-download them periodically, or researchers can publish new signatures and the old copy get overwritten.

The **custom rules are mine.** These should never get overwritten by an update, and to make sure of this, they live in a separate file that the **updater** does not touch.


### Layer 1 Explanation

Running the command `suricata-update` pulls newly minted or updated rules from a **rule source**, such as *Suricata*'s default one, **Emerging Threats Open**, and downloads these rules into the file at this directory

`/var/lib/suricata/rules/suricata.rules`

It is just like how `apt` fetches and updates software, but `suricata-update` fetches and updates rule files.

> [!warning] When you want newer signatures, you run `suricata-update` again, it re-downloads, and it _replaces_ the consolidated file with a fresh version. Anything in there is disposable because it can always be re-fetched.


### Layer 2 Explanation

 I am the rule author in this layer, I create the rules that I want. They get stored in their own file, conventionally,

`/var/lib/suricata/rules/local.rules`

And this is how both layers actually get loaded. Since *Suricata* does not know about either file, there's a section which lists which rule file to load.

```
rule-files:
  - suricata.rules        # Layer 1: the consolidated community rules
  - local.rules           # Layer 2: your custom rules
```


OK, that was a lot of information and not much doing, so I am going to get back to the doing part.




## Installing Rules

```
sudo suricata-update
```

`suricata-update`: the rule-manager tool we just discussed. Run with no arguments, it does its default behavior: fetch the Emerging Threats Open ruleset, process it, and merge it into `/var/lib/suricata/rules/suricata.rules`.

![[Pasted image 20260629220845.png]]

This update automatically disabled rules for **Modbus** as you can see in the picture, we need to enable that so we do not run into any errors.


To enable **Modbus** detection, I went into the config file `/etc/suricata/suricata.yaml` and found the block which is for **Modbus**. From here I changed the "no" to "yes" for the part which says "enabled". I then exited and saved the config file.
	![[Pasted image 20260630155306.png]]


After doing this, I ran the command in order to validate that I get no errors and that all the rules are working as they should.

```
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

- `-T`: dry-run validation, load everything then exit.
- `-c /etc/suricata/suricata.yaml`: the config to test.
- `-v`: verbose so any error names its location.

![[Pasted image 20260630155457.png]]


It is then time to run `sudo suricata-update` again in order for its self-test to past as well, not just the explicit test I ran.
	![[Pasted image 20260630155731.png|663x422]]
Everything checks out, no errors. I now have **Modbus** parsing and detection on and the subnets are scoped to my simulation.








## Creating Custom Rules

Now is the rule creating time. I am going to create custom rules which will detect all the attacks that I did in *Stage 3*.

The good thing for me is I can create a single rule that will catch the *coil attack*, *ST injection attack*, and the *replay attack* all at once. This is because all these attacks have something in common. They are writing function codes from a source that shouldn't be writing.



### The Skeleton of Suricata Rules

This is the skeleton of a *Suricata* rule

`action protocol src_ip src_port direction dst_ip dst_port (options)`
 
- **action**: what to do. I want `alert`.
- **protocol**: for Modbus app-layer matching, you can use `modbus` (now that you enabled detection) or `tcp`. Worth thinking about which and why.
- **src_ip / src_port**: where it's coming from. My variables `$HOME_NET`, `$EXTERNAL_NET`, literal IPs, or `any`. Negation works with `!` (e.g., `!192.168.95.5`).
- **direction**: `->` (one way) or `<>` (both). For an attack hitting the **PLC**, you want one way.
- **dst_ip / dst_port**: where it's going. The **PLC**, port 502.
- **(options)**: the meat: `msg` (alert text), `sid` (unique ID, use 1000000+ for custom), `rev` (revision), and the match logic.




This [link](https://docs.suricata.io/en/suricata-7.0.3/rules/modbus-keyword.html) explains how **Modbus** can be used in *Suricata*. It has all the documentation.

There are two ways to match **Modbus** operations, one is by *function code* and the other is by *access type*.


*Function code* matches the raw **FC** number such as **FC5** (write single coil).
- `modbus: function 21` matches the Write File record function. So `function 5` = write single coil, `function 6` = write single register, etc. 
- You can also match whole classes: `modbus: function reserved` matches functions used by some companies for legacy products, and `modbus: function !reserved` matches every function but reserved. 


*Access Type* matches the semantic action which is often cleaner.
- `modbus: access read` matches read access and `modbus: access write` matches write access. 
- You can narrow to specific tables: `modbus: access write coils` matches write access to the Coils table, and you can target an address and value, e.g. `modbus: access write holding, address 500, value >200` matches writing a value greater than 200 at address 500 of the Holding Registers table.

If I were to use the *function code* type to match operations, I would have to specify which **FC** command specifically I would like to match, such as **FC5**, but If i instead decided to use *access type* to match operations, I could use this command `modbus: access write coils` which would match ANY write to the coil table. Obviously this one is more robust so I will be going with this one.


I am going to attempt to create a rule just based on the information I have shown here, I have not yet looked up or asked AI to make a rule for me. I want the rule to alert for any IP that does not belong to the **HMI** or **EWS** trying to write coils to them.

Here we go. The skeleton again is this

`action protocol src_ip src_port direction dst_ip dst_port (options)`

`alert  modbus  ![192.168.90.107, 192.168.95.5]  502  ->  192.168.95.2  502  (msg: "Unauthorized Write!"; sid:1000001; rev:1)`


Now that I created my rule I will see if it was correct. I found out that is has some issues. 
1. I put the source port as `502` instead of `any`
	The attacking machine can use any port to send their traffic to the **PLC** to be executed, not just 502, so ANY traffic from a machine that is not the **HMI** or **EWS** should alert.
	
2.  No actual **Modbus** match.
	The rule body does not contain anything that checks for a coil write. I need the `modbus:` keyword.
	
3. The space inside the list, and the missing final semicolon.
	`[192.168.90.107, 192.168.95.5]` -> `[192.168.90.107,192.168.95.5]`
	`rev:1` does not end with a semicolon when it should -> `rev:1;`




**Fixed Rule**
`alert  modbus  ![192.168.90.107,192.168.95.5]  any  ->  192.168.95.2  502  (modbus:access write coils; msg:"Unauthorized Coil Write!"; sid:1000001; rev:1;)`



## Placing the 1st Custom Rule


I then pasted my rule inside my *local.rules* file, where *Suricata* will be able to use it.

**Note:** The directory for the rule file is  `/var/lib/suricata/rules/`. I created a file named "*local.rules*"  and will edit that for my rules.
	![[Pasted image 20260702163812.png]]



Now I have to add the file inside the config file of *Suricata* so that it knows which file to look at 
	![[Pasted image 20260630165822.png]]


I then validated that the rule was working by running this command which tests *Suricata*.

```
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

![[Pasted image 20260630170338.png]]


Time to actually capture an attack. The first thing I do is fire up *Suricata* with the following command in my Ubuntu terminal

```
sudo suricata -c /etc/suricata/suricata.yaml -i eno1
```

- `-c /etc/suricata/suricata.yaml`: the config file, same as always.
- `-i eno1`: the new flag. `-i` means "interface," and `eno1` is the physical NIC my macvlan ICS and DMZ traffic rides on. *Suricata* taps the parent interface and sees the container Modbus traffic crossing it. Note there's **no `-T`** this time; without it, *Suricata* runs live instead of just validating.

![[Pasted image 20260630171639.png]]



After getting *Suricata* up and running, I then open the file which the alert will be saved to. The directory for this is `/var/log/suricata/fast.log`. In order for me to watch it, I open another terminal and go into that file with 

```
sudo tail -f /var/log/suricata/fast.log
```

- `tail`: a tool that prints the _end_ of a file. By default it shows the last 10 lines. The idea is you usually care about the most recent entries in a log, not the whole history.
- `-f`: "follow.". Instead of printing the tail once and exiting, it _stays open_ and live-streams new lines to my screen as they get appended to the file. So the moment Suricata writes an alert, it appears here instantly.
- `/var/log/suricata/fast.log`: the file to follow, Suricata's simple one-line-per-alert text log.

Now all that's left to do is do a *coil manipulation attack* and watch *Suricata* alert me. The attack is the same exact one from [Coil Manipulation Attack](#coil-manipulation-attack)

![[Pasted image 20260630171157.png]]

![[Pasted image 20260630171139.png]]

As you can see, *Suricata* noticed there was a coil write from `192.168.90.6` (Kali machine) on port `48930` to the **PLC** at `192.168.95.2`. My rule worked successfully!

The next step is to create more alert rules and even some **IPS** rules, which will prevent things from happening instead of just alerting us.






## Rule Roadmap

I came to the realization that I wanted a surgical rule for each attack that I attempted so that I could say I was able to stop this very specific attack. Now I also want to create general rules which would be useful as well.

My plan is simple, I am going to create surgical rules for each attack that I have done in this simulation, proving I can prevent them. Then I will create general rules which will detect all unauthorized traffic.

**Phase 1: Surgical detection rules (one per attack). Current phase.**

- *Rule* 1000001: unauthorized **coil write** → PLC. Done. Catches coil manipulation.
- *Rule* 1000002: unauthorized **register write** (FC6/FC16) → PLC. Catches the register-manipulation intent / direct register writes.
- *Rule* 1000003: unauthorized **program upload** → PLC. Catches ST injection (needs investigation, program uploads may not be Modbus, so this rule might key on the OpenPLC transfer, not Modbus, we'll dig into it).
- *Rule* 1000004: **replay** detection. Trickier, replay looks identical to legit traffic content-wise; the signal is duplicate/repeated identical transactions, likely needs a threshold or a content match on the specific replayed bytes. We'll reason it through.

**Phase 2: Cross-layer rules (attacks the write-rules structurally can't see).**

- *Rule* 1000005: **ARP spoofing** detection → catches the MITM/concealment attack. Layer 2, not Modbus payload. No source-based rule can catch this because the whole attack is impersonating a trusted source.
  > [!warning] Abandoned. Suricata 7.0.3 does not implement ARP alerting despite the config exposing a toggle for it. I confirmed this wasn't a config mistake on my end before giving up on it; if a future Suricata release adds real ARP rule support, this SID slot is reserved for it. This is why the ruleset below jumps straight from 1000004 to 1000006.
- *Rule* 1000006: **scan/recon** detection → catches enumeration (coil scanning, register mapping, port scans). Uses `threshold`/`detection_filter` (fire after N events in M seconds), a new mechanic.

**Phase 3: The broad catch-all.**

- Rule 1000010 (higher number, deliberately): any Modbus from non-HMI/EWS → PLC. The safety net. Catches anything the surgical rules miss, including novel techniques and ST injection if it does ride Modbus.

**Phase 4: IPS conversion (the drop decision).**

- Convert Suricata to inline/IPS mode. Decide _which_ rules become `drop` vs stay `alert`. This is where your "does the general rule snuff the surgical one" question finally becomes live, and you'll answer it by choosing to drop on surgical high-confidence rules while keeping broad detection as alert-only.

**Phase 5: Wazuh integration.**

- Feed `eve.json` into the Wazuh Docker stack, build dashboards, close the red-to-blue loop.




## Phase 1: Surgical detection rules


### Rule 1000002 - Unauthorized Register Writes

This rule, as the name states, will catch unauthorized register writes. Unauthorized meaning any register writes coming from a system that is not the **HMI** or **EWS**.

Something to point out is this rule is going to alert of any unauthorized register writes, not just faking the register value but actual writes. My [Register Manipulation Attack w/ MITM](#register-manipulation-attack-w-mitm) did not write to the registers and actually affect the process, instead it sat in the middle of the conversation, editing the packet as it was on its way from the **PLC** to the **HMI**, and changed the value, so the **HMI** saw a super high number but the actual system was fine.

This rule WILL alert for an actual register write though, not just a spoof.

Using the [Modbus Keyword Documentation](https://docs.suricata.io/en/suricata-7.0.3/rules/modbus-keyword.html) I will figure out how to write the rule. After reading the use cases, I saw that the keyword "access" is the keyword I need in order to address registers.

Using `modbus: access input` I will be addressing the input registers of the *ICS*.

Syntax:
`modbus: access read <discretes | coils | input | holding>`
`modbus: access read <discretes | coils | input | holding>, address <value>`

This is my rule before any outside help, lets see how well I do. First, the skeleton again

`action protocol src_ip src_port direction dst_ip dst_port (options)`

Now my rule

`alert modbus ![192.168.90.107,192.168.95.5] any -> 192.168.95.2 502 (modbus: access write | input; msg:"Unauthorized Register Write!"; sid:1000002; rev:1)`
*The issues with my rule*
1. The register table I picked was wrong. I chose input when it should be holding. 
	- **Input registers**: read-only. These are live sensor readings coming _in_ from field devices (FC4 reads them). You _cannot write_ to them, there's no Modbus function to write an input register, because they represent physical sensor data, not operator-settable values. This is the table your FC4 MITM attack was falsifying _in transit_.
	- **Holding registers**: read/write. These are the operator-configurable values: setpoints, valve commands, targets. FC6/FC16 write to _these_. This is the writable table.
	- The correct syntax would be `modbus:access write holding;`
	
2. Mistake 2 was my use of the pipe `|`. The pipe in the syntax was just a placeholder just like how **< >** are place holders.
	
3. I made the same mistake with spacing and not using the `;`.
	- Space after `modbus:` - I have `modbus: access` with a space. Convention is no space: `modbus:access`. (Tolerated, but match house style.)
	- Missing trailing semicolon - my options end with `rev:1)`. Every option needs its semicolon before the closing parent: `rev:1;)`. Same fix as rule 1000001.




**My revised rule**

`alert modbus ![192.168.90.107,192.168.95.5] any -> 192.168.95.2 502 (modbus:access write holding; msg:"Unauthorized Register Write!"; sid:1000002; rev:1;)`


Now that my rule is done, I can add it to my *local.rules* file and make sure that it works!


```
nano /var/lib/suricata/rules/local.rules
```
![[Pasted image 20260702172837.png]]


Then I can run *Suricata* as well as monitor the log file using `sudo tail -f /var/log/suricata/fast.log`
	![[Pasted image 20260702173044.png]]


Lastly, I validated the rule using

```
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
- `-T`: dry-run, load and validate then exit.
- `-c /etc/suricata/suricata.yaml`: the config.
- `-v`: verbose, names the file and line if a rule fails.

All good
	![[Pasted image 20260702173458.png]]


Run *Suricata* using 

```
sudo suricata -c /etc/suricata/suricata.yaml -i eno1
```

Now it is time to launch at attack and see if I can catch it.

I ran this command to send a single probe write to the **purge valve** position *register* to test whether my writes land, then read it back rapidly
```
python3 -c "
from pymodbus.client import ModbusTcpClient
import time
c = ModbusTcpClient('192.168.95.2', port=502)
c.connect()
print('[*] Writing 12345 to register 102 ONCE, then reading back 20 times fast.')
c.write_register(102, 12345)
for i in range(20):
    r = c.read_holding_registers(102, count=1)
    if not r.isError():
        val = r.registers[0]
        mine = '  <-- MY VALUE!' if val == 12345 else ''
        print(f'readback {i}: reg102={val}{mine}')
    time.sleep(0.05)
c.close()
"
```

- `c.write_register(102, 12345)` - **FC6 write single register**: write the distinctive value 12345 to holding register 102, exactly once. This is the single probe write.
- `for i in range(20)` + `time.sleep(0.05)` - immediately after writing, read the register back 20 times at 50ms spacing (1 second total). Fast readback so I catch the value if it's there even briefly before the loop overwrites it.
- `r.registers[0]` - the current value of register 102 on each readback.
- `mine = ' <-- MY VALUE!' if val == 12345 else ''` - this is the tell. On any readback where the value equals your 12345, it flags it with an arrow. So if my write ever shows up, I'll see "MY VALUE!" jump out in the output. If it never appears, I know it never landed.
- `print(...)` - prints each readback so I see the sequence: does 12345 appear at all, and if so, for how many reads before the loop reclaims it?

### The result

My *Suricata* rule picked up the attempted unauthorized writes, exactly as intended. Now as we know from my [Holding Register Write Attack](#holding-register-write-attack), this *register* write attempt did not actually close the **purge valve**. However, the traffic was still actually sent to the **PLC** and the **PLC** acted upon it, therefore it was picked up by my *Suricata* rule.
	![[Pasted image 20260706211601.png]]







### Rule 1000003 - Unauthorized Program Upload to PLC 

This next rule is going to be different from the **modbus** rules that I have done already. This rule is going to need to use syntax regarding HTTP, not **modbus**. *Suricata* does allow me to create rules which can dissect and alert me on HTTP traffic luckily.

Lets think about this logically, whenever an operator uploads a program to the **OpenPLC** website at port 8080 (**IP 192.168.95.2**), they do so on the **Engineering Workstation** (EWS). The **EWS** has an IP obviously, so our rule would basically say, "Any program upload to the **OpenPLC** website NOT from the **EWS**, alert me".

Before I get into how I would create a rule to match this specific event, I need to talk about some technical things. When I upload a program into the "Upload Program" section on the **OpenPLC** website interface, I looked at the URL whilst doing so, and I noticed this URL `http://192.168.95.2:8080/upload-program-action`. This URL popped up at the exact moment I hit the "upload" button. Meaning that this specific path pertains to the action of uploading a program.

This mean I can use this path in my rule, in order to match it to when someone actually does the action of uploading to the **OpenPLC** website, and it will alert me.

So **OpenPLC** runs a web interface on port 8080, and the upload is just an **HTTP POST** request to that **web server.**

When you interact with a web page, your browser sends **HTTP** requests to the server and the server sends **responses** **back**. There are different types of HTTP requests depending on what you are trying to do, and the type is called the **method**.

The two most common methods are **GET** and **POST**. A **GET** request is used to _retrieve_ something, when you type a URL into your browser and hit enter, your browser sends a **GET** request asking the server to send you that page. A **POST** request is used to _send_ something, when you fill out a form and click submit, or when you **upload** a file, your browser sends a **POST** request carrying your data in the body of the request. The server receives it, does something with it (saves a file, runs a process, updates a database), and responds.

In my case, when I click the upload button on the **OpenPLC** web interface, my browser sends an **HTTP POST** request to `http://192.168.95.2:8080/upload-program-action`. The compiled *PLC* program rides along in the body of that request, and **OpenPLC** receives it and loads it into the *runtime*. The *path* `/upload-program-action` is the *specific endpoint* on the server that **handles** program uploads, nothing else in the **OpenPLC** interface **POST**s to that path. That specificity is  what makes it a reliable rule target.

That reasoning, protocol HTTP not Modbus, method POST, path `/upload-program-action`, unauthorized source not the EWS, is the actual rule. I finished writing it, along with the remaining rules on my roadmap (1000004, 1000006, 1000010), in the next stage below, where I brought AI in to move faster on the remaining Suricata syntax and start on the alert-enrichment pipeline.

# Stage 5: AI-Assisted Alert Enrichment

In this stage, I will be implementing an AI in order to automatically read alerts that go off and then give context, a solution, and what exactly happened. In order to do this I will have AI also help with finishing the rules I'd already reasoned through above (1000003) and writing the rest of the roadmap (1000004, 1000006, 1000010) in order to save time.

Here is the complete, finalized set of rules now sitting inside `/local.rules`.
## Suricata Rules

**Rule 1000003: Unauthorized Program Upload**

```
alert tcp ![192.168.90.107,192.168.95.5] any -> 192.168.95.2 8080 (http.method; content:"POST"; http.uri; content:"/upload-program-action"; msg:"Unauthorized Program Upload to PLC"; sid:1000003; rev:1;)
```

Catches an HTTP POST to OpenPLC's upload endpoint from any machine that isn't the HMI or EWS. This is the ST injection attack's detection signature.

---

**Rule 1000004: Unauthorized Modbus Write (Replay)**

```
alert modbus ![192.168.90.107,192.168.95.5] any -> 192.168.95.2 502 (modbus:access write; msg:"Unauthorized Modbus Write"; sid:1000004; rev:1;)
```

Catches any Modbus write (coils or registers) from an unauthorized source. Broader than 1000001/1000002, and catches my replay attack since it was an FC5 write from Kali. True replay-specific detection (duplicate transaction IDs) would need Wazuh correlation on top. (Trimmed the `msg` down from an earlier "- Possible Replay" suffix since this rule fires on plenty of non-replay unauthorized writes too: the shorter message matches what's actually deployed in `local.rules`.)

---

**Rule 1000005: ARP Spoofing Detection (Abandoned)**

Not implemented. Suricata 7.0.3 does not support ARP alerting despite the config exposing a toggle for it. This SID is deliberately skipped rather than reused, so if a future Suricata release adds real ARP rule support, 1000005 is reserved for it. See the Rule Roadmap note above for the full explanation.

---

**Rule 1000006: Recon / Port Scan**

```
alert tcp ![192.168.90.107,192.168.95.5] any -> 192.168.95.2 502 (msg:"Modbus Reconnaissance - Multiple Connection Attempts"; flags:S; threshold:type both,track by_src,count 10,seconds 10; sid:1000006; rev:1;)
```

Catches repeated TCP SYN packets to port 502 from an unauthorized source. `flags:S` matches connection attempts only. Ten attempts in ten seconds from the same host is the scan/enumeration pattern, not normal traffic.

---

**Rule 1000010: Broad Catch-All**

```
alert modbus ![192.168.90.107,192.168.95.5] any -> 192.168.95.2 502 (msg:"Unauthorized Modbus Traffic to PLC"; sid:1000010; rev:1;)
```

No function code filter, no table restriction. Any Modbus at all from a non-authorized source to the PLC fires this. The safety net that catches everything the surgical rules miss, including novel techniques and anything that doesn't fit a specific pattern. Higher sid (1000010) is intentional, keeps it visually separate from the surgical rules in the file.

## Adding and Verifying Rules Work

Once I added all these rules to my *local.rules* file. I then ran the validation test
	![[Pasted image 20260710175312.png]]
	![[Pasted image 20260710175542.png]]

All good the rules work.

The complete ruleset is now:
- **1000001**: Unauthorized coil write
- **1000002**: Unauthorized register write
- **1000003**: Unauthorized program upload (HTTP POST)
- **1000004**: Unauthorized Modbus write / replay
- **1000006**: Recon / port scan (SYN flood to 502)
- **1000010**: Broad catch-all (any unauthorized Modbus)


The plan of what I want to build using AI is this. Attack happens → Suricata detects it → eve.json gets a new line → Python script reads it → sends it to AI → AI returns enriched analysis → Dashboard displays it

This means that the data flow would look something like this

1. Open eve.json and seek to the end (don't re-process old alerts)
2. Loop forever:
   a. Read any new lines that appeared
   b. For each new line:
      - Parse the JSON
      - Extract: timestamp, src_ip, dest_ip, sid, alert message, protocol
      - Build a prompt: "Here is a Suricata alert from my ICS lab: [alert data]. 
        Here is the context: [system prompt]. Analyze this alert."
      - Send to Claude API
      - Receive the enriched analysis
      - Display it (terminal / dashboard)
   c. Sleep briefly, repeat

I am going to be using a web dashboard for this part of the lab, it just looks nicer/cooler. The entire goal of this next step is to transform these alerts into an easy to digest format that someone can glance at and know what to do. 

I first need to create an API key using Claude so that I can feed all of the data that I get from *Suricata* into Claude for analyzing. **API** stands for Application Programming Interface, API is a defined way for two pieces of software to talk to each other.

When you use Claude in a chat, you are using a visual interface, you type, you see a response, it is designed for humans. An **API** is the same idea but designed for software to software communication, no visual, just structured data going back and forth.

When I generate an **API** key in console.anthropic.com, it gives me a long string starting with `sk-ant-`, this is my credential, its like a username and password combined into one token.

Every time my python script sends a request to Anthropics servers requesting to use Clause, they need to know 2 things. 
1. Who is asking? So they can be billed
2.  Whether or not this person is allowed to ask? So random strangers cannot use my credits.

The **API** key answer both questions.

> [!Warning ] This is why you **never** hardcode the key in the script file itself. If the file goes to GitHub, the key goes with it, and anyone who finds it can make API calls billed to your account. Storing it as an environment variable (`export ANTHROPIC_API_KEY=...`) keeps it out of the code and out of version control.


## Process Sequence 

**The exact sequence when a Suricata alert fires and my pipeline processes it:**

My Python script is watching `eve.json` with a `readline()` loop. The file is sitting at its end (I told it to seek to the end on startup so old alerts do not get replayed). The moment Suricata writes a new line, `readline()` returns it.

The script parses the JSON, checks if it is an *alert event type*, and checks if the *same rule fired recently* (the 30-second rate limiter). If it passes both checks, it **builds two things**: a system prompt (the big block of text describing my lab, my network, my rules, what everything means) and a user message (the specific alert data: timestamp, source IP, destination IP, rule sid, message).

It then calls `client.messages.create(...)`, which is the Anthropic SDK's way of sending a request to the API. Under the hood, the SDK constructs an HTTPS POST request to `https://api.anthropic.com/v1/messages`, attaches my API key in the header, and sends the system prompt plus user message as the request body. This goes over the internet to Anthropic's servers.

Anthropic's servers receive the request, verify my key, load Claude Sonnet 4.6, run the inference (Claude reads my prompt and generates a response), and send back a JSON response containing Claude's output text. My script receives that response, parses the JSON out of it, and stores the enriched alert object in memory.


**Flask** is a lightweight Python web server, this is what serves the dashboard.

The dashboard HTML file, open in my browser, runs a JavaScript loop that calls `http://localhost:5000/alerts` every 3 seconds. It gets back the list of **enriched alerts**, renders them in the timeline, and displays the AI analysis when you click one. My browser never talks to Anthropic directly. It only talks to my local **Flask** server, which already has the enriched data ready.


**The Flow**
Attack on Kali
    ↓
Suricata detects it on *eno1*
    ↓
Suricata writes a JSON line to */var/log/suricata/eve.json*
    ↓
*ics_alert_pipeline.py* reads the new line
    ↓
Script sends system prompt + alert data to Anthropic API (HTTPS, your key attached)
    ↓
Anthropic servers run *Claude Sonnet 4.6* on the input
    ↓
Claude returns structured *JSON* analysis
    ↓
Script stores the enriched alert in memory
    ↓
Dashboard polls http://localhost:5000/alerts every 3 seconds
    ↓
*Flask* returns the enriched alert list
    ↓
Dashboard renders the alert in the timeline and shows the *AI analysis*


I would like to note that this is more than just using AI to capture alerts and give a solution or response to these alerts. I have gone through the trouble of documenting the **baseline** of this simulation, this baseline context makes the AI much stronger in locating and figuring out what is happening very specifically.

The AI is much more intelligent in its responses because I have fed it a detailed system prompt describing how the **ICS** works, the network topology, the authorized hosts, and what each of my rules detects. That baseline context is what makes its analysis specific to my environment instead of generic


## Starting the AI response

Lets get the entire thing started now that I explained how everything functions. Run *Suricata* using

```
sudo suricata -c /etc/suricata/suricata.yaml -i eno1
```

I have the tail of the log file running using 
```
sudo tail -F /var/log/suricata/fast.log
```
![[Pasted image 20260711130934.png]]




I then used my API key from Claude and ran the python script in order to get the responses from Claude working. `export ANTHROPIC_API_KEY="YOUR_API_KEY"`


To run the script
```
python3 ics_alert_pipeline.py
```
![[Pasted image 20260711131803.png]]


Time to run the attack and see what happens. This is the [Coil Manipulation Attack](#coil-manipulation-attack) from [Stage 3: Attack Execution](#stage-3-attack-execution)
	![[Pasted image 20260711130958.png]]

I turned the *Chemical A* process on and then off again. Lets see what I get in my logs and dashboard.
	![[Pasted image 20260711130918.png]]
	![[Pasted image 20260711130414.png]]
	![[Pasted image 20260711130828.png]]



The way that I am getting Claude to accurately diagnose and structure its response comes from the python script, which has a `SYSTEM_PROMPT` variable, telling Claude how it should respond. Here is the prompt Claude reads when parsing these alerts.

My old prompt has flaws. Sometimes Claude does not fully comply with the directions and puts a character or word that should not be in its response. When this happens, the alert tells the user that "AI analysis failed to parse". Which is annoying because I don't get an explanation of the alert or a solution. Just that it happened. To fix this, I created a more strict prompt for Claude and will be using regex to parse Claude's responses as well.
	![[Pasted image 20260713194526.png]]

**New Prompt**

``` python
# ─── SYSTEM PROMPT ───────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an ICS/OT cybersecurity analyst for a GRFICSv3 chemical reactor simulation lab.
Your job is to analyze Suricata IDS alerts and produce clear, actionable incident analysis tailored to this specific environment.
NETWORK TOPOLOGY:
- ICS Network (192.168.95.0/24): the control network
- 192.168.95.2 : Chemical Reactor PLC (OpenPLC runtime, Modbus TCP port 502, web interface port 8080)
- 192.168.95.5 : Engineering Workstation (EWS): the ONLY authorized source for program uploads and register writes
- 192.168.95.200: Router (ICS-side interface)
- DMZ Network (192.168.90.0/24): the operator network
- 192.168.90.107: HMI: authorized to read process data and issue coil writes during operator actions
- 192.168.90.6 : Kali Linux attacker machine: NEVER authorized to communicate with the PLC
- 192.168.90.200: Router (DMZ-side interface)
- 192.168.90.250: Caldera (adversary simulation framework)
- Admin Network (172.19.0.0/16): management plane, not for process traffic
AUTHORIZED WRITERS TO PLC:
- Coil writes: HMI (192.168.90.107) and EWS (192.168.95.5) only
- Register writes: EWS (192.168.95.5) only
- Program uploads: EWS (192.168.95.5) only
- Any other source issuing writes is unauthorized and should be treated as an active attack
ICS PROCESS OVERVIEW:
The simulation models a chemical reactor with the following key devices:
- Chemical A feed valve: binary on/off, controlled by coil 40 (coil write attack target)
- Purge valve: modulating (holding register 102), controls pressure venting, high-gain (k=-20) causes fast oscillation
- Product valve: modulating (holding register 103), controls product draw-off
- Reactor pressure: monitored via input register 108 (raw value ~55000 at normal ~2700 kPa)
- Process danger: sustained high pressure can cause reactor overpressure failure
SURICATA RULE CATALOG:
- sid 1000001: Unauthorized coil write (FC5/FC15): direct process manipulation, can disable Chemical A feed
- sid 1000002: Unauthorized register write (FC6/FC16): setpoint/valve manipulation
- sid 1000003: Unauthorized program upload to OpenPLC: highest impact, replaces control logic entirely
- sid 1000004: Unauthorized Modbus write (any type): broad write detection, may be replay attack
- sid 1000006: Modbus reconnaissance: port scanning/enumeration before an attack
- sid 1000010: Any unauthorized Modbus traffic: catch-all, novel or unclassified technique
KNOWN ATTACK SEQUENCE FROM THIS LAB:
Stage 2: Register mapping (FC4 read enumeration)
Stage 3: Coil manipulation (FC5 write to coil 40 from Kali)
Stage 4: MITM concealment (ARP spoof + Modbus response falsification)
Stage 4: Structured Text injection (HTTP POST to /upload-program-action from Kali)
Stage 4: Replay attack (re-sent captured FC5 bytes over fresh TCP connection)
CRITICAL FORMATTING RULES - YOU MUST FOLLOW THESE EXACTLY:
1. Respond ONLY with a valid JSON object. Nothing before it, nothing after it.
2. No markdown, no code fences, no backticks, no explanation outside the JSON.
3. Use ONLY straight double quotes (") never curly/smart quotes.
4. Do NOT use em dashes (--) inside any string value. Use a comma or period instead.
5. Do NOT use newline characters inside string values. Keep all text on one line per field.
6. Every string value must be properly escaped. If you need a quote inside a string, use \".
7. The JSON must be parseable by Python's json.loads() with no modifications.
Use this exact schema:
{
"severity": "high",
"severity_reason": "one sentence explaining why this severity",
"what_happened": "2-3 sentences describing what happened in this ICS environment",
"likely_attack": "1-2 sentences on the probable attack technique and intent",
"actions": ["action 1", "action 2", "action 3"],
"tags": ["tag1", "tag2", "tag3"]
}"""
```




## Fixing the Parse Errors for Good: Forced Tool Use

Even after tightening the prompt with the "CRITICAL FORMATTING RULES" above, I was still getting the occasional "AI analysis failed to parse" fallback. I chased this for a while with string surgery in the Python script, replacing smart quotes with straight ones, stripping markdown code fences if Claude wrapped the JSON in them, cutting out everything before the first `{` and after the last `}`, replacing em dashes with hyphens. It helped, but it never fully went away, and I finally understood why: **no amount of prompt wording can *guarantee* format.** Claude is generating plain text token by token. A system prompt full of "CRITICAL RULES" is still just me *asking nicely*. There is nothing structural stopping it from occasionally adding a stray word, an extra quote style, or a bit of preamble.

> [!info] The real fix, in one line
> Stop asking Claude to *write* JSON. Force it to *call a function* whose inputs are defined by a schema.

This is called **tool use** (also called **function calling**) in the Anthropic API. Instead of describing the JSON shape in prose and hoping Claude copies it exactly, I define the shape as an actual **JSON Schema** object and hand it to the API as a `tool`. Then I set `tool_choice` to force Claude to call that specific tool every time, instead of letting it choose whether to respond in plain text or not.

**Analogy:** the old approach was like asking someone to "please fill out this form neatly, using only blue ink, one word per line." The new approach is like handing them an actual form with labeled boxes that are the only place they're physically able to write. One relies on their handwriting discipline. The other constrains the shape of what can come back at all.

### What changed in `ics_alert_pipeline.py`

I added a schema, `ALERT_ANALYSIS_TOOL`, describing exactly the six fields I need back (`severity` restricted to an enum of `low`/`medium`/`high`/`critical`, four free-text string fields, and `actions`/`tags` as arrays of strings). This gets passed into the API call:

```python
response = client.messages.create(
    model=MODEL,
    max_tokens=800,
    system=SYSTEM_PROMPT,
    messages=[{"role": "user", "content": user_message}],
    tools=[ALERT_ANALYSIS_TOOL],
    tool_choice={"type": "tool", "name": "submit_alert_analysis"},
)
```

`tool_choice` is the part doing the real work here. Without it, Claude *could* still just answer in plain text and ignore the tool. With it, Claude is forced to respond by calling `submit_alert_analysis`, and the SDK hands back the arguments as an already-parsed dict at `response.content[...].input`. No `json.loads()`, no regex, no manual string cleanup. The "CRITICAL FORMATTING RULES" block and the literal JSON example got removed from `SYSTEM_PROMPT` entirely, since the schema is now the contract instead of a paragraph of instructions.

I kept a small `_valid_analysis()` check as a second line of defense; the tool schema makes malformed output extremely unlikely, but it costs nothing to double check that all six fields are present, `severity` is one of the four allowed values, and `actions`/`tags` are actually lists of strings before trusting the result.

> [!warning] Two related bugs fixed in the same pass
> - If the Anthropic API call itself failed (network blip, rate limit, etc.), the old code did `return None` and the alert vanished from the dashboard with zero trace it ever happened. Now that path builds the same well-formed fallback object used for schema failures (tagged `api-error`), so the alert still shows up instead of silently disappearing.
> - `dashboard.html` read `analysis.severity`, `.actions`, `.tags` straight off the response with no null checks. Since the backend fallback is always well-formed this never actually broke, but it was one contract change away from a JavaScript error blanking the whole alert panel. Added optional chaining and defaults there as cheap insurance.

The old fallback's tag also got renamed from `parse-error` to `schema-error`, since a failure here is no longer a JSON-decoding problem specifically, it's Claude's tool call not matching the schema (or the tool not being called at all).

This ties directly back into the [AI Eval Harnesses](#ai-eval-harnesses-and-frozen-inputs) idea from earlier in this vault: once that harness exists, "does the enrichment still come back in the right shape" stops being a vibe I notice from the terminal and becomes a number I can track across prompt and model changes.


## Verifying the Tool-Use Fix and a Second Bug It Uncovered

After making the forced tool-use change above, I wanted to actually confirm it worked instead of just trusting the theory. Suricata was running live and the dashboard was open in the browser, so with Claude Code I generated real attack traffic and watched it flow through the pipeline end to end.

The test: `docker exec` into the Kali container and use its pre-installed `pymodbus` to send an unauthorized FC5 coil write to coil 40 on the PLC, read the current value first, write the opposite value, then write the original value back so the process ends in the same state it started in. One write like that fires three rules at once off the same packet, since `192.168.90.6` is neither the HMI nor the EWS: **1000001** (coil write), **1000004** (any unauthorized write), and **1000010** (catch-all).

Both alerts landed in the dashboard, but both still had `"tags": ["schema-error", ...]` and the generic fallback text. So tool use alone did not fix it, something else was wrong.

### Root Cause: `max_tokens`, Not Format

Looking at the raw tool call Claude actually sent (printed to the pipeline's terminal on schema failure), the dict was missing `actions` and `tags` entirely, not empty arrays, the keys were not there at all. Everything before them in the schema, `severity`, `severity_reason`, `what_happened`, `likely_attack`, was present and fairly verbose.

That pattern, early fields present and wordy, the last fields in the schema missing outright, is the signature of hitting the token ceiling mid-generation. `max_tokens` was set to `800`, and `severity_reason` plus `what_happened` alone were running 150-200 words each for a "high" severity alert like the Kali coil write. Claude was running out of budget before it finished writing the JSON arguments for the tool call, so the SDK handed back a partial, and therefore schema-invalid, `input` dict.

> [!info] `tool_choice` guarantees Claude *calls* the tool. It does not guarantee the call finishes before the token budget runs out.

### The Fix

Two changes to `ics_alert_pipeline.py`:

```python
# before
max_tokens=800,

# after
max_tokens=1500,
```

And a line added to `SYSTEM_PROMPT`, right above the tool-call instruction, so this does not just quietly recur the next time an alert produces a slightly longer explanation:

```
Keep severity_reason and what_happened to 2-3 sentences each, be precise, not exhaustive.
The tool call must always include all required fields, including actions and tags.
```

### Confirming the Fix

Restarted the pipeline and ran the exact same coil-write test again. This time the alert came back fully formed, `actions` (7 items) and `tags` (10 items) both present, no `schema-error` tag anywhere.

![[Pasted image 20260727233021.png]]
![[Pasted image 20260727233034.png]]
![[Pasted image 20260727233001.png]]

> [!warning] Two-bug lesson
> "It calls the tool now" and "it always finishes calling the tool" are different guarantees. Forced tool use fixes the *shape* problem, Claude can no longer ramble outside the schema, but it does not fix a *budget* problem, Claude can still get cut off mid-argument if it's too wordy for the token ceiling. Both needed fixing to actually kill the schema-error fallback for good.

This is another concrete case for the [eval harness](#ai-eval-harnesses-and-frozen-inputs) idea. A frozen high-severity input case in that suite would have caught this the first time, instead of needing a live re-test to notice.

## Dashboard UX Fixes and a MITRE ATT&CK Layer

A follow-up session, this time starting from a cold lab: brought up all four layers (simulation containers, Suricata on `eno1`, the pipeline, the dashboard), and while checking each layer's health before testing anything, found something worth a note.

### A Stray Suricata Was Already Running

`ps aux` showed three separate `suricata` processes at once: my own `-i eno1` instance (the correct one, physical NIC, sees the macvlan ICS/DMZ traffic), a leftover `-i eth2` process from an earlier session, and a `systemd` service (`systemctl is-active suricata` returned `active`, `Restart=on-failure`). All three write to the same `/var/log/suricata/eve.json`, so the pipeline could plausibly be tailing a mix of alerts from an interface that cannot even see the macvlan traffic properly.

Killed the stray process by PID, and it came right back within a few seconds, courtesy of the systemd unit's `Restart=on-failure` policy. A real fix needs `sudo systemctl stop suricata && sudo systemctl disable suricata`, not just `kill`. Left it running for now at my own call, revisit before anything resembling a demo recording.

> [!warning] Known imperfect state
> As of this session, the systemd-managed Suricata instance is still alive alongside the manual `eno1` one. Alerts observed afterward were all correct and complete, so it does not appear to be corrupting `eve.json` in practice, but it has not been cleanly resolved.

### Re-verifying the Pipeline End to End

Before touching the dashboard, reran the same coil-write test used to verify the `max_tokens` fix above: `docker exec` into Kali, flip coil 40 off then back on. Confirmed the pipeline is still healthy, all three co-fired rules (**1000001**, **1000004**, **1000010**) enriched cleanly with no `schema-error` fallback.

### Bug: Critical Alerts Rendering Blue

Watching that live test is what surfaced the next bug. Both `critical`-severity alerts in the dashboard were highlighted **blue**, the color reserved for the lowest, least urgent tier.

```javascript
// before — only two severities handled, everything else silently becomes "low"
function sev(s) { return s==='high'?'high':s==='medium'?'medium':'low'; }
```

The tool schema's `severity` enum has always included `"critical"` (`ALERT_ANALYSIS_TOOL`, `ics_alert_pipeline.py`), but the dashboard's `sev()` helper only ever checked for `'high'` and `'medium'`, so `critical` fell through to the `low` branch and inherited its blue styling. Classic case of the frontend and the schema drifting apart silently, since nothing throws an error when a string just doesn't match a case, it just quietly does the wrong thing.

```javascript
// after — explicit 4-tier ramp, unrecognized values still default to low but no longer swallow real values
function sev(s) {
  const v = (s || '').toLowerCase();
  return ['critical','high','medium','low'].includes(v) ? v : 'low';
}
```

Rebuilt the severity color ramp end to end: `critical` = red with a subtle pulse on the sidebar, `high` = orange, `medium` = yellow, `low` = blue. Split the header's single "High" counter into separate "Critical" and "High" chips so both are visible at a glance instead of critical incidents hiding inside an undifferentiated count.

### Feature: Grouping Same-Packet Alerts

The coil-write test is a good illustration of a UX problem: one Modbus packet from an unauthorized source routinely trips multiple Suricata rules at once (1000001 coil-specific, 1000004 broad-write, 1000010 catch-all), and the dashboard listed all three as separate top-level timeline entries. Functionally correct, but noisier than real SOC tooling, where correlated alerts get grouped.

Implemented client-side grouping in `dashboard.html`: alerts sharing source IP, destination IP, and destination port within a 500ms window now collapse into a single expandable card, headlined by whichever member has the highest severity, with a `×N` count badge and a sid chip per member. Clicking the card expands it into individual rows, each independently selectable to view its own analysis.

The 500ms window was not a guess. Pulling the raw alert timestamps from a live burst showed all three co-fired rules landing at the **exact same microsecond**:

```
2026-07-31T13:22:34.792020-0700  sid 1000001  Unauthorized Coil Write!
2026-07-31T13:22:34.792020-0700  sid 1000004  Unauthorized Modbus Write
2026-07-31T13:22:34.792020-0700  sid 1000010  Unauthorized Modbus Traffic to PLC
```

That confirmed a tight window safely catches genuine same-packet, multi-rule fires without accidentally merging separate, sequential attack steps (like a register-hammer's individual writes) into one card.

### Feature: MITRE ATT&CK for ICS Tagging

The bigger addition: every alert now carries a MITRE ATT&CK for ICS technique.

Extended `ALERT_ANALYSIS_TOOL`'s schema with a required `mitre_technique` field (format: `"T0XXX - Technique Name"`). 

```python
MITRE_HINTS = {
    1000001: "T0855 (Unauthorized Command Message) — a direct coil write forcing a physical process change.",
    1000002: "T0855 (Unauthorized Command Message) — a direct register write altering a setpoint or valve position.",
    1000003: "T0821 (Modify Controller Tasking) — uploading new control logic to the PLC, replacing its program.",
    1000004: "T0855 (Unauthorized Command Message) — broad write detection; if the payload is a program upload this may instead be T0821.",
    1000006: "T0846 (Remote System Discovery) — scanning or enumerating the Modbus service on port 502.",
    1000010: "No single best fit — catch-all. Prefer T0855 unless context suggests reconnaissance (T0846) or something else.",
}
```

Each alert's user message now includes a `MITRE hint:` line pulled from this table, and the system prompt was told explicitly to treat the hint as ground truth rather than inventing an ID from memory. This is the same philosophy as the earlier hardcoded rule catalog, constrain the model to known-correct facts about this specific environment instead of trusting free generation for anything checkable.

On the dashboard side, added a clickable badge in the analysis panel, parsed out of the `mitre_technique` string, linking straight to the technique's page on `attack.mitre.org`.

Verified live: the same coil-write burst returned `T0855 - Unauthorized Command Message` consistently across all three co-fired SIDs, matching the hint table exactly.

![[Pasted image 20260731133134.png]]
![[Pasted image 20260731133915.png]]
![[Pasted image 20260731133149.png]]



> [!info] Connects to the eval harness plan
> The [eval harness](#ai-eval-harnesses-and-frozen-inputs) table below already lists `mitre_technique_present` as an expected structured field, written into this doc before the field existed in the pipeline. It exists now, so the frozen input set should include at least one case that pins down the exact expected technique ID per SID.

### Closing the Severity Floor Gap

`CLAUDE.md` for this project lists "hardcoded per-SID severity overrides so the model cannot downgrade a critical rule" under existing hardening for `ics_alert_pipeline.py`. Going back through the file to find that logic, it was not there, `severity` coming back from Claude's tool call was only checked against the four allowed strings (`_VALID_SEVERITIES`), never against a per-rule floor. Whether it was removed at some point or just never built, either way it is a real gap: as written, nothing stopped Claude from rating a coil-write attack `"low"` if it reasoned its way there on a given alert.

Built it for real rather than leaving it as a documented gap.

```python
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

MIN_SEVERITY = {
    1000001: "high",      # coil write — direct actuator manipulation
    1000002: "high",      # register write — direct setpoint manipulation
    1000003: "critical",  # program upload — full control logic replacement
    1000004: "high",      # broad write detection — direct process manipulation risk
    1000006: "medium",    # recon/scanning — precursor, not direct manipulation
    1000010: "medium",    # catch-all — unclassified traffic, uncertain impact
}


def _apply_severity_floor(sid: int, analysis: dict) -> dict:
    floor = MIN_SEVERITY.get(sid)
    if floor and _SEVERITY_RANK[analysis["severity"]] < _SEVERITY_RANK[floor]:
        original = analysis["severity"]
        analysis["severity"] = floor
        analysis["severity_reason"] = (
            f"[Severity floor applied: sid {sid} is never rated below '{floor}'; "
            f"the model assigned '{original}'.] " + analysis["severity_reason"]
        )
        analysis["tags"] = list(analysis.get("tags", [])) + ["severity-floor-applied"]
    return analysis
```

Design choices worth noting:
- **One-directional.** The floor only clamps up, never down. Claude is still free to call something `critical` when its floor is only `medium`, the floor exists to stop under-rating, not to flatten every alert to a fixed severity.
- **Transparent, not silent.** When the floor overrides the model, it prepends a bracketed note to `severity_reason` explaining exactly what happened and what the model originally said, and adds a `severity-floor-applied` tag. A reviewer (or a future me) should never have to guess whether a severity came from the model or from a hardcoded rule.
- **Applies after every code path**, not just the success path. It runs on the schema-error and API-error fallback analyses too, so a critical rule never gets under-rated just because the AI call itself failed.
- **Per-SID floors, not one global minimum.** Recon (1000006) and the catch-all (1000010) got a lower floor (`medium`) than direct writes, since treating a port scan the same as a confirmed coil write would just train me to ignore the severity field.

Verified the clamp logic in isolation before trusting it against a live alert: fed `_apply_severity_floor` a fake `low`-severity analysis for sid 1000001 (floor `high`) and confirmed it clamped up with the correct reason text and tag; fed it an already-`critical` analysis for the same sid and confirmed it left it untouched; fed it a sid with no floor entry and confirmed it passed through unchanged. All three matched expectations.

Restarted the pipeline and reran the coil-write test live. None of the alerts actually needed the floor, Claude was already rating them `high`/`critical` on its own, which is the expected common case. The floor is a backstop for the rare miss, not something meant to fire on every alert.

# Current Status

This is a living document, not a finished writeup. As of this update, the following is built and working end to end: Stages 1-3 (recon, Modbus mapping, and the full attack catalog, MITM concealment, coil manipulation, ST injection, replay, register hammering, holding register sweep), Stage 4's detection layer (six custom Suricata rules, SIDs 1000001-1000010, alert-only/IDS mode), and Stage 5's AI enrichment pipeline (Flask + forced tool-use Claude integration, dashboard front end).

What's still open, and what I'm working on next:

- **Eval harness for `ics_alert_pipeline.py`**: a frozen set of captured `eve.json` alerts covering the attack catalog plus a benign baseline, so prompt/model/parsing changes get regression-tested instead of caught by hand (see the note at the top of this doc).
- **Phase 4: IPS conversion**: moving Suricata from alert-only to inline drop mode on the high-confidence surgical rules, while keeping the broad catch-all as alert-only.
- **Phase 5: Wazuh integration**: feeding `eve.json` into the Wazuh stack for aggregation and dashboards, closing the red-to-blue loop.
- **Product valve (register 103) attack**: the holding-register hammer attack didn't produce a physical pressure change because it hit a mirrored register, not the actuator (see Stage 3). Attacking the product valve instead, which actually draws mass out of the reactor, is the more promising path to a real physical effect, and is still an open experiment.

I'll keep updating this doc as each of these closes out rather than treating it as a fixed final report.


## To add

### AI Eval Harnesses and Frozen Inputs

> [!info] Overview
> An eval harness is an automated test suite for AI-integrated systems. It uses "frozen" (unchanging) input data to detect when prompt edits, model version bumps, or parsing changes break behavior. This is the shipping-engineer version of Deployment Diligence and is required for any Modality 3 (Agency) AI artifact I ship.

---

## Key Concepts

### What is an Eval Harness
A formal, automated version of the "does this still work" gut check. It is a script that runs test cases through my actual pipeline, compares outputs against expected results, and prints pass/fail per case with a final exit code.

**Analogy:** Like a CompTIA practice exam score. Turns a vibes check ("I think I know this material") into a comparable number I can track across attempts.

### What are Frozen Inputs
Pre-captured test data saved to disk that never changes byte for byte. Not "a similar alert," but the exact same alert JSON with the same timestamp, source IP, and payload every single run.

**Analogy:** Like a Suricata pcap replay. Same packets every time. If Suricata's output changes between replays, the cause has to be my rule, not the traffic. Same idea here: if the input never changes, any difference in Claude's output has to come from my prompt or the model.

### Why "Frozen" Matters
If the input varies, I cannot isolate causes. Frozen inputs give scientific control: only one variable changes at a time (my prompt, the model version, temperature, etc.).

---

## How It Works

1. Capture real inputs during normal operation, save each as a separate file.
2. Create matching "expected" output files with the correct classification or response for each input.
3. Write a script that:
   4. Loads each input file.
   5. Runs it through the actual pipeline (production code path, not a copy).
   6. Parses Claude's JSON response.
   7. Compares fields against the expected file.
   8. Prints `PASS` or `FAIL <field> expected X got Y` per case.
   9. Exits `0` if all pass, `1` if any fail.
10. Run whenever anything that could affect behavior changes.
11. Run before every commit that touches the pipeline.

---

## Directory Structure

```
grficsv3-ics-detection-lab/
├── ics_alert_pipeline.py
├── evals/
│   ├── inputs/                          # frozen inputs, one per file
│   │   ├── 001_arp_spoof.json
│   │   ├── 002_modbus_write_coil.json
│   │   ├── 003_st_program_upload.json
│   │   ├── 004_holding_register_sweep.json
│   │   ├── 005_register_hammer_102.json
│   │   └── 006_benign_hmi_poll.json     # negative case
│   ├── expected/                        # expected outputs, matched by name
│   │   ├── 001_arp_spoof.expected.json
│   │   └── ...
│   └── run_evals.py                     # the harness script
```

---

## Comparison Strategies

### Structured Fields (Exact Match)
Compare field by field: `severity`, `category`, boolean flags, MITRE technique IDs. These should be identical across runs at `temperature=0.1`.

### Free-Text Fields (Sanity Checks Only)
Explanation strings will vary in phrasing even at low temperature. Do not exact-match them. Instead check:
- Length bounds (example: 40 to 800 characters)
- Required keywords present (example: "Modbus" must appear if the alert is Modbus-related)
- No forbidden strings (example: no raw stack traces, no "I cannot" refusals)

### LLM-as-Judge (Advanced)
Use a second Claude call as evaluator: "Does this explanation correctly identify an ARP spoofing attempt against the HMI, yes or no?" This is how Anthropic and OpenAI evaluate their own models internally. Overkill for lab use, worth knowing exists.

---

## Suggested Frozen Input Set for ICS Pipeline

> [!info] Superseded by what actually got built
> This was the pre-implementation plan. See [Eval Harness: Built and Passing](#eval-harness-built-and-passing) below for the real set, which diverged in two ways: no ARP case (sid 1000005 was abandoned, no working ARP rule exists to generate a real alert from), and no benign baseline (that tests whether the Suricata rule layer stays silent on authorized traffic, a different layer than this harness, which exercises Claude's enrichment of alerts that already fired).

| # | Case | Attack Type | Expected Severity |
|---|------|-------------|-------------------|
| 001 | ARP spoof Kali to HMI | Reconnaissance / MITM | high |
| 002 | Modbus write coil (register 105) | Command injection | high |
| 003 | Structured Text program upload | Program logic tampering | critical |
| 004 | Modbus holding register sweep read | Reconnaissance | medium |
| 005 | Register hammer on register 102 | Denial-of-view / mirror abuse | high |
| 006 | Benign HMI polling baseline | None (negative case) | informational |

### Expected Output Fields per Case

> [!info] Also superseded, see the real match strategy below
> `category` and `requires_human_review` turned out not to be fields worth asking Claude for. They're properties of the SID (which rule fired), not judgment calls the model needs to make, so the real harness derives them in `run_evals.py` from a static lookup instead of adding them to the tool schema. `severity` is mostly checked as "at least" rather than exact, tied to the same `MIN_SEVERITY` floor added to the pipeline itself, since exact-matching a model-generated field is brittle against legitimate wording variance.

| Field | Type | Match Strategy |
|-------|------|----------------|
| `severity` | fixed enum | exact match |
| `category` | fixed enum | exact match |
| `mitre_technique_present` | string (e.g. T0830) | exact match |
| `requires_human_review` | boolean | exact match |
| `explanation` | free text | length bounds + keyword check |

---

## When to Run the Harness

> [!tip] Trigger Points
> Run `python evals/run_evals.py` after any of these changes:
> - System prompt edited
> - Model version bumped (e.g. `claude-sonnet-4-6` to next release)
> - `temperature` or `max_tokens` changed
> - JSON extraction or truncation-repair logic touched
> - Before every git commit that modifies `ics_alert_pipeline.py`

---

## Key Terms

| Term | Definition | Real-World Analogy |
|------|------------|--------------------|
| Eval Harness | Automated test suite for AI outputs | CompTIA practice exam |
| Frozen Input | Pre-saved test data that never changes | Suricata pcap replay file |
| Regression Test | Test that catches when new changes break old behavior | Retesting a fixed bug after every update |
| LLM-as-Judge | Using another AI call to grade output correctness | Second grader checking first grader's work |
| Semantic Match | Comparing meaning rather than exact wording | Two correct explanations of the same concept |
| Structured Field | Output value with a fixed set of possible values | Multiple-choice answer |
| Prompt Drift | Behavior change caused by prompt edits | Recipe tasting different after tweaking ingredients |
| Model Drift | Behavior change caused by model updates | Same recipe tasting different from a new oven |
| Negative Case | A test where the correct answer is "no alert" or "benign" | A tripwire that should NOT fire on normal traffic |

---

## Next Steps

- [x] Create `evals/` folder structure inside `grficsv3-ics-detection-lab` repo
- [x] Capture 5 to 10 real alert JSONs from `eve.json` during controlled attack runs (5 real, 1 synthetic, see below)
- [x] Handwrite expected output files for each frozen input
- [x] Ask Claude to help build `run_evals.py` (reference this note)
- [ ] Add "How to Run Evals" section to project README
- [ ] Convert "AI JSON parser reliability failures" in Known Limitations from a static caveat to a monitored, measurable item
- [ ] Replace the synthetic sid 1000003 (ST program upload) input with a real capture once comfortable authorizing that specific attack against the live PLC
- [ ] Consider a separate Suricata-rule-level regression suite for negative cases (authorized traffic that should stay silent), distinct from this Claude-enrichment harness

---

## Eval Harness: Built and Passing

The plan above was written before any of it existed. This is what actually got built, in one session, starting from nailing down the expected-output schema before writing a line of harness code.

### Correcting the Schema Before Building Anything

The original plan assumed `category` and `requires_human_review` would be fields Claude outputs, exact-matched like `severity`. Looking at the real tool schema in `ics_alert_pipeline.py`, neither exists, and thinking it through, neither should: both are properties of *which rule fired*, not something the model needs to judge per alert. `category` is just a `sid → category` lookup. `requires_human_review` is just `severity in {"high", "critical"}`. Asking Claude to independently reconstruct facts that are already deterministic from the SID adds a place for the model to be wrong about something that isn't actually ambiguous.

So both got moved into the harness itself as derived values, computed from the SID rather than asked of the model:

```python
CATEGORY_MAP = {
    1000001: "command-injection",
    1000002: "command-injection",
    1000003: "program-tampering",
    1000004: "command-injection",
    1000006: "reconnaissance",
    1000010: "unclassified",
}

HUMAN_REVIEW_SEVERITIES = {"high", "critical"}
```


Example of the **SID rule 100000**
![[Pasted image 20260731141828.png]]


The `severity` match strategy also changed from the original plan's "exact match" to mostly "at least this severity," reusing the same `MIN_SEVERITY` floor and `_SEVERITY_RANK` ordering already added to the pipeline for the [severity floor fix](#closing-the-severity-floor-gap). Exact-matching a model-generated field is brittle: Claude can legitimately call something `critical` one run and `high` the next depending on subtle phrasing, and an eval that fails on that kind of harmless variance trains me to ignore it. What actually matters is that severity never drops *below* the floor. The one exception is sid 1000003 (program upload), where the floor is `critical`, the maximum possible value, so floor and ceiling are the same and an exact match is safe rather than brittle.

Same reasoning applied to `mitre_technique`: matched on the extracted `T0XXX` ID only (never the trailing name text, phrasing varies), and for SIDs where `MITRE_HINTS` itself offers more than one legitimate candidate (1000004 and 1000010), the expected file lists acceptable IDs rather than pinning one.

### Gathering Frozen Inputs

Five of six inputs are real captures pulled straight from `eve.json` during live attack runs earlier in this session: coil write (1000001), register write (1000002), broad write (1000004), the catch-all (1000010), and a recon case (1000006, see below). The sixth, the ST program upload (1000003), is synthetic, hand-built to match Suricata's real HTTP alert schema rather than actually run against the live PLC, since it's the highest-impact rule in the catalog (full control logic replacement) and the `attack-testing` skill deliberately has no ready-made command for it. The input file says so explicitly in a `_frozen_input_note` field, so nobody mistakes it for a live capture later.

### A Skill Bug Found Along the Way

Generating the recon case (1000006) surfaced a real bug, not in the pipeline, in the `attack-testing` skill's documented command. The rule is a threshold rule:

```
threshold:type both,track by_src,count 10,seconds 10
```

It needs **10 SYN packets to port 502 within 10 seconds** from one source. The skill's documented command, `sudo nmap -sS -p 502 192.168.95.2`, sends one SYN (maybe two with a retry) against a single responsive port, nowhere near the threshold. Ran it as literally documented. Zero alerts. Silent failure, exactly the kind of thing this whole harness project exists to catch systematically instead of by hand.

The fix: `flags:S` in the rule matches any SYN-only packet, not specifically a raw SYN scan, so a plain TCP `connect()` loop trips it just as well and needs no root:

```python
import socket
for i in range(12):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(('192.168.95.2', 502))
    except Exception:
        pass
    finally:
        s.close()
```

12 iterations reliably clears the threshold. Updated the `attack-testing` skill itself to lead with this version (marked `[CLAUDE OK]`, no sudo needed), and kept a corrected nmap variant (`for i in 1 2 3; do sudo nmap -sS -p 502 ...; done`) as the fallback for anyone who specifically wants a real SYN scan.

### First Real Run Caught a Second Bug

With all six inputs and expected files in place, the first full run of `run_evals.py` came back 5/6. The failure:

```
[FAIL] 002_register_write
    - severity_reason: length 505 above max_len 500
    - likely_attack: length 527 above max_len 500
```

Before touching anything, reran the same case standalone to see if this was a real regression or just noise, since `temperature=0.1` isn't fully deterministic. Second run came back at 460 and 404 characters, comfortably inside the bound. That settled it: not a pipeline defect, an eval calibration issue. The system prompt asks for "2-3 sentences," and dense ICS content can legitimately swing between roughly 400 and 550 characters for that. `max_len: 500` was set too tight in the expected files. Widened it to 650 across all six cases and reran.

```
6/6 cases passed
```

> [!info] Why this mattered enough to write down
> An eval harness that's too strict is its own failure mode, it either gets loosened reflexively until it stops catching anything, or it gets ignored because it cries wolf. Verifying the failure was real *before* changing the bound, rather than just widening it until green, is the difference between calibrating a test and defeating its purpose.

### What's Running Now

```
evals/
├── inputs/
│   ├── 001_coil_write.json
│   ├── 002_register_write.json
│   ├── 003_broad_write.json
│   ├── 004_catchall.json
│   ├── 005_recon_scan.json
│   └── 006_st_program_upload.json     # synthetic, see _frozen_input_note
├── expected/
│   ├── 001_coil_write.expected.json
│   ├── 002_register_write.expected.json
│   ├── 003_broad_write.expected.json
│   ├── 004_catchall.expected.json
│   ├── 005_recon_scan.expected.json
│   └── 006_st_program_upload.expected.json
└── run_evals.py
```

`run_evals.py` imports `ics_alert_pipeline` directly, clears rate-limit state per case so each one is judged independently of real-world timing, runs `enrich_alert()` on the frozen input, and grades the result: exact match for severity floor/ceiling cases and MITRE IDs, "at least" comparisons where the floor is the real invariant, length-and-keyword bounds for free text, item-count bounds for arrays, and derived (not model-asked) checks for category and human-review status. Exits non-zero on any failure, so it's ready to sit in front of a commit that touches the system prompt, the model version, `temperature`/`max_tokens`, or the JSON extraction logic, per the trigger points already listed above.



# Stage 6:  Correlation: separate command, register state, and physical effect


In this stage, I am going to imrpove the organziation of the alert dashboard. Right now one attack can generate multiple alerts and those are not grouped in a way that lets say,  Splunk would group alerts. It is unorganized in that each alert has its own severity rating and looks as if they are seperate, as well as they have their own "cards".

I will be changing it to be such that if a very specific rule such as a modbus coil attack happens, that SID of that is I believe100004, will be the headline while the other general attacks such as the broad unauthorized modbus traffic, will be suporting evidence with their SID noted.

I will also be implenting a way to know if an attack actually had an affect on the physical process. That is, if a register attack took place and nothing on the physical process changed, then it will state that in the alert, to have more specificity and granular alerting. I will utlize the **EWS** to scan the process as the alert comes in to see if the physical process was changed.

### EWS Didn't Work Out, Used Kali Instead

First problem: the pipeline itself runs on the host, not in a container, and the host's own NIC (`eno1`) sits on a completely different subnet (`192.168.1.0/24`) than the macvlan ICS network. Confirmed with a raw socket connect, `192.168.95.2:502` from the host just times out. So the live read has to happen from inside a container that's actually on the ICS network, `docker exec`, not from the pipeline process itself.

Tried EWS first like I planned. Its image (`workstation/Dockerfile`, upstream, not mine) doesn't have `pymodbus` installed at all. `kali`'s image does, `attacker/Dockerfile` installs `python3-pymodbus` directly, so nothing extra to build. Went with kali for now since it works immediately, but it's a real compromise worth writing down: the system prompt itself calls Kali "never authorized" to talk to the PLC, and now it's the pipeline's own trusted read source for checking physical state. Still strictly read-only and doesn't touch detection either way. Revisit once EWS's image actually carries pymodbus.

### Three Separate Facts Instead of One Story

Every alert with a Modbus write payload now carries three facts:
- **Command attempted** - pulled straight out of Suricata's own Modbus decode (`modbus.request.write.address` / `.data` in `eve.json`). Ground truth for what was actually sent, not something the model has to guess.
- **Register/coil observed** - a live, read-only Modbus read of that same address, taken right after the alert.
- **Physical indicator** - a live read of reactor pressure (input register 108), a real sensor value, not a control mirror like registers 102/103.

New required field on the model's output, `physical_effect_assessment`: `observed` / `not_observed` / `inconclusive` / `not_applicable`. It's told explicitly to base that only on the two live reads above, never on inference. That's what makes something like "unauthorized write detected, but no physical change observed" an honest, groundable claim for register 102 (the mirror, not the real actuator) instead of a guess dressed up as one.

### Bug: Same Packet, Three Different Verdicts

First live test surfaced a problem. One coil-write packet tripped all three rules like it always does (1000001, 1000004, 1000010). Each one independently took its own live read, seconds apart, because enrichment happens one alert at a time. My own restore-write (turning the coil back on) landed in the middle of that sequence, so the three cards for the exact same packet came back with three different verdicts: `observed`, `inconclusive`, `not_observed`. Each individual read was honest about what it saw at that exact moment, but three different answers for one attack defeats the entire point of this feature.

Fixed by grouping alerts server-side on `flow_id` (Suricata gives every rule that matches one packet the same flow_id) and taking the live reads **once per group**, shared across every rule that fired on that packet.

```python
def group_key(raw: dict) -> str:
    flow_id = raw.get("flow_id")
    if flow_id is not None:
        return f"flow-{flow_id}"
    return f"{raw.get('src_ip')}-{raw.get('dest_ip')}-{raw.get('dest_port')}-{raw.get('timestamp')}"
```

Reran the same coil-write test live afterward: all three rules now agree on the same verdict.

> [!info] pymodbus gotcha found along the way
> pymodbus 3.x response objects all carry a `.bits` attribute regardless of type, empty list for register reads. A naive `hasattr(r, 'bits')` check meant to tell a coil read from a register read always took the wrong branch, silently returning an empty list for every register read instead of the actual value. Fixed by branching on the read kind directly (I already know it going in) instead of introspecting the response object.

### Cutting the Text Down, Splitting Actions
Once the facts were right, the dashboard itself was still a wall of text: one long "recommended actions" list mixing "block this IP right now" with "audit your firewall rules next quarter," and no visual weight on the one thing this whole feature exists for, whether the attack actually did anything physical.

Split the schema's `actions` into two: `immediate_actions` (max 4, must reference the actual attacker IP/address/value already given, no generic advice) and `after_neutralized_actions` (max 4, hardening/follow-up, explicitly not urgent). Added a one-line `headline` field so there's something to read before the paragraphs start. Tightened every narrative field to 1-2 sentences each with no repeating the same fact across fields.

On the dashboard: a color-coded physical-effect banner (red = confirmed, green = not observed, amber = inconclusive) right under the severity block, showing the command sent, what the PLC reads right now, and reactor pressure. The same status now shows as a small chip in the compact timeline list too, so it's visible before even opening an alert. "Do Now" is a red-tinted block near the top; "After Threat Is Neutralized" got demoted into a quieter, muted list further down. Everything else (what happened, likely attack, tags) is collapsed by default behind a "Show details" toggle instead of always being on screen.

### Eval Harness Had to Move Too

Renaming `actions` broke all six `array_checks` in the harness, since they were checking a field name that no longer existed. Updated all six `expected/*.json` files to check `immediate_actions` / `after_neutralized_actions` instead.

Tightening the prompt caused one real regression: `003_broad_write` failed because `what_happened` no longer said "Modbus" literally, the model wrote "FC5 coil write" instead, just as accurate, just not the exact word the harness was checking for. Rather than loosen the prompt back up and lose the density fix, extended the harness with a `required_keywords_any_of` check (any one of a list is enough, not all of them) and used that instead of a single rigid keyword.

```
6/6 cases passed
```

### Screenshot
![[GRFICSv3 Documentation-1790477004355.webp]]
![[GRFICSv3 Documentation-1790476995897.webp]]

### What's Left

Steps 2 (expand the eval harness: unsupported physical-impact claims, API-failure cases, a real benign-traffic/false-alarm test) and 3 (process-data monitoring, scoped correctly this time) are still open. Picking this back up next session.

# References

- [GRFICSv3](https://github.com/Fortiphyd/GRFICSv3) by Fortiphyd Logic, the open-source ICS/OT simulation this lab is built on top of.
- [Suricata Modbus Keyword Documentation](https://docs.suricata.io/en/suricata-7.0.3/rules/modbus-keyword.html)
- [Suricata 7.0.3 Documentation](https://docs.suricata.io/en/suricata-7.0.3/)
