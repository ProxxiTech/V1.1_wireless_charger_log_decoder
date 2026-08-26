#!/usr/bin/env python3
"""
IP6829 wireless-charger TX live log decoder.

Decodes the UART debug stream (115200 8N1, e.g. via a CH340 dongle) emitted by
the Injoinic IP6829 firmware and shows a live status dashboard.

Line formats handled (as seen in "V1.1_v1.1 over heat Aug 14.txt"):
    VI:5034,149,495          bus voltage mV, current A, current B (mA-ish raw)
    F:292,1024,800,0         inverter operating point: freq raw, duty raw, ...
    NTC:1410,0               NTC voltage mV, over-temp warning flag
    $H3,FF,1                 Qi packet from RX: header 0x03 Control Error
    $H4,11,1                 header 0x04 Received Power (RP8)
    $H1,93,1                 header 0x01 Signal Strength (ping response)
    $H71,12,0,5C,0,0,0,0,1   header 0x71 Identification
    $H51,A,0,0,82,0,1        header 0x51 Configuration
    Ploss:79,1432            FOD power loss mW, transmitted power mW
    Pt:742                   received power reported by RX, mW
    ST:27                    power transfer stopped, code (27 = over-temp)
    FD328,1024               digital ping operating point (freq, duty)
    API:117,163,260          analog ping current readings
    SS:0x800                 status bitmask at object detect

Usage:
    python ip6829_live_decoder.py                    # GUI, pick COM port
    python ip6829_live_decoder.py --port COM5        # GUI, open port at once
    python ip6829_live_decoder.py --replay LOG.txt   # GUI, replay a saved log
    python ip6829_live_decoder.py --summary LOG.txt  # no GUI, print analysis
"""

import argparse
import math
import os
import re
import sys
import time
import threading
from collections import deque

# raw captures are written as "YYYY-MM-DD HH:MM:SS.mmm <line>"; the parser
# strips the stamp so both stamped and legacy unstamped logs replay fine
TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+")

# ---------------------------------------------------------------- protocol --

STOP_CODES = {
    27: "OVER TEMPERATURE (NTC)",
    23: "RX REQUESTED STOP (EPT packet, see reason above)",
    # observed during ping with nothing valid on the pad (not faults):
    4: "ping: no handshake (code 4)",
    5: "ping: no receiver (code 5)",
    # other codes not yet decoded; shown numerically when they appear
}

QI_HEADERS = {
    0x01: "Signal Strength",
    0x02: "End Power Transfer",
    0x03: "Control Error",
    0x04: "Received Power (RP8)",
    0x05: "Charge Status",
    0x06: "Power Control Hold-off",
    0x18: "Proprietary",
    0x31: "Received Power (RP16)",
    0x51: "Configuration",
    0x71: "Identification",
    0x81: "Extended Identification",
}

# NTC thresholds observed in the Aug 14 log (NTC voltage falls as temp rises)
NTC_WARN_MV = 580     # warning flag latches ~here
NTC_STOP_MV = 475     # ST:27 fires ~here
NTC_RESUME_MV = 700   # charging restarts once NTC recovers above ~here

# --- NTC voltage -> temperature conversion ---------------------------------
# Thermistor per the IP6829 design guide BOM: 100k @ 25 C, B = 3950, wired
# from the NTC pin to GND. The pull-up is inside the IP6829 and Injoinic does
# not publish it; 100k to the 3.3V VCC rail is assumed (the usual choice that
# centers the divider at 25 C). If a spot-check with an IR thermometer
# disagrees, adjust NTC_PULLUP / NTC_VREF_MV below.
NTC_R25 = 100_000.0     # ohms at 25 C
NTC_BETA = 3950.0
NTC_PULLUP = 100_000.0  # internal pull-up, ohms (assumed)
NTC_VREF_MV = 3300.0    # pull-up rail, mV (assumed = VCC)


# --- F: raw value -> inverter frequency ------------------------------------
# The F: value behaves like a timer period: it RISES as the chip pushes more
# power, i.e. as the operating frequency descends toward the 100 kHz
# resonance. Assuming a 48 MHz timer clock puts every observed value inside
# the IP6829's specified 115-148 kHz band (ping F=328 -> 146 kHz, the design
# guide's typical f_op). ESTIMATE - calibrate FREQ_CLK_HZ with one scope
# measurement of the coil frequency at a known F: value.
FREQ_CLK_HZ = 48e6


def freq_raw_to_khz(raw):
    if not raw:
        return None
    return FREQ_CLK_HZ / raw / 1000.0


def ntc_mv_to_c(mv):
    """Convert an NTC: reading in mV to degrees Celsius (beta model)."""
    if mv is None or mv <= 0 or mv >= NTC_VREF_MV:
        return None
    r = NTC_PULLUP * mv / (NTC_VREF_MV - mv)
    inv_t = 1.0 / 298.15 + math.log(r / NTC_R25) / NTC_BETA
    return 1.0 / inv_t - 273.15


def signed8(v):
    return v - 256 if v > 127 else v


def decode_qi_packet(header, payload):
    """Return a one-line human explanation of a $H packet."""
    name = QI_HEADERS.get(header, "header 0x%02X" % header)
    if header == 0x03 and payload:
        ce = signed8(payload[0])
        if ce == 0:
            return "Control Error 0 (RX satisfied, hold power)"
        return "Control Error %+d (RX requests %s power)" % (
            ce, "more" if ce > 0 else "less")
    if header == 0x01 and payload:
        return "Signal Strength %d/256 (%.0f%%)" % (payload[0], payload[0] / 2.56)
    if header == 0x04 and payload:
        return "Received Power raw %d" % payload[0]
    if header == 0x02 and payload:
        ept = {0: "Unknown", 1: "Charge complete", 2: "Internal fault",
               3: "Over temperature", 4: "Over voltage", 5: "Over current",
               6: "Battery failure", 8: "No response", 11: "Restart"}
        return "End Power Transfer: %s" % ept.get(payload[0], payload[0])
    if header == 0x51 and len(payload) >= 5:
        maxp = (payload[0] & 0x3F) / 2.0
        return "Configuration: RX max power %.1f W" % maxp
    if header == 0x71 and len(payload) >= 7:
        ver = payload[0]
        mfr = (payload[1] << 8) | payload[2]
        return "Identification: Qi v%d.%d, manufacturer 0x%04X" % (
            ver >> 4, ver & 0xF, mfr)
    return "%s: %s" % (name, ",".join("%02X" % b for b in payload))


class LogParser:
    """Stateful parser for the IP6829 debug stream."""

    def __init__(self):
        self.state = "IDLE"          # IDLE / PING / HANDSHAKE / POWER / STOPPED
        self.vbus = self.i1 = self.i2 = None
        self.freq = self.duty = None
        self.ntc_mv = None
        self.ntc_flag = 0
        self.ploss = self.ptx = self.prx = None
        self.ce = None
        self.stop_code = None
        self.restarts = 0
        self.stops = 0
        self.rx_maxpower = None
        self.rx_id = None
        self.events = deque(maxlen=500)   # (kind, text) tuples
        self.on_event = None              # optional callback(kind, text)
        self.last_vi_time = 0.0           # wall time of the last VI: line
        self.last_ntc_time = 0.0          # wall time of the last NTC: line
        self.last_ploss_time = 0.0        # wall time of the last Ploss: line

    def _event(self, kind, text):
        self.events.append((kind, text))
        if self.on_event:
            self.on_event(kind, text)

    def feed(self, line):
        """Parse one line; returns True if the line was recognized."""
        line = TS_PREFIX_RE.sub("", line.strip())
        if not line:
            return False
        try:
            return self._feed(line)
        except (ValueError, IndexError):
            self._event("warn", "unparsed: " + line)
            return False

    def _feed(self, line):
        if line.startswith("VI:"):
            self.vbus, self.i1, self.i2 = map(int, line[3:].split(","))
            self.last_vi_time = time.time()
            if self.state in ("IDLE", "STOPPED", "PING", "HANDSHAKE"):
                self.state = "POWER"
            return True

        if line.startswith("F:"):
            parts = list(map(int, line[2:].split(",")))
            self.freq, self.duty = parts[0], parts[1]
            return True

        if line.startswith("NTC:"):
            v, flag = line[4:].split(",")
            self.ntc_mv, prev = int(v), self.ntc_flag
            self.last_ntc_time = time.time()
            self.ntc_flag = int(flag)
            t = ntc_mv_to_c(self.ntc_mv)
            t_txt = " (~%.0f C)" % t if t is not None else ""
            if self.ntc_flag and not prev:
                self._event("warn", "NTC warning latched at %d mV%s, heating"
                            % (self.ntc_mv, t_txt))
            elif prev and not self.ntc_flag:
                self._event("ok", "NTC recovered at %d mV%s, cooled down"
                            % (self.ntc_mv, t_txt))
            return True

        if line.startswith("Ploss:"):
            self.ploss, self.ptx = map(int, line[6:].split(","))
            self.last_ploss_time = time.time()
            return True

        if line.startswith("Pt:"):
            self.prx = int(line[3:])
            return True

        if line.startswith("ST:"):
            self.stop_code = int(line[3:])
            self.stops += 1
            self.state = "STOPPED"
            reason = STOP_CODES.get(self.stop_code, "code %d" % self.stop_code)
            self._event("stop", "POWER TRANSFER STOPPED - %s" % reason)
            return True

        if line.startswith("FD"):
            self.state = "PING"
            return True

        if line.startswith("API:"):
            self.state = "PING"
            return True

        if line.startswith("SS:"):
            self.state = "PING"
            self._event("info", "object detected, status %s" % line[3:])
            return True

        if line.startswith("$H"):
            fields = line[2:].split(",")
            header = int(fields[0], 16)
            payload = [int(x, 16) for x in fields[1:-1]]
            ok = fields[-1] == "1"
            text = decode_qi_packet(header, payload)
            if not ok:
                self._event("warn", "bad checksum: " + line)
            if header == 0x03 and payload:
                self.ce = signed8(payload[0])
            elif header == 0x01:
                self.state = "HANDSHAKE"
                self.restarts += 1
                self._event("start", "ping answered (%s) - restart #%d" %
                            (text, self.restarts))
            elif header == 0x51:
                if len(payload) >= 5:
                    self.rx_maxpower = (payload[0] & 0x3F) / 2.0
                self._event("info", text)
                self.state = "POWER"
            elif header == 0x71:
                self.rx_id = text
                self._event("info", text)
            elif header == 0x02:
                self._event("stop", text)
            return True

        return False

    # convenience for dashboards
    def ntc_status(self):
        if self.ntc_mv is None:
            return ("no data", "gray")
        if self.state == "STOPPED":
            return ("COOLING DOWN (resumes < ~%.0f C)"
                    % (ntc_mv_to_c(NTC_RESUME_MV) or 0), "blue")
        if self.ntc_mv <= NTC_STOP_MV:
            return ("OVER TEMP", "red")
        if self.ntc_flag or self.ntc_mv <= NTC_WARN_MV:
            return ("HOT - warning", "orange")
        return ("OK", "green")


# ----------------------------------------------------------------- summary --

def summarize(path):
    p = LogParser()
    ntc_min = 10 ** 9
    ntc_max = 0
    ploss_max = 0
    cycles = []          # lines-per-charging-cycle
    last_stop_line = 0
    stop_lines = []
    with open(path, errors="ignore") as f:
        for n, line in enumerate(f, 1):
            p.feed(line)
            if p.ntc_mv is not None:
                ntc_min = min(ntc_min, p.ntc_mv)
                ntc_max = max(ntc_max, p.ntc_mv)
            if p.ploss is not None:
                ploss_max = max(ploss_max, p.ploss)
            if line.startswith("ST:"):
                stop_lines.append(n)
                if last_stop_line:
                    cycles.append(n - last_stop_line)
                last_stop_line = n
    print("=== %s ===" % path)
    print("stops (ST): %d, all decoded events below" % p.stops)
    print("restarts (ping answered): %d" % p.restarts)
    print("NTC range: %d..%d mV (falls as temperature rises)" % (ntc_min, ntc_max))
    t_hi, t_lo = ntc_mv_to_c(ntc_min), ntc_mv_to_c(ntc_max)
    if t_hi is not None and t_lo is not None:
        print("estimated temperature range: %.1f..%.1f C "
              "(100k B=3950 NTC, assumed 100k pull-up to %.1fV)"
              % (t_lo, t_hi, NTC_VREF_MV / 1000))
    print("max FOD Ploss: %d mW" % ploss_max)
    if cycles:
        print("lines per stop-to-stop cycle: min %d / avg %d / max %d" %
              (min(cycles), sum(cycles) // len(cycles), max(cycles)))
    print("last state: %s   RX: %s, max power %s W" %
          (p.state, p.rx_id, p.rx_maxpower))
    print("--- event log ---")
    for kind, text in p.events:
        print("[%-5s] %s" % (kind, text))


# --------------------------------------------------------------------- GUI --

def run_gui(args):
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox

    root = tk.Tk()
    root.title("IP6829 Live Decoder")
    parser = LogParser()
    line_queue = deque()
    queue_lock = threading.Lock()
    reader = {"stop": threading.Event(), "thread": None, "ser": None}

    # -- top bar: source selection ------------------------------------------
    top = ttk.Frame(root)
    top.pack(fill="x", padx=6, pady=4)
    ttk.Label(top, text="Port:").pack(side="left")
    port_cb = ttk.Combobox(top, width=28, state="readonly")
    port_cb.pack(side="left", padx=4)

    def list_ports():
        try:
            import serial.tools.list_ports
            ports = list(serial.tools.list_ports.comports())
        except ImportError:
            return []
        # CH340 first
        ports.sort(key=lambda p: "CH340" not in (p.description or ""))
        return ["%s  (%s)" % (p.device, p.description) for p in ports]

    def refresh_ports():
        vals = list_ports()
        port_cb["values"] = vals
        if vals and not port_cb.get():
            port_cb.set(vals[0])

    ttk.Button(top, text="Refresh", command=refresh_ports).pack(side="left")
    connect_btn = ttk.Button(top, text="Connect")
    connect_btn.pack(side="left", padx=6)
    src_label = ttk.Label(top, text="disconnected", foreground="gray")
    src_label.pack(side="left", padx=8)

    # -- state banner ---------------------------------------------------------
    banner = tk.Label(root, text="WAITING FOR DATA", font=("Segoe UI", 18, "bold"),
                      bg="gray30", fg="white", pady=6)
    banner.pack(fill="x", padx=6, pady=(0, 4))

    # -- numeric grid ---------------------------------------------------------
    grid = ttk.Frame(root)
    grid.pack(fill="x", padx=6)
    fields = {}
    layout = [
        ("Vbus (mV)", "vbus"), ("I1 (mA)", "i1"), ("I2 (mA)", "i2"),
        ("Freq raw", "freq"), ("Freq kHz (est.)", "fkhz"),
        ("CE (RX ctrl err)", "ce"),
        ("NTC (mV)", "ntc"), ("Temp (C)*", "temp"), ("NTC status", "ntcstat"),
        ("Stops / Restarts", "cnt"),
        ("Ptx (mW)", "ptx"), ("Prx (mW)", "prx"), ("Ploss FOD (mW)", "ploss"),
    ]
    for idx, (label, key) in enumerate(layout):
        r, c = divmod(idx, 3)
        cell = ttk.Frame(grid)
        cell.grid(row=r, column=c, sticky="w", padx=8, pady=2)
        ttk.Label(cell, text=label, foreground="gray").pack(anchor="w")
        var = tk.StringVar(value="-")
        lbl = tk.Label(cell, textvariable=var, font=("Consolas", 14, "bold"))
        lbl.pack(anchor="w")
        fields[key] = (var, lbl)

    # -- strip charts (plain canvas, no matplotlib needed) --------------------
    charts = ttk.Frame(root)
    charts.pack(fill="both", expand=True, padx=6, pady=4)
    HIST_WINDOW = 300.0   # seconds shown on every chart (same time scale)
    GAP_SPLIT = 5.0       # break the trace when no data for this long
    chart_specs = [("Temperature (C, est. from NTC)", "temp", "#cc4400"),
                   ("Current I1 (mA)", "i1", "#0066cc"),
                   ("Vbus (mV)", "vbus", "#1a7a1a"),
                   ("FOD power loss Ploss (mW)", "ploss", "#b30000"),
                   ("Inverter frequency (kHz, estimated)", "freq", "#7a1a7a"),
                   ("Current I2 (mA)", "i2", "#00879e"),
                   ("Ptx transmitted power (mW)", "ptx", "#946200"),
                   ("Prx received power (mW)", "prx", "#4d6600"),
                   ("Control Error from RX", "ce", "#555555")]
    DEFAULT_VISIBLE = {"temp", "i1", "vbus", "ploss", "freq"}
    canvases = []
    hist = {k: deque() for _, k, _ in chart_specs}  # (time, value) pairs
    # checkbox row to choose which parameters are charted
    selbar = ttk.Frame(charts)
    selbar.pack(side="top", fill="x")
    visible = {}
    frames = {}

    def clear_charts():
        for dq in hist.values():
            dq.clear()

    ttk.Button(selbar, text="Clear", command=clear_charts).pack(
        side="right", padx=3)

    def relayout():
        for _, key, _ in chart_specs:
            frames[key].pack_forget()
        for _, key, _ in chart_specs:
            if visible[key].get():
                frames[key].pack(side="top", fill="both", expand=True, pady=2)

    for title, key, color in chart_specs:
        visible[key] = tk.BooleanVar(value=key in DEFAULT_VISIBLE)
        ttk.Checkbutton(selbar, text=key, variable=visible[key],
                        command=relayout).pack(side="left", padx=3)
        f = ttk.LabelFrame(charts, text=title)
        frames[key] = f
        cv = tk.Canvas(f, height=80, bg="white", highlightthickness=0)
        cv.pack(fill="both", expand=True)
        canvases.append((cv, key, color))
    relayout()

    def draw_chart(cv, key, color, now):
        cv.delete("all")
        dq = hist[key]
        t0 = now - HIST_WINDOW
        while dq and dq[0][0] < t0:
            dq.popleft()
        w = max(cv.winfo_width(), 50)
        h = max(cv.winfo_height(), 50)
        data = list(dq)
        if len(data) < 2:
            return
        vals = [v for _, v in data]
        lo, hi = min(vals), max(vals)
        span = max(hi - lo, 1e-9)

        def xy(t, v):
            return (5 + (t - t0) / HIST_WINDOW * (w - 10),
                    h - 8 - (v - lo) * (h - 20) / span)

        seg = []
        prev_t = None
        for t, v in data:
            if prev_t is not None and t - prev_t > GAP_SPLIT:
                if len(seg) >= 4:
                    cv.create_line(*seg, fill=color, width=2)
                seg = []
            seg += xy(t, v)
            prev_t = t
        if len(seg) >= 4:
            cv.create_line(*seg, fill=color, width=2)

        fmt = (lambda v: "%.1f" % v) if key == "temp" else (lambda v: str(int(v)))
        cv.create_text(4, 4, anchor="nw", text=fmt(hi), fill="gray")
        cv.create_text(4, h - 14, anchor="nw", text=fmt(lo), fill="gray")
        cv.create_text(w - 4, h - 14, anchor="ne",
                       text="last %d s" % int(HIST_WINDOW), fill="gray")
        if key == "temp":
            for mv, c in ((NTC_WARN_MV, "orange"), (NTC_STOP_MV, "red")):
                tc = ntc_mv_to_c(mv)
                if tc is not None and lo <= tc <= hi:
                    y = h - 8 - (tc - lo) * (h - 20) / span
                    cv.create_line(5, y, w - 5, y, fill=c, dash=(3, 3))

    # -- event log -------------------------------------------------------------
    logf = ttk.LabelFrame(root, text="Decoded events")
    logf.pack(fill="both", expand=True, padx=6, pady=(0, 6))
    logbox = scrolledtext.ScrolledText(logf, height=10, state="disabled",
                                       font=("Consolas", 9))
    logbox.pack(fill="both", expand=True)
    for tag, color in (("stop", "red"), ("start", "green"), ("warn", "#b36b00"),
                       ("ok", "green"), ("info", "black")):
        logbox.tag_config(tag, foreground=color)

    def on_event(kind, text):
        stamp = time.strftime("%H:%M:%S")
        logbox.config(state="normal")
        logbox.insert("end", "%s  %s\n" % (stamp, text), kind)
        logbox.yview("end")
        logbox.config(state="disabled")

    parser.on_event = on_event

    # -- reader threads ---------------------------------------------------------
    def serial_reader(port):
        import serial
        try:
            ser = serial.Serial(port, args.baud, timeout=1)
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Serial error", str(e)))
            return
        reader["ser"] = ser
        log_name = time.strftime("ip6829_raw_%Y%m%d_%H%M%S.txt")
        raw_log = open(log_name, "a", buffering=1)  # line-buffered
        root.after(0, lambda: parser._event("info", "saving raw log to " + log_name))
        while not reader["stop"].is_set():
            try:
                line = ser.readline().decode(errors="ignore")
            except Exception:
                break
            if line:
                now = time.time()
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
                stamp += ".%03d " % (int(now * 1000) % 1000)
                raw_log.write(stamp + (line if line.endswith("\n") else line + "\n"))
                with queue_lock:
                    line_queue.append(line)
        raw_log.close()
        try:
            ser.close()
        except Exception:
            pass

    def replay_reader(path, speed, tail_mb):
        # ~4 VI frames/s on the wire; 3 log lines per frame -> ~12 lines/s
        delay = 1.0 / (12.0 * speed)
        with open(path, errors="ignore") as f:
            if tail_mb > 0:
                skip = os.path.getsize(path) - int(tail_mb * 1048576)
                if skip > 0:
                    f.seek(skip)
                    f.readline()      # drop the partial line at the cut
            batch = 0
            for line in f:
                if reader["stop"].is_set():
                    return
                with queue_lock:
                    line_queue.append(line)
                batch += 1
                if batch >= 20:       # sleep per chunk: Windows timers are coarse
                    time.sleep(delay * 20)
                    batch = 0

    def start_reader(target, *a):
        reader["stop"].clear()
        t = threading.Thread(target=target, args=a, daemon=True)
        reader["thread"] = t
        t.start()

    def toggle_connect():
        if reader["thread"] and reader["thread"].is_alive():
            reader["stop"].set()
            connect_btn.config(text="Connect")
            src_label.config(text="disconnected", foreground="gray")
            return
        sel = port_cb.get()
        if not sel:
            messagebox.showwarning("No port", "Select a COM port first")
            return
        port = sel.split()[0]
        start_reader(serial_reader, port)
        connect_btn.config(text="Disconnect")
        src_label.config(text="live on %s @ %d" % (port, args.baud),
                         foreground="green")

    connect_btn.config(command=toggle_connect)

    # -- periodic UI update -----------------------------------------------------
    STATE_COLORS = {"POWER": ("POWER TRANSFER", "#1a7a1a"),
                    "PING": ("PINGING / OBJECT DETECT", "#946200"),
                    "HANDSHAKE": ("HANDSHAKE (ID & CONFIG)", "#946200"),
                    "STOPPED": ("STOPPED", "#b30000"),
                    "IDLE": ("WAITING FOR DATA", "gray30")}

    def tick():
        n = 0
        while n < 2000:  # bound work per tick
            with queue_lock:
                if not line_queue:
                    break
                line = line_queue.popleft()
            parser.feed(line)
            n += 1

        text, color = STATE_COLORS.get(parser.state, (parser.state, "gray30"))
        if parser.state == "STOPPED" and parser.stop_code is not None:
            reason = STOP_CODES.get(parser.stop_code,
                                    "code %d" % parser.stop_code)
            text = "STOPPED - %s" % reason
        banner.config(text=text, bg=color)

        def put(key, val, color="black"):
            var, lbl = fields[key]
            var.set("-" if val is None else str(val))
            lbl.config(fg=color)

        put("vbus", parser.vbus)
        put("i1", parser.i1)
        put("i2", parser.i2)
        put("freq", parser.freq)
        fk = freq_raw_to_khz(parser.freq)
        put("fkhz", "%.1f" % fk if fk is not None else None)
        put("ce", "%+d" % parser.ce if parser.ce is not None else None)
        stat, scolor = parser.ntc_status()
        tcolor = {"red": "red", "orange": "#b36b00"}.get(scolor, "black")
        put("ntc", parser.ntc_mv, tcolor)
        tnow = ntc_mv_to_c(parser.ntc_mv)
        put("temp", "%.1f" % tnow if tnow is not None else None, tcolor)
        put("ntcstat", stat, {"green": "#1a7a1a", "orange": "#b36b00",
                              "red": "red", "blue": "#0055cc"}.get(scolor, "black"))
        put("cnt", "%d / %d" % (parser.stops, parser.restarts),
            "red" if parser.stops else "black")
        put("ptx", parser.ptx)
        put("prx", parser.prx)
        put("ploss", parser.ploss,
            "red" if (parser.ploss or 0) > 500 else "black")

        # sample all charts on the same clock; skip a metric when its source
        # lines stopped arriving (e.g. no VI: frames during thermal cooldown)
        now = time.time()
        if tnow is not None and now - parser.last_ntc_time < GAP_SPLIT:
            hist["temp"].append((now, tnow))
        if parser.i1 is not None and now - parser.last_vi_time < GAP_SPLIT:
            hist["i1"].append((now, parser.i1))
            hist["i2"].append((now, parser.i2))
            hist["vbus"].append((now, parser.vbus))
            if parser.freq:
                hist["freq"].append((now, freq_raw_to_khz(parser.freq)))
            if parser.ce is not None:
                hist["ce"].append((now, parser.ce))
        if parser.ploss is not None and now - parser.last_ploss_time < 10:
            hist["ploss"].append((now, parser.ploss))
            hist["ptx"].append((now, parser.ptx))
            if parser.prx is not None:
                hist["prx"].append((now, parser.prx))
        t0 = now - HIST_WINDOW
        for dq in hist.values():
            while dq and dq[0][0] < t0:
                dq.popleft()
        for cv, key, color in canvases:
            if visible[key].get():
                draw_chart(cv, key, color, now)
        root.after(150, tick)

    refresh_ports()
    if args.replay:
        tail_note = (" last %g MB" % args.tail_mb) if (
            args.tail_mb > 0 and
            os.path.getsize(args.replay) > args.tail_mb * 1048576) else ""
        src_label.config(text="replay: %s (x%g)%s" % (args.replay, args.speed,
                                                      tail_note),
                         foreground="#0055cc")
        start_reader(replay_reader, args.replay, args.speed, args.tail_mb)
    elif args.port:
        port_cb.set(args.port)
        start_reader(serial_reader, args.port)
        connect_btn.config(text="Disconnect")
        src_label.config(text="live on %s @ %d" % (args.port, args.baud),
                         foreground="green")
    root.after(150, tick)
    root.geometry("980x920")
    root.mainloop()
    reader["stop"].set()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--port", help="COM port to open at startup (e.g. COM5)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--replay", metavar="FILE", help="replay a saved log file")
    ap.add_argument("--speed", type=float, default=20.0,
                    help="replay speed multiplier (default 20x)")
    ap.add_argument("--tail-mb", type=float, default=5.0,
                    help="replay only the last N MB of a large file "
                         "(default 5; 0 = whole file)")
    ap.add_argument("--summary", metavar="FILE",
                    help="offline: parse FILE and print an analysis, no GUI")
    args = ap.parse_args()
    if args.summary:
        summarize(args.summary)
        return
    run_gui(args)


if __name__ == "__main__":
    main()
