# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Howard M. Harte
#
# Open a serial port through serbridge when a bridge is serving it.
#
# `serbridge --listen` writes the URL of its RFC 2217 server to a file named for
# the port it holds. New-SerBridgePort looks there first: with a bridge running
# it returns a SerBridge.Port, an RFC 2217 client with the members of
# System.IO.Ports.SerialPort that scripts use; with none it returns a real
# System.IO.Ports.SerialPort. Either way the script goes on as before:
#
#   Import-Module (Join-Path $PSScriptRoot 'SerBridge.psm1')
#   $sp = New-SerBridgePort -PortName COM17 -BaudRate 115200
#   $sp.ReadTimeout = 500
#   $sp.Open(); $sp.Write("dir`r"); Start-Sleep 1; $sp.ReadExisting(); $sp.Close()
#
# This file is copied into each repository that uses it; the canonical copy is
# retrosim-transports/serbridge/clients/powershell/SerBridge.psm1.
#
# The C# is kept to C# 5, the language Windows PowerShell 5.1's Add-Type
# compiles.

if (-not ('SerBridge.Port' -as [type])) {
    # Windows PowerShell 5.1 adds a named reference to its defaults, which hold
    # everything else the C# uses; System.IO.Ports is in System.dll there,
    # named by SerialPort's assembly. PowerShell 7 drops its defaults once any
    # reference is named, and System.IO.Ports is its own assembly there, so
    # every assembly the C# uses is named.
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $refs = @('System.IO.Ports', 'System.Net.Sockets', 'System.Net.Primitives',
            'System.Collections', 'System.Runtime', 'System.ComponentModel.Primitives',
            'System.Threading', 'System.Threading.Thread', 'System.Threading.ThreadPool',
            'System.Text.Encoding.Extensions')
    } else {
        $refs = @([System.IO.Ports.SerialPort].Assembly.Location)
    }
    Add-Type -ReferencedAssemblies $refs -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO.Ports;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SerBridge
{
    /// <summary>An RFC 2217 client with the members of SerialPort that
    /// scripts use. Settings may be changed before or after Open, as on a
    /// SerialPort; after Open each change is sent to the bridge, and one the
    /// port refuses throws.</summary>
    public class Port : IDisposable
    {
        const byte IAC = 255, DONT = 254, DO = 253, WONT = 252, WILL = 251, SB = 250, SE = 240;
        const byte BINARY = 0, ECHO = 1, SGA = 3, COM_PORT = 44;

        readonly string host;
        readonly int tcp;
        TcpClient client;
        NetworkStream stream;
        Thread reader;
        readonly object gate = new object();
        readonly object writeGate = new object();
        readonly Queue<byte> rx = new Queue<byte>();
        readonly Dictionary<int, byte[]> answers = new Dictionary<int, byte[]>();
        readonly bool[] we = new bool[256], they = new bool[256];
        volatile bool open;
        int modem;

        int baud = 9600, dataBits = 8;
        Parity parity = Parity.None;
        StopBits stopBits = StopBits.One;
        Handshake handshake = Handshake.None;
        bool dtr, rts, brk;

        public string PortName { get; private set; }
        public int ReadTimeout = -1;
        public int WriteTimeout = -1;
        public string NewLine = "\n";
        public Encoding Encoding = Encoding.ASCII;

        public Port(string url)
        {
            PortName = url;
            var u = new Uri(url);
            if (u.Scheme != "rfc2217") throw new ArgumentException("not an rfc2217:// URL: " + url);
            host = u.Host;
            tcp = u.Port;
        }

        public bool IsOpen { get { return open; } }

        public int BytesToRead { get { lock (gate) return rx.Count; } }

        public int BaudRate
        {
            get { return baud; }
            set { if (open) Ask(1, BigEndian(value), "baud rate " + value); baud = value; }
        }

        public int DataBits
        {
            get { return dataBits; }
            set { if (open) Ask(2, new[] { (byte)value }, "data bits " + value); dataBits = value; }
        }

        public Parity Parity
        {
            get { return parity; }
            set { if (open) Ask(3, new[] { ParityCode(value) }, "parity " + value); parity = value; }
        }

        public StopBits StopBits
        {
            get { return stopBits; }
            set { if (open) Ask(4, new[] { StopCode(value) }, "stop bits " + value); stopBits = value; }
        }

        public Handshake Handshake
        {
            get { return handshake; }
            set { if (open) Ask(5, new[] { FlowCode(value) }, "handshake " + value); handshake = value; }
        }

        public bool DtrEnable
        {
            get { return dtr; }
            set { if (open) Ask(5, new[] { (byte)(value ? 8 : 9) }, "DTR"); dtr = value; }
        }

        public bool RtsEnable
        {
            get { return rts; }
            set { if (open) Ask(5, new[] { (byte)(value ? 11 : 12) }, "RTS"); rts = value; }
        }

        public bool BreakState
        {
            get { return brk; }
            set { if (open) Ask(5, new[] { (byte)(value ? 5 : 6) }, "BREAK"); brk = value; }
        }

        public bool CtsHolding { get { return (modem & 0x10) != 0; } }
        public bool DsrHolding { get { return (modem & 0x20) != 0; } }
        public bool CDHolding { get { return (modem & 0x80) != 0; } }

        public void Open()
        {
            if (open) throw new InvalidOperationException("The port is already open.");
            client = new TcpClient();
            client.NoDelay = true;
            client.Connect(host, tcp);
            stream = client.GetStream();
            open = true;
            reader = new Thread(ReadLoop);
            reader.IsBackground = true;
            reader.Start();
            try
            {
                // Marked agreed BEFORE asking, so the bridge's answers, which
                // can arrive before Send returns, are not answered again.
                lock (gate)
                {
                    we[COM_PORT] = we[BINARY] = we[SGA] = true;
                    they[COM_PORT] = they[BINARY] = they[SGA] = true;
                }
                Send(new byte[] { IAC, WILL, COM_PORT, IAC, DO, COM_PORT, IAC, WILL, BINARY, IAC, DO, BINARY, IAC, WILL, SGA, IAC, DO, SGA });
                // The settings, then the lines: as SerialPort opens, DTR and
                // RTS stay deasserted unless the script asked for them.
                Ask(1, BigEndian(baud), "baud rate " + baud);
                Ask(2, new[] { (byte)dataBits }, "data bits " + dataBits);
                Ask(3, new[] { ParityCode(parity) }, "parity " + parity);
                Ask(4, new[] { StopCode(stopBits) }, "stop bits " + stopBits);
                Ask(5, new[] { FlowCode(handshake) }, "handshake " + handshake);
                Ask(5, new[] { (byte)(dtr ? 8 : 9) }, "DTR");
                Ask(5, new[] { (byte)(rts ? 11 : 12) }, "RTS");
                Ask(12, new byte[] { 3 }, "purge");
            }
            catch
            {
                Close();
                throw;
            }
        }

        public void Close()
        {
            open = false;
            try { if (stream != null) stream.Close(); } catch { }
            try { if (client != null) client.Close(); } catch { }
            lock (gate) Monitor.PulseAll(gate);
        }

        public void Dispose() { Close(); }

        public void Write(string text) { var b = Encoding.GetBytes(text); Write(b, 0, b.Length); }

        public void Write(char[] chars, int offset, int count)
        {
            var b = Encoding.GetBytes(chars, offset, count);
            Write(b, 0, b.Length);
        }

        public void Write(byte[] buffer, int offset, int count)
        {
            if (!open) throw new InvalidOperationException("The port is closed.");
            var esc = new List<byte>(count + 8);
            for (int i = 0; i < count; i++)
            {
                byte c = buffer[offset + i];
                esc.Add(c);
                if (c == IAC) esc.Add(IAC);
            }
            Send(esc.ToArray());
        }

        public void WriteLine(string text) { Write(text + NewLine); }

        public string ReadExisting()
        {
            byte[] b;
            lock (gate) { b = rx.ToArray(); rx.Clear(); }
            return Encoding.GetString(b);
        }

        public int ReadByte()
        {
            lock (gate)
            {
                WaitFor(delegate { return rx.Count > 0; }, ReadTimeout);
                return rx.Dequeue();
            }
        }

        public int Read(byte[] buffer, int offset, int count)
        {
            lock (gate)
            {
                WaitFor(delegate { return rx.Count > 0; }, ReadTimeout);
                int n = 0;
                while (n < count && rx.Count > 0) buffer[offset + n++] = rx.Dequeue();
                return n;
            }
        }

        public string ReadTo(string value)
        {
            var sb = new StringBuilder();
            DateTime end = ReadTimeout < 0 ? DateTime.MaxValue : DateTime.UtcNow.AddMilliseconds(ReadTimeout);
            while (true)
            {
                int left = ReadTimeout < 0 ? -1 : (int)Math.Max(0, (end - DateTime.UtcNow).TotalMilliseconds);
                int c;
                lock (gate)
                {
                    WaitFor(delegate { return rx.Count > 0; }, left);
                    c = rx.Dequeue();
                }
                sb.Append((char)c);
                if (sb.Length >= value.Length && sb.ToString(sb.Length - value.Length, value.Length) == value)
                    return sb.ToString(0, sb.Length - value.Length);
            }
        }

        public string ReadLine() { return ReadTo(NewLine); }

        public void DiscardInBuffer()
        {
            if (open) Ask(12, new byte[] { 1 }, "purge");
            lock (gate) rx.Clear();
        }

        public void DiscardOutBuffer() { if (open) Ask(12, new byte[] { 2 }, "purge"); }

        // ---- protocol ---------------------------------------------------

        delegate bool Ready();

        /// <summary>Waits on `gate` (held by the caller) until ready or the
        /// timeout, in ms (-1 waits forever).</summary>
        void WaitFor(Ready ready, int timeout)
        {
            DateTime end = timeout < 0 ? DateTime.MaxValue : DateTime.UtcNow.AddMilliseconds(timeout);
            while (!ready())
            {
                if (!open) throw new InvalidOperationException("The port is closed.");
                int left = timeout < 0 ? 1000 : (int)(end - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0) throw new TimeoutException("The operation has timed out.");
                Monitor.Wait(gate, Math.Min(left, 1000));
            }
        }

        void Send(byte[] b)
        {
            lock (writeGate)
            {
                if (WriteTimeout >= 0) stream.WriteTimeout = WriteTimeout;
                stream.Write(b, 0, b.Length);
            }
        }

        /// <summary>Sends a COM-PORT-OPTION request and waits for the answer,
        /// which must equal the request: the bridge answers a refused
        /// setting with the value still in effect.</summary>
        void Ask(int code, byte[] value, string what)
        {
            lock (gate) answers.Remove(code + 100);
            var msg = new List<byte> { IAC, SB, COM_PORT, (byte)code };
            foreach (byte b in value) { msg.Add(b); if (b == IAC) msg.Add(IAC); }
            msg.Add(IAC);
            msg.Add(SE);
            Send(msg.ToArray());
            byte[] got;
            lock (gate)
            {
                try { WaitFor(delegate { return answers.ContainsKey(code + 100); }, 3000); }
                catch (TimeoutException) { throw new TimeoutException("serbridge did not answer the request for " + what); }
                got = answers[code + 100];
            }
            if (got.Length < value.Length) throw new InvalidOperationException("serbridge refused " + what);
            for (int i = 0; i < value.Length; i++)
                if (got[i] != value[i]) throw new InvalidOperationException("serbridge refused " + what + " (see its log)");
        }

        void ReadLoop()
        {
            var buf = new byte[4096];
            var sub = new List<byte>();
            int state = 0; // 0 data, 1 IAC, 2 negotiate, 3 sub, 4 sub-IAC
            byte cmd = 0;
            try
            {
                while (open)
                {
                    int n = stream.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    lock (gate)
                    {
                        for (int i = 0; i < n; i++)
                        {
                            byte b = buf[i];
                            switch (state)
                            {
                                case 0:
                                    if (b == IAC) state = 1; else rx.Enqueue(b);
                                    break;
                                case 1:
                                    if (b == IAC) { rx.Enqueue(IAC); state = 0; }
                                    else if (b == SB) { sub.Clear(); state = 3; }
                                    else if (b == DO || b == DONT || b == WILL || b == WONT) { cmd = b; state = 2; }
                                    else state = 0;
                                    break;
                                case 2:
                                    Negotiate(cmd, b);
                                    state = 0;
                                    break;
                                case 3:
                                    if (b == IAC) state = 4; else sub.Add(b);
                                    break;
                                case 4:
                                    if (b == IAC) { sub.Add(IAC); state = 3; }
                                    else if (b == SE) { Subnegotiation(sub); state = 0; }
                                    else state = 0;
                                    break;
                            }
                        }
                        Monitor.PulseAll(gate);
                    }
                }
            }
            catch { }
            finally
            {
                open = false;
                lock (gate) Monitor.PulseAll(gate);
            }
        }

        /// <summary>Called with `gate` held. Agrees to what this client
        /// offered and refuses the rest, answering only a change of state.</summary>
        void Negotiate(byte c, byte opt)
        {
            bool ours = opt == BINARY || opt == SGA || opt == COM_PORT;
            bool theirs = ours || opt == ECHO;
            byte[] reply = null;
            if (c == DO) { if (!ours) reply = new[] { IAC, WONT, opt }; else if (!we[opt]) { we[opt] = true; reply = new[] { IAC, WILL, opt }; } }
            else if (c == DONT) { if (we[opt]) { we[opt] = false; reply = new[] { IAC, WONT, opt }; } }
            else if (c == WILL) { if (!theirs) reply = new[] { IAC, DONT, opt }; else if (!they[opt]) { they[opt] = true; reply = new[] { IAC, DO, opt }; } }
            else if (c == WONT) { if (they[opt]) { they[opt] = false; reply = new[] { IAC, DONT, opt }; } }
            if (reply != null) ThreadPool.QueueUserWorkItem(delegate { try { Send(reply); } catch { } });
        }

        void Subnegotiation(List<byte> sub)
        {
            if (sub.Count < 2 || sub[0] != COM_PORT) return;
            int code = sub[1];
            var value = sub.GetRange(2, sub.Count - 2).ToArray();
            if (code == 107 && value.Length > 0) modem = value[0];
            else answers[code] = value;
        }

        static byte[] BigEndian(int v) { return new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }; }

        static byte ParityCode(Parity p)
        {
            switch (p)
            {
                case Parity.Odd: return 2;
                case Parity.Even: return 3;
                case Parity.Mark: return 4;
                case Parity.Space: return 5;
                default: return 1;
            }
        }

        static byte StopCode(StopBits s)
        {
            switch (s)
            {
                case StopBits.Two: return 2;
                case StopBits.OnePointFive: return 3;
                default: return 1;
            }
        }

        static byte FlowCode(Handshake h)
        {
            switch (h)
            {
                case Handshake.XOnXOff: return 2;
                case Handshake.RequestToSend: return 3;
                default: return 1;
            }
        }
    }
}
'@
}

function Get-SerBridgeUrl {
    <#
    .SYNOPSIS
    The rfc2217:// URL of the serbridge holding a port, or $null.
    #>
    param([Parameter(Mandatory)][string]$PortName)
    $root = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:TEMP }
    $base = ($PortName -replace '^/dev/', '' -replace '[/\\:?]', '_').ToUpperInvariant()
    $file = Join-Path (Join-Path $root 'serbridge') "$base.url"
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    $url = (Get-Content -LiteralPath $file -TotalCount 1).Trim()
    if ($url -like 'rfc2217://*') { return $url }
    return $null
}

function New-SerBridgePort {
    <#
    .SYNOPSIS
    A port to open: through serbridge if one holds it, else the port itself.

    .DESCRIPTION
    Returns a SerBridge.Port connected to the bridge's RFC 2217 server when a
    bridge holds the port, otherwise a System.IO.Ports.SerialPort. Both start
    closed, with DTR and RTS deasserted, and take the same settings and calls
    (Open, Close, Write, ReadExisting, ReadByte, ReadTo, ReadLine,
    DiscardInBuffer, BytesToRead, ReadTimeout, BaudRate, Parity, DataBits,
    StopBits, Handshake, DtrEnable, RtsEnable, BreakState).

    PortName may also be an rfc2217:// URL.
    #>
    param(
        [Parameter(Mandatory)][string]$PortName,
        [int]$BaudRate = 9600,
        [System.IO.Ports.Parity]$Parity = [System.IO.Ports.Parity]::None,
        [int]$DataBits = 8,
        [System.IO.Ports.StopBits]$StopBits = [System.IO.Ports.StopBits]::One
    )
    $url = if ($PortName -like 'rfc2217://*') { $PortName } else { Get-SerBridgeUrl $PortName }
    if ($url) {
        $p = New-Object SerBridge.Port $url
    } else {
        $p = New-Object System.IO.Ports.SerialPort $PortName
    }
    $p.BaudRate = $BaudRate
    $p.Parity = $Parity
    $p.DataBits = $DataBits
    $p.StopBits = $StopBits
    return $p
}

Export-ModuleMember -Function New-SerBridgePort, Get-SerBridgeUrl
