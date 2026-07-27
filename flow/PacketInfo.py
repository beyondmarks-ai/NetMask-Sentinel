from scapy.layers.inet import IP, UDP, TCP
import psutil
import threading
import time


_PROCESS_CACHE = {}
_PROCESS_CACHE_AT = 0.0
_PROCESS_CACHE_LOCK = threading.Lock()


def _process_for_ports(*ports):
    """Return a best-effort local process match using a short-lived connection cache."""
    global _PROCESS_CACHE, _PROCESS_CACHE_AT
    wanted = {int(port) for port in ports if port}
    if not wanted:
        return None, ''
    now = time.monotonic()
    with _PROCESS_CACHE_LOCK:
        if now - _PROCESS_CACHE_AT > 2.0:
            refreshed = {}
            try:
                for connection in psutil.net_connections(kind='inet'):
                    local = connection.laddr
                    local_port = getattr(local, 'port', None)
                    if local_port is None and isinstance(local, tuple) and len(local) > 1:
                        local_port = local[1]
                    if local_port and connection.pid:
                        try:
                            refreshed[int(local_port)] = (
                                int(connection.pid), psutil.Process(connection.pid).name()
                            )
                        except (psutil.Error, OSError):
                            continue
            except (psutil.Error, OSError):
                refreshed = {}
            _PROCESS_CACHE = refreshed
            _PROCESS_CACHE_AT = now
        for port in wanted:
            match = _PROCESS_CACHE.get(port)
            if match:
                return match
    return None, ''


flags = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
    'N': ''
}


class PacketInfo:
    def __init__(self):
        self.src = ""
        self.dest = ""
        self.src_port = 0
        self.dest_port = 0
        self.protocol = ''
        self.timestamp = 0

        self.PSH_flag = False
        self.FIN_flag = False
        self.SYN_flag = False
        self.ACK_flag = False
        self.URG_flag = False
        self.RST_flag = False

        self.payload_bytes = 0
        self.header_bytes = 0
        self.packet_size = 0
        self.win_bytes = 0

        self.fwd_id = ""
        self.bwd_id = ""

        self.pid = None
        self.p_name = ''


    def setSrc(self, p):
        self.src = p.getlayer(IP).src

    def getSrc(self):
        return self.src

    def setDest(self, p):
        self.dest = p.getlayer(IP).dst

    def getDest(self):
        return self.dest

    def setSrcPort(self, p):
        if p.haslayer(TCP):
            self.src_port = p.getlayer(TCP).sport
        elif p.haslayer(UDP):
            self.src_port = p.getlayer(UDP).sport


    def getSrcPort(self):
        return self.src_port

    def setDestPort(self, p):
        if p.haslayer(TCP):
            self.dest_port = p.getlayer(TCP).dport
        elif p.haslayer(UDP):
            self.dest_port = p.getlayer(UDP).dport
        if self.pid is None:
            self.pid, self.p_name = _process_for_ports(self.src_port, self.dest_port)

    def getPID(self):
        return self.pid

    def getPName(self):
        return self.p_name

    def getDestPort(self):
        return self.dest_port

    def setProtocol(self, p):
        if p.haslayer(TCP):
            self.protocol = 'TCP'
        if p.haslayer(UDP):
            self.protocol = 'UDP'

    def getProtocol(self):
        return self.protocol

    def setTimestamp(self, p):
        self.timestamp = p.time

    def getTimestamp(self):
        return self.timestamp

    def setPSHFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'PSH' in flag:
                self.PSH_flag = True

    def getPSHFlag(self):
        return self.PSH_flag

    def setFINFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'FIN' in flag:
                self.FIN_flag = True

    def getFINFlag(self):
        return self.FIN_flag

    def setSYNFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'SYN' in flag:
                self.SYN_flag = True

    def getSYNFlag(self):
        return self.SYN_flag

    def setACKFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'ACK' in flag:
                self.ACK_flag = True

    def getACKFlag(self):
        return self.ACK_flag

    def setURGFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'URG' in flag:
                self.URG_flag = True

    def getURGFlag(self):
        return self.URG_flag

    def setRSTFlag(self, p):
        if p.haslayer(TCP):
            tcp_flags = p[TCP].flags
            flag = [flags[x] for x in tcp_flags]
            if 'RST' in flag:
                self.RST_flag = True

    def getRSTFlag(self):
        return self.RST_flag

    def setPayloadBytes(self, p):
        if p.haslayer(TCP):
            self.payload_bytes = len(p[TCP].payload)
        if p.haslayer(UDP):
            self.payload_bytes = len(p[UDP].payload)

    def getPayloadBytes(self):
        return self.payload_bytes

    def setHeaderBytes(self, p):
        if p.haslayer(TCP):
            self.header_bytes = len(p[TCP]) - len(p[TCP].payload)
        if p.haslayer(UDP):
            self.header_bytes = len(p[UDP]) - len(p[UDP].payload)

    def getHeaderBytes(self):
        return self.header_bytes

    def setPacketSize(self, p):
        if p.haslayer(TCP):
            self.packet_size = len(p[TCP])
        if p.haslayer(UDP):
            self.packet_size = len(p[UDP])

    def getPacketSize(self):
        return self.packet_size

    def setWinBytes(self, p):
        if p.haslayer(TCP):
            self.win_bytes = int(p[TCP].window)

    def getWinBytes(self):
        return self.win_bytes

    def setFwdID(self):
        self.fwd_id = self.src + "-" + self.dest + "-" + \
                       str(self.src_port) + "-" + str(self.dest_port) + "-" + self.protocol

    def getFwdID(self):
        return self.fwd_id

    def setBwdID(self):
        self.bwd_id = self.dest + "-" + self.src + "-" + \
                      str(self.dest_port) + "-" + str(self.src_port) + "-" + self.protocol

    def getBwdID(self):
        return self.bwd_id