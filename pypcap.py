from struct import unpack


class PcapHGlobalHeader(object):
    def __init__(self, header):
        LITTLE_ENDIAN_MAGIC_NUMBER = 0xa1b2c3d4    # little endian

        self.global_header = unpack('<IHHiIII', header)

        if self.global_header[0] == LITTLE_ENDIAN_MAGIC_NUMBER:
            self.endian = '<'
        else:
            self.endian = '>'

        self.version_major = self.global_header[1]
        self.version_minor = self.global_header[2]
        self.thiszone = self.global_header[3]
        self.sigfigs = self.global_header[4]
        self.snaplen = self.global_header[5]
        self.network = self.global_header[6]


class PcapPacketHeader(object):
    def __init__(self, packet, endian='<'):
        self._packet_header = unpack(endian + 'IIII', packet)

        self.ts_sec = self._packet_header[0]
        self.ts_usec = self._packet_header[1]
        self.incl_len = self._packet_header[2]
        self.orig_len = self._packet_header[3]


class Packet(object):
    def __init__(self, header, payload, endian='<'):
        self.header = header
        self.payload = payload


class PcapReader(object):
    def __init__(self, file_name):
        PCAP_GLOBAL_HEADER_SiZE = 24
        PACKET_HEADER_SIZE = 16

        with open(file_name, 'br') as f:
            global_header = PcapHGlobalHeader(f.read(PCAP_GLOBAL_HEADER_SiZE))

            # print(global_header.endian, global_header.version_major, global_header.version_minor, global_header.thiszone, global_header.sigfigs, global_header.snaplen, global_header.network)

            self.packets = []

            while True:
                buffer = f.read(PACKET_HEADER_SIZE)

                if buffer == b'':
                    break

                packet_header = PcapPacketHeader(buffer, global_header.endian)

                # body = f.read(packet_header.incl_len)
                # print(f'idx: {pcap_idx:x} header: {buffer.hex()} body: {body.hex()[0:24]}')

                self.packets.append(Packet(packet_header, f.read(packet_header.incl_len)))




if __name__ == '__main__':
    fname = 'test.pcap'

    pcap = PcapReader(fname)

    print(pcap.packets[2].payload.hex())
