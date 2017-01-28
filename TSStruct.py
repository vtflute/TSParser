__author__ = 'xiao'

import io
import struct
import sys
from ctypes import *

def from_bytes(input_bytes, byteorder='big'):
    length = len(input_bytes)
    if byteorder == 'big':
        parts = struct.unpack((">%dB" % length), input_bytes)
        parts = parts[0:-1]
    elif byteorder == 'little':
        parts = struct.unpack(("<%dB" % length), input_bytes)
        parts = reversed(parts[0:-1])

    integer = 0
    for i in parts:
        integer = i * 256 + integer
    return integer


class PTSPattern(Union):

    class _Pattern(Structure):
        _fields_ = [
            ('prefix', c_int64, 4),
            ('pts1', c_int64, 3),
            ('marker', c_int64, 1),
            ('pts2', c_int64, 15),
            ('marker', c_int64, 1),
            ('pts3', c_int64, 15),
            ('marker', c_int64, 1),
            ]
    _anonymous_ = ('bits',)
    _fields_ = [
        ('bits', _Pattern),
        ('int', c_int64),
        ]

    def __int__(self, data):
        super(PTSPattern, self).__init__()
        self.position = data.tell()
        self.raw = data.read(5)
        self.int = from_bytes(self.raw, byteorder='big')
        self.value = self.pts3 + self.pts2 << 15 + self.pts1 << 30

class PES(Union):
    class _PES(Structure):
        _fields_ = [
            ('packet_start_code_prefix', c_int32, 24),
            ('stream_id', c_int32, 8),
            ('pes_packet_length', c_int16, 16),
            ]

    _anonymous_ = ("bits",)
    _fields_ = [
        ("bits", _PES),
        ("int", c_int64)
        ]

    def isPaddingStream(self):
        if self.stread_id == 0xBE:
            return True
        else:
            return False

    def isAuxillaryStream(self):
        if self.stread_id == 0xBC or    \
            self.stream_id == 0xBF or   \
            self.stream_id == 0xF0 or   \
            self.stream_id == 0xF1 or   \
            self.stream_id == 0xFF or   \
            self.stream_id == 0xF2 or   \
            self.stream_id == 0xF8:
            return True
        else:
            return False
    def isMainStream(self):
        if not (self.isPaddingStream() and self.isAuxillaryStream()):
            return  True
        else:
            return False

    class MainStream(Union):
        class _Header(Structure):
            _fields_ = [
                ('prefix', c_uint16, 2),
                ('pes_scrambling_control', c_int16, 2),
                ('pes_priority', c_int16, 1),
                ('data_alignment_indicator', c_int16, 1),
                ('copyright', c_int16, 1),
                ('original_or_copy', c_int16, 1),
                ('pts_dts_flag', c_int16, 2),
                ('escr_flag', c_int16, 1),
                ('es_rate_flag', c_int16, 1),
                ('esm_trick_mode_flag', c_int16, 1),
                ('additional_copy_info_flag', c_int16, 1),
                ('pes_crc_flag', c_int16, 1),
                ('pes_extension_flag', c_int16, 1),
                ('pes_header_data_length', c_int8, 8),
                ]
        _anonymous_ = ('bits', )
        _fields_ = [
            ('bits', _Header),
            ('int', c_int32),
            ]

        def parsePTS(self, data):
            if self.pts_dts_flag == 0x2:
                self.PTS = PTSPattern(data)
            elif self.pts_dts_flag == 0x3:
                self.PTS = PTSPattern(data)
                self.DTS = PTSPattern(data)
            elif self.pts_dts_flag == 0x1:
                print('pts_dts_flag 0x1')
            elif self.pts_dts_flag == 0x0:
                print('pts_dts_flag 0x0')

        def __init__(self, data):
            super(PES.MainStreamHeader, self).__init__()
            self.position = data.tell()
            self.raw = data.read(3)
            self.int = from_bytes(self.raw, byteorder='big')
            self.optional_fields = io.BytesIO(data.read(self.pes_header_data_length))       #including stuffing fields
            self.parsePTS(self.optional_fields)

            self.payload_length = self.pes_packet_length - self.pes_header_data_length
            self.payload = io.BytesIO(data.read(self.payload_type))



    def __init__(self, data, payload_unit_start_indicator):
        super(PES, self).__init__()
        self.position = data.tell()
        self.raw = data.read(6)
        self.int = from_bytes(self.raw, byteorder='big')
        #TODO not handle pes_packet_length == 0
        self.variable_fields = io.BytesIO(data.read(self.pes_packet_length))

        if self.isMainStream():
            self.type = 'MainStream'
            self.stream = self.MainStream(data)
        elif self.isAuxillaryStream():
            self.type = 'AuxillaryStream'
        elif self.isPaddingStream():
            self.type = 'PaddingStream'

class TSPayloadFactory(object):

    def __init__(self, data, payload_unit_start_indicator):
        super


    @classmethod
    def probe(data):
        prefix = from_bytes(data, byteorder='big')
        if prefix & 0x00000100:
            return 'PES'
        else:
            self.payload_type = 'PSI'

class TSHeader(Union):
    class _TSHeader(BigEndianStructure):
        _fields_ = [("syncByte", c_uint, 8),
                    ("transport_error_indicator", c_uint, 1),
                    ("payload_unit_start_indicator", c_uint, 1),
                    ("transport_priority", c_uint, 1),
                    ("pid", c_uint, 13),
                    ("scrambling_control", c_uint, 2),
                    ("adaptation_field_ctrl", c_uint, 2),
                    ("continuity_counter", c_uint, 4)]

    _anonymous_ = ("bits",)
    _fields_ = [("bits", _TSHeader),
                ("int", c_uint),]

    def __init__(self, data):
        super(TSHeader, self).__init__()
        self.int = struct.unpack('I', data)[0]

class TSAdaptationField(Union):
    class _AdaptationField(BigEndianStructure):
        _fields_ = [("adaptation_field_length", c_uint16, 8),
                    ("discontinuity_indicator", c_uint16, 1),
                    ("random_access_indicator", c_uint16, 1),
                    ("elementary_stream_priority_indicator", c_uint16, 1),
                    ("PCR_flag", c_uint16, 1),
                    ("OPCR_flag", c_uint16, 1),
                    ("splicing_point_flag", c_uint16, 1),
                    ("transport_private_data_flag", c_uint16, 1),
                    ("adaptation_field_extension_flag", c_uint16, 1),]

    class PCR(Union):
        class _PCR(BigEndianStructure):
            _fields_ = [("pcr_base", c_uint64, 33),
                        ("pcr_padding", c_uint64, 6),
                        ("pcr_extension", c_uint64, 9),]
        _anonymous_ = ("bits",)
        _fields_ = [("bits", _PCR),
                    ("int", c_uint64),]

        def __init__(self, data):
            super(TSAdaptationField.PCR, self).__init__()
            self.int = from_bytes(data, byteorder='big')

    _anonymous_ = ("bits", )
    _fields_ = [("bits", _AdaptationField),
                ("int", c_uint16)]

    def __init__(self, data):
        super(TSAdaptationField, self).__init__()
        field_offset = 0
        field_length = 2
        try:
            self.int = struct.unpack("H", data[field_offset: field_offset + field_length])[0]
        except struct.error:
            data[field_offset: field_offset + field_length]

        if  (self.PCR_flag == 1):

            field_offset = field_offset + field_length
            field_length = 6
            self.pcr = self.PCR(data[field_offset:field_offset + field_length])

        if (self.OPCR_flag == 1):
            field_offset = field_offset + field_length
            field_length = 6
            self.opcr = self.PCR(data[field_offset:field_offset + field_length])


class TSPacket(object):

    def parse(self):
        field_offset = 0
        field_length = 4
        self.head = TSHeader(self.data[field_offset: field_offset + field_length])

        if self.head.adaptation_field_ctrl & 0x2:
            #Parse adapation_field data
            field_offset = field_offset + field_length
            #field_length = struct.unpack(">B", self.data[field_offset])[0] + 1
            field_length = from_bytes(self.data[field_offset], byteorder='big') + 1
            self.adaption_field = TSAdaptationField(self.data[field_offset: field_offset + field_length])
        if self.head.adaptation_field_ctrl & 0x1:
            #Parse payload field data
            field_offset = field_offset + field_length
            self.payload = self.data[field_offset:]

    @classmethod
    def iterator(cls, data, packet_length):
        yield  TSPacket(data)


    def __init__(self, packet_data):
        self.packet_length = len(packet_data)
        self.data = packet_data
        self.parse()

class TSStream(object):

    def __init__(self):
        self.PIDMap = dict()


    def findSyncByte(self):
        seq = self.data.read(64*1024)
        offset = seq.find(b'G')
        #TODO how to dynamicly determine packet length
        return (offset, 188)

    def prepare(self):
        (begin, packet_length) = self.findSyncByte()
        self.data.seek(begin, io.SEEK_SET)
        self.packet_length = packet_length

    def locatePAT(self):
        for packet in TSPacket.iterator(self.data, self.packet_length):
            if packet.head.pid == 0:
                break

        return packet

    def read_packet_records(self, filehandle):
        """Read a whole Transport Stream Packet Out"""
        while True:
            packet = filehandle.read(self.packet_length)
            if not packet or len(packet) != self.packet_length:
                break

            yield packet

    def parse(self, filehandle):
        self.data = filehandle
        self.prepare()
        packets = map(lambda x: TSPacket(x), self.read_packet_records(self.data))
        for p in packets:
            pid = p.head.pid
            if pid not in self.PIDMap:
                self.PIDMap[pid] = [p]
            else:
                pkt_queue = self.PIDMap[pid]
                pkt_queue.append(p)
        print(self.PIDMap)


##Following for Test

def getFilename():
    filename = sys.argv[1]
    return filename

if __name__ == "__main__":

    filename = getFilename()
    filehandle = open(filename, 'rb')
    filehandle.seek(188*440)

    #For test
    stream = TSStream()
    stream.parse(filehandle)
