__author__ = 'xiao'

import io
import struct
import sys
from ctypes import *

def _from_bytes(input_bytes, byteorder='big'):
    length = len(input_bytes)
    if byteorder == 'big':
        parts = struct.unpack((">%dB" % length), input_bytes)
        parts = parts[0 : length]
    elif byteorder == 'little':
        parts = struct.unpack(("<%dB" % length), input_bytes)
        parts = reversed(parts[0: length])
    return parts

def integer_from_bytes(input_bytes, byteorder='big'):
    integer = 0
    parts = _from_bytes(input_bytes, byteorder)
    for i in parts:
        integer = i + (integer << 8)
    return integer


class PTSPattern(Union):
    class _Pattern(BigEndianStructure):
        _fields_ = [
            ('prefix', c_uint, 4),
            ('pts1', c_uint, 3),
            ('marker', c_uint, 1),
            ('pts2', c_uint, 15),
            ('marker', c_uint, 1),
            ('pts3', c_uint, 15),
            ('marker', c_uint, 1),]
    _anonymous_ = ('bits',)
    _pattern_type = c_uint8 * 5
    _fields_ = [('bits', _Pattern),
                ('int', _pattern_type)]
    pattern_length = 5

    def __init__(self, data):
        super(PTSPattern, self).__init__()
        ins = _from_bytes(data, byteorder='big')
        self.int = PTSPattern._pattern_type(*ins)
        self.value = self.pts3 + (self.pts2 << 15) + (self.pts1 << 30)

class ESCRPattern(Union):
    class _Pattern(BigEndianStructure):
        _fields_ = [
            ('reserved', c_uint, 2),
            ('ESCR_base0', c_uint, 3),
            ('marker_bit0', c_uint, 1),
            ('ESCR_base1', c_uint, 15),
            ('marker_bit1', c_uint, 1),
            ('ESCR_base2', c_uint, 15),
            ('marker_bit2', c_uint, 1),
            ('ESCR_extension', c_uint, 9),
            ('marker_bit3', c_uint, 1),]
    _anonymous_ = ('bits',)
    _pattern_type = c_uint8 * 6
    _fields_ = [('bits', _Pattern),
                ('int', _pattern_type)]
    pattern_length = 6

    def __init__(self, data):
        super(ESCRPattern, self).__init__()
        ins = _from_bytes(data, byteorder='big')
        self.int = ESCRPattern._pattern_type(*ins)
        self.value = (self.ESCR_base0 << 30) + (self.ESCR_base1 << 15) + self.ESCR_base2

class ESratePattern(Union):
    class _Pattern(BigEndianStructure):
        _fields_ = [('marker_bit0', c_uint, 1),
                    ('ES_rate', c_uint, 22),
                    ('marker_bit1', c_uint, 1)]
    _anonymous_ = ('bits',)
    _pattern_type = c_uint8 * 3
    _fields_ = [('bits', _Pattern),
                ('int', _pattern_type)]
    pattern_length = 3

    def __init__(self, data):
        super(ESratePattern, self).__init__()
        ins = _from_bytes(data, byteorder='big')
        self.int = ESCRPattern._pattern_type(*ins)
        
class DSMTrickModePattern(object):
    class _ModePattern(Union):
        class _FastForwardPattern(BigEndianStructure):
            _fields_ = [('field_id', c_uint, 2),
                        ('intra_slice_refresh', c_uint, 1),
                        ('frequency_truncation', c_uint, 2)]
        class _SlowMotionPattern(BigEndianStructure):
            _fields_ = [('rep_cntrl', c_uint, 5),]
        class _FreezeFramePattern(BigEndianStructure):
            _fields_ = [('field_id', c_uint, 2),
                        ('reserved', c_uint, 3)]
        class _FastReversePattern(BigEndianStructure):
            _fields_ = [('field_id', c_uint, 2),
                        ('intra_slice_refresh', c_uint, 1),
                        ('frequency_truncation', c_uint, 2)]
        class _SlowReversePattern(BigEndianStructure):
            _fields_ = [('rep_cntrl', c_uint, 5)]
    
        _fields_ = [('fast_forward', _FastForwardPattern),
                    ('slow_motion', _SlowMotionPattern),
                    ('freeze_frame', _FreezeFramePattern),
                    ('fast_reverse', _FastReversePattern),
                    ('slow_reverse', _SlowReversePattern),
                    ('int', c_uint, 5)]
        def __init__(self, integer):
            super(DSMTrickModePattern._ModePattern, self).__init__()
            self.int = integer & 0x1F

    pattern_length = 1

    def __init__(self, data):
        super(DSMTrickModePattern, self).__init__()
        ins = _from_bytes(data, byteorder='big')
        self.trick_mode_control = ins & 0xE0
        self.trick_mode = DSMTrickModePattern._ModePattern(ins)

class PES(Union):
    class _PES(BigEndianStructure):
        _fields_ = [
            ('packet_start_code_prefix', c_uint, 24),
            ('stream_id', c_uint, 8),
            ('pes_packet_length', c_uint, 16),
            ]

    _anonymous_ = ("bits",)
    _prefix_type = c_uint8 * 6
    _fields_ = [
        ("bits", _PES),
        ("int", _prefix_type)
        ]

    def isPaddingStream(self):
        if self.stream_id == 0xBE:
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
        class _Header(BigEndianStructure):
            _fields_ = [
                ('prefix', c_uint, 2),
                ('pes_scrambling_control', c_uint, 2),
                ('pes_priority', c_uint, 1),
                ('data_alignment_indicator', c_uint, 1),
                ('copyright', c_uint, 1),
                ('original_or_copy', c_uint, 1),
                ('pts_dts_flag', c_uint, 2),
                ('escr_flag', c_uint, 1),
                ('es_rate_flag', c_uint, 1),
                ('esm_trick_mode_flag', c_uint, 1),
                ('additional_copy_info_flag', c_uint, 1),
                ('pes_crc_flag', c_uint, 1),
                ('pes_extension_flag', c_uint, 1),
                ('pes_header_data_length', c_uint, 8),]
        _anonymous_ = ('bits', )
        _header_type = c_uint8 * 3
        _fields_ = [
            ('bits', _Header),
            ('int', _header_type),
            ]

        def parsePTS(self, d):
            if self.pts_dts_flag == 0x2:
                data = d.read(PTSPattern.pattern_length)
                self.PTS = PTSPattern(data)
            elif self.pts_dts_flag == 0x3:
                data = d.read(PTSPattern.pattern_length)
                self.PTS = PTSPattern(data)
                data = d.read(PTSPattern.pattern_length)
                self.DTS = PTSPattern(data)
            elif self.pts_dts_flag == 0x1:
                print('pts_dts_flag 0x1 forbidden')

        def parseESCR(self, d):
            if self.escr_flag == 0x1:
                data = d.read(ESCRPattern.pattern_length)
                self.ESCR = ESCRPattern(data)

        def parseESrate(self, d):
            if self.es_rate_flag == 0x1:
                data = d.read(ESratePattern.pattern_length)
                self.ESrate = ESratePattern(data)

        def parseDSMTrickMode(self, d):
            if self.esm_trick_mode_flag == 0x1:
                data = d.read(DSMTrickModePattern.pattern_length)
                self.DSM_trick_mode = DSMTrickModePattern(data)

        def parseAdditionalCopyInfo(self, d):
            if self.additional_copy_info_flag == 0x1:
                self.additional_copy_info = integer_from_bytes(d.read(1))

        def parsePESCRC(self, d):
            if self.pes_crc_flag == 0x1:
                self.previous_PES_packet_CRC = integer_from_bytes(d.read(2))

        def parsePESextension(self, d):
            if self.pes_extension_flag == 0x1:
                print('parse PES extension')

        def parsePESHeaderData(self, d):
            data = d.read(self.pes_header_data_length)
            h = io.BytesIO(data)
            self.parsePTS(h)
            self.parseESCR(h)
            self.parseESrate(h)
            self.parseDSMTrickMode(h)
            self.parseAdditionalCopyInfo(h)
            self.parsePESextension(h)

        def __init__(self, data):
            super(PES.MainStream, self).__init__()
            self._header_length = 3
            self.pes_packet_length = len(data)
            d = io.BytesIO(data)
            ins = _from_bytes(d.read(self._header_length), byteorder='big')
            self.int = PES.MainStream._header_type(*ins)
            
            self.parsePESHeaderData(d)
            self.payload_length = self.pes_packet_length - self.pes_header_data_length
            self.payload = d.read(self.payload_length)

    def __init__(self, data):
        super(PES, self).__init__()
        self.prefix_length = 6
        d = io.BytesIO(data)
        ins = _from_bytes(d.read(self.prefix_length), byteorder='big')
        self.int = PES._prefix_type(*ins)
        if self.pes_packet_length == 0:
            pes_packet_length = -1
        else:
            pes_packet_length = self.pes_packet_length

        if self.isMainStream():
            self.type = 'MainStream'
            self.stream = self.MainStream(d.read(pes_packet_length))
        elif self.isAuxillaryStream():
            self.type = 'AuxillaryStream'
        elif self.isPaddingStream():
            self.type = 'PaddingStream'


class PAT(Union):
    class _PAT(BigEndianStructure):
        _fields_ = [("table_id", c_uint, 8),
                    ("section_syntax_indicator", c_uint, 1),
                    ("void_0", c_uint, 1),
                    ("reserved_0", c_uint, 2),
                    ("section_length", c_uint, 12),
                    ("transport_stream_id", c_uint, 16),
                    ("reserved_1", c_uint, 2),
                    ("version_number", c_uint, 5),
                    ("current_next_indicator", c_uint, 1),
                    ("section_number", c_uint, 8),
                    ("last_section_number", c_uint, 8)]
    _anonymous_ = ("bits",)
    _header_type = c_uint8 * 8
    _fields_ = [("bits", _PAT),
                ('int', _header_type)]
        
    def _get_program_info(self, d):
        length = self.section_length - 5 - 4
        program_info_size = 4
        for index in range(0, length, program_info_size):
            (program_number, pid) = struct.unpack(">HH", d.read(program_info_size))
            pid = pid & 0x1FFF
            self.program_list.append({"program_number":program_number, "pid":pid})
        self.CRC_32 = integer_from_bytes(d.read(4), byteorder='big')     

    def __init__(self, data):
        super(PAT, self).__init__()
        self.structure_length = 8
        d = io.BytesIO(data)
        pointer_field = struct.unpack(">B", d.read(1))[0]
        d.read(pointer_field)
        ins = _from_bytes(d.read(self.structure_length), byteorder='big')
        self.int = PAT._header_type(*ins)
        self.program_list = list()
        self._get_program_info(d)            

class PMT(Union):
    class _PMT(BigEndianStructure):
        _fields_ = [("table_id", c_uint, 8),
                    ("section_syntax_indicator", c_uint, 1),
                    ("void_0", c_uint, 1),
                    ("reserved_0", c_uint, 2),
                    ("section_length", c_uint, 12),
                    ("program_num", c_uint, 16),
                    ("reserved_1", c_uint, 2),
                    ("version_number", c_uint, 5),
                    ("current_next_indicator", c_uint, 1),
                    ("section_number", c_uint, 8),
                    ("last_section_number", c_uint, 8),
                    ("reserved_2", c_uint, 3),
                    ("PCR_PID", c_uint, 13),
                    ("reserved_3", c_uint, 4),
                    ("program_info_length", c_uint, 12)]
    _anonymous_ = ("bits",)
    _header_type = c_uint8 * 12
    _fields_ = [("bits", _PMT),
               ("int", _header_type)]

    def _get_ES_info(self, d):
        self.program_info = d.read(self.program_info_length)
        length = self.section_length - self.program_info_length - 9 - 4
        while length:
            (stream_type, elementary_PID, es_info_length) = struct.unpack_from(">BHH", d.read(5))
            elementary_PID = elementary_PID & 0x1FFF
            es_info_length = es_info_length & 0x0FFF
            es_info = d.read(es_info_length)
            self.es_list.append({'elementary_PID':elementary_PID, 'es_info_length':es_info_length, 'es_info':es_info})          
            length = length - 5 - es_info_length
        self.CRC_32 = integer_from_bytes(d.read(4), byteorder='big')

    def __init__(self, data):
        super(PMT, self).__init__()
        self.structure_length = 12
        d = io.BytesIO(data)
        pointer_field = struct.unpack(">B", d.read(1))[0]
        d.read(pointer_field)
        ins = _from_bytes(d.read(self.structure_length), byteorder='big')
        self.int = PMT._header_type(*ins)
        self.es_list = list()
        self._get_ES_info(d)

class TSPayloadFactory(object):
    "Generate Transport Stream PES or PSI based on payload"
    def __init__(self):
        super(TSPayloadFactory, self).__init__()
        self.workers = dict()
        self.pid_type_map = dict()
    
    class Worker(object):
        "Parse specific pid payload"
        def __init__(self, pid, start_indicator = False):
            self.pid = pid
            self.start_indicator = start_indicator
            self.type = ""
            self.cache = bytearray()
            self.queue = list()

        def parse(self):
            "Implement in subclass"
            raise NotImplementedError

        def feed(self, data, start_indicator = False):
            "Continue parsing and try to return a complete PES or PSI through feedback"
            if start_indicator == True:
                if not self.type:
                    self.type = self.probe(data)
                if len(self.cache) > 0:
                    self.parse()
                self.cache = data
            else:
                self.cache += data

        def feedback(self):
            "Try to return a complete PES or PSI"
            if len(self.queue) > 0:
                return self.queue.pop()

        def probe(data):
            prefix = data[0:4]
            if prefix & 0x00000100:
                return 'PES'
            else:
                return 'PSI'

    class PATWorker(Worker):
        def __init__(self, pid, payload_unit_start_indicator, report_callback, instance):
            super(TSPayloadFactory.PATWorker, self).__init__(pid, payload_unit_start_indicator)
            self.type = 'PAT'
            self.callback = report_callback
            self.factory_instance = instance

        def parse(self):
            item = PAT(self.cache)
            if item:
                info = list()
                for p in item.program_list:
                    if p['program_number'] == 0:
                        i = {"type":"NET", "pid":p["pid"]}
                    else:
                        i = {"type":"PMT", "pid":p["pid"]}
                    info.append(i)
                    self.callback(self.factory_instance, self.type, info)
                self.queue.append(item)

    class PMTWorker(Worker):
        def __init__(self, pid, payload_unit_start_indicator, report_callback, instance):
            super(TSPayloadFactory.PMTWorker, self).__init__(pid, payload_unit_start_indicator)
            self.type = 'PMT'
            self.callback = report_callback
            self.factory_instance = instance

        def parse(self):
            item = PMT(self.cache)
            if item:
                info = list()
                for es in item.es_list:
                    i = {"type":"PES", "pid":es["elementary_PID"]}
                    info.append(i)
                    self.callback(self.factory_instance, self.type, info)
                self.queue.append(item)

    class PESWorker(Worker):
        def __init__(self, pid, payload_unit_start_indicator):
            super(TSPayloadFactory.PESWorker, self).__init__(pid, payload_unit_start_indicator)
            self.type = 'PES'
        
        def parse(self):
            item = PES(self.cache)
            if item and item.packet_start_code_prefix == 1:
                self.queue.append(item)

    def dispatch_worker(self, pid, data, payload_unit_start_indicator, factory_instance):
        if pid == 0:
            worker = TSPayloadFactory.PATWorker(pid, payload_unit_start_indicator, TSPayloadFactory.report_callback, factory_instance)
            self.pid_type_map[pid] = 'PAT'
        elif pid == 1:
            print("found a Conditional Access Table packet")
        elif pid == 2:
            print("found a Transport Stream Description Table packet")
        elif pid == 0x1FFF:
            print("found a NULL packet")
    
        try:
            pid_type = self.pid_type_map[pid]            
        except KeyError:
            if data[0:3] == b'\x00\x00\x01' and payload_unit_start_indicator:
                worker = TSPayloadFactory.PESWorker(pid, payload_unit_start_indicator)
                self.pid_type_map[pid] = 'PES'
            else:
                print("About pid %d, info not found in previous packet" % (pid))
                worker = None
        else:
            if pid_type == "PMT":
                worker = TSPayloadFactory.PMTWorker(pid, payload_unit_start_indicator, TSPayloadFactory.report_callback, factory_instance)
            elif pid_type == "PES":
                worker = TSPayloadFactory.PESWorker(pid, payload_unit_start_indicator)
        #dispatch PMT and other workers here
        if worker:
            worker.feed(data, payload_unit_start_indicator)
        return worker
    
    def feed(self, pid, data, payload_unit_start_indicator):
        try:
            worker = self.workers[pid]
            worker.feed(data, payload_unit_start_indicator)
        except KeyError:
            worker = self.dispatch_worker(pid, data, payload_unit_start_indicator, self)
            if worker:
                self.workers[pid] = worker

    def feedback(self, pid):
        try:
            worker = self.workers[pid]
            return worker.feedback()
        except KeyError:
            return None

    def report_callback(self, src_type, info):
        if src_type == 'PAT' or src_type == 'PMT':
            for i in info:
                pid = i["pid"]
                try:
                    pid_type = self.pid_type_map[pid]
                except KeyError:
                    self.pid_type_map[pid] = i["type"]
                else:
                    if pid_type != i["type"]:
                        print("Duplicated pid for type %s and type %s" % (pid_type, i["type"]))

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
    _header_type = c_uint8 * 4
    _fields_ = [("bits", _TSHeader),
                ("int", _header_type),]
    header_length = 4

    def __init__(self, data):
        super(TSHeader, self).__init__()
        ins = _from_bytes(data, byteorder='big')
        self.int = TSHeader._header_type(*ins)

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
        _field_type = c_uint8 * 6
        _fields_ = [("bits", _PCR),
                    ("int", _field_type),]
        field_length = 6

        def __init__(self, data):
            super(TSAdaptationField.PCR, self).__init__()
            ins = _from_bytes(data, byteorder='big')
            self.int = TSAdaptationField.PCR._field_type(*ins)

    _anonymous_ = ("bits", )
    _field_type = c_uint8 * 2
    _fields_ = [("bits", _AdaptationField),
                ("int", _field_type)]
    field_length = 2

    def __init__(self, data):
        super(TSAdaptationField, self).__init__()
        d = io.BytesIO(data)
        ins = _from_bytes(d.read(TSAdaptationField.field_length), byteorder='big')
        self.int = TSAdaptationField._field_type(*ins)

        if (self.PCR_flag == 1):
            self.pcr = self.PCR(d.read(TSAdaptationField.PCR.field_length))

        if (self.OPCR_flag == 1):
            self.opcr = self.PCR(d.read(TSAdaptationField.PCR.field_length))


class TSPacket(object):

    def parse(self, data):
        d = io.BytesIO(data)
        self.head = TSHeader(d.read(TSHeader.header_length))
        if self.head.adaptation_field_ctrl & 0x2:
            #Parse adapation_field data
            field_length = integer_from_bytes(d.read(1), byteorder='big')
            self.adaption_field = TSAdaptationField(d.read(field_length))
        if self.head.adaptation_field_ctrl & 0x1:
            #Parse payload field data
            self.payload = d.read()

    @classmethod
    def iterator(cls, data, packet_length):
        yield  TSPacket(data)


    def __init__(self, packet_data):
        self.packet_length = len(packet_data)
        self.parse(packet_data)

class TSStream(object):

    def __init__(self):
        self.PIDMap = dict()
        self.payload_parser = TSPayloadFactory()


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
            self.payload_parser.feed(p.head.pid, p.payload, p.head.payload_unit_start_indicator)
            payload = self.payload_parser.feedback(p.head.pid)
            if payload:
                try:
                    queue = self.PIDMap[p.head.pid]
                    queue.append(payload)
                except KeyError as e:
                    self.PIDMap[p.head.pid] = [payload]

    def getPidManifest(self):
        return self.PIDMap.keys()

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
    pids = stream.getPidManifest()
    print(pids)