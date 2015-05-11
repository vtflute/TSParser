__author__ = 'xiao'

import io
import struct
import sys
from ctypes import *

class TSHeader(Union):
        class _TSHeader(BigEndianStructure):
                _fields_ =   [("syncByte", c_uint, 8),
                                    ("transport_error_indicator", c_uint, 1),
                                    ("payload_unit_start_indicator", c_uint, 1),
                                    ("transport_priority", c_uint, 1),
                                    ("pid", c_uint, 13),
                                    ("scrambling_control", c_uint, 2),
                                    ("adaptation_field_ctrl", c_uint, 2),
                                    ("continuity_counter", c_uint, 4)]

        _anonymous_ = ("bits",)
        _fields_ =   [("bits", _TSHeader),
                            ("int", c_uint),]

        def __init__(self, data):
                super(TSHeader, self).__init__()
                self.position = data.tell()
                self.raw = data.read(4)
                self.int = struct.unpack('I', self.raw)[0]

class TSAdaptationField(Union):
        class _AdaptationField(BigEndianStructure):
                _fields_ = [
                    ("adaptation_field_length", c_uint16, 8),
                    ("discontinuity_indicator", c_uint16, 1),
                    ("random_access_indicator", c_uint16 , 1),
                    ("elementary_stream_priority_indicator", c_uint16, 1),
                    ("PCR_flag", c_uint16, 1),
                    ("OPCR_flag", c_uint16, 1),
                    ("splicing_point_flag", c_uint16, 1),
                    ("transport_private_data_flag", c_uint16, 1),
                    ("adaptation_field_extension_flag", c_uint16, 1),
                ]

        class PCR(Union):
                class _PCR(BigEndianStructure):
                        _fields_ = [
                            ("pcr_base", c_uint64, 33),
                            ("pcr_padding", c_uint64, 6),
                            ("pcr_extension", c_uint64, 9),
                        ]
                _anonymous_ = ("bits",)
                _fields_ = [
                    ("bits", _PCR),
                    ("int", c_uint64),
                ]

                def __init__(self, data):
                        super(TSAdaptationField.PCR, self).__init__()
                        self.position = data.tell()
                        self.raw = data.read(6)
                        self.int = int.from_bytes(self.raw, byteorder='big')

        _anonymous_ = ("bits", )
        _fields_ = [
            ("bits", _AdaptationField),
            ("int", c_uint16)
        ]

        def __init__(self, data):
                    super(TSAdaptationField, self).__init__()
                    self.position = data.tell()
                    self.raw = data.read(2)
                    self.int = struct.unpack("H", self.raw)[0]
                    self.optional_fields = io.BytesIO(data.read(self.adaptation_field_length - 1))
                    if  (self.PCR_flag == 1):
                        self.pcr = self.PCR(self.optional_fields)
                    if (self.OPCR_flag == 1):
                        self.opcr = self.PCR(self.optional_fields)


class PTSPattern(Union):
        class _Pattern (Structure):
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
                self.int = int.from_bytes(self.raw, byteorder='big')
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
                        super(PES.MainStreamHeader, self).__init__();
                        self.position = data.tell()
                        self.raw = data.read(3)
                        self.int = int.from_bytes(self.raw, byteorder='big')
                        self.optional_fields = io.BytesIO(data.read(self.pes_header_data_length))       #including stuffing fields
                        self.parsePTS(self.optional_fields)

                        self.payload_length = self.pes_packet_length - self.pes_header_data_length
                        self.payload = io.BytesIO(data.read(self.payload_type))



        def __init__(self, data, payload_unit_start_indicator):
                super(PES, self).__init__()
                self.position = data.tell()
                self.raw = data.read(6)
                self.int = int.from_bytes(self.raw, byteorder='big')
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
                self.probe(data)

        def probe(self,data):
                prefix = int.from_bytes(data.read(4), byteorder='big')
                if prefix & 0x00000100:
                        return 'PES'
                else:
                        return "PSI"
                data.seek(-4, whence=io.SEEK_CUR)



class TSPacket(object):

    def __init__(self, filehandle):
            self.postition = filehandle.tell()
            self.head = TSHeader(filehandle)
            if self.head.adaptation_field_ctrl & 0x2:
                        #Parse adapation_field data
                        self.adaption_field = TSAdaptationField(filehandle)
            if self.head.adaptation_field_ctrl & 0x1:
                        #Parse payload field data
                        self.payload = TSPayloadFactory(filehandle, self.head.payload_unit_start_indicator)

##Following for Test
import tkinter
import tkinter.messagebox
import tkinter.filedialog

def getFilename():
    root=tkinter.Tk()
    fTyp=[('.ts File','*.ts'),('.TOD File','*.TOD'),('.trp File','*.trp'),('All Files','*.*')]
    iDir='~/'
    filename=tkinter.filedialog.askopenfilename(filetypes=fTyp,initialdir=iDir)
    root.destroy()
    return filename;

if __name__ == "__main__":

    filename = getFilename()
    filehandle =open(filename, 'rb')
    filehandle.seek(188*440)

    #For test
    packet = TSPacket(filehandle)