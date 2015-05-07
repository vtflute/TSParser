__author__ = 'xiao'

import io
import struct
import sys
import tkinter
import tkinter.messagebox
import tkinter.filedialog
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
                            ("value", c_uint),]

        def __init__(self, data):
                super(TSHeader, self).__init__()
                self.position = data.tell()
                self.raw = data.read(4)
                self.value = struct.unpack('I', self.raw)[0]

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
                    ("value", c_uint64),
                ]

                def __init__(self, data):
                        super(TSAdaptationField.PCR, self).__init__()
                        self.position = data.tell()
                        self.raw = data.read(6)
                        self.value = int.from_bytes(self.raw, byteorder='big')

        _anonymous_ = ("bits", )
        _fields_ = [
            ("bits", _AdaptationField),
            ("value", c_uint16)
        ]

        def	__init__(self, data):
                    super(TSAdaptationField, self).__init__()
                    self.position = data.tell()
                    self.raw = data.read(2)
                    self.value = struct.unpack("H", self.raw)[0]
                    self.optional_fields = io.BytesIO(data.read(self.adaptation_field_length - 1))
                    if  (self.PCR_flag == 1):
                        self.pcr = self.PCR(self.optional_fields)
                    if (self.OPCR_flag == 1):
                        self.opcr = self.PCR(self.optional_fields)


class TSPacket(object):

    def __init__(self, filehandle):
            self.postition = filehandle.tell()
            self.head = TSHeader(filehandle)
            if self.head.adaptation_field_ctrl & 0x2:
                        #Parse adapation_field data
                        self.adaption_field = TSAdaptationField(filehandle)
            if self.head.adaptation_field_ctrl & 0x1:
                        #Parse payload field data
                        self.payload_field


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