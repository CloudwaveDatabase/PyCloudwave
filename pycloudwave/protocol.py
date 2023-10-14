# Python implementation of low level CloudwaveDB client-server protocol

from .constants import FIELD_TYPE, SERVER_STATUS, COMMAND
from . import err

import struct
import sys
import time
from datetime import date, datetime

DEBUG = False

NULL_COLUMN = 251
UNSIGNED_CHAR_COLUMN = 251
UNSIGNED_SHORT_COLUMN = 252
UNSIGNED_INT24_COLUMN = 253
UNSIGNED_INT64_COLUMN = 254


def dump_packet(data):  # pragma: no cover
    def printable(data):
        if 32 <= data < 127:
            return chr(data)
        return "."

    try:
        print("packet length:", len(data))
        for i in range(1, 7):
            f = sys._getframe(i)
            print("call[%d]: %s (line %d)" % (i, f.f_code.co_name, f.f_lineno))
        print("-" * 66)
    except ValueError:
        pass
    dump_data = [data[i : i + 16] for i in range(0, min(len(data), 256), 16)]
    for d in dump_data:
        print(
            " ".join("{:02X}".format(x) for x in d)
            + "   " * (16 - len(d))
            + " " * 2
            + "".join(printable(x) for x in d)
        )
    print("-" * 66)
    print()


class CloudwavePacket:
    """Representation of a Cloudwave response packet.

    Provides an interface for reading/parsing the packet results.
    """

    __slots__ = ("_position", "_data")

    def __init__(self, data):
        self._position = 0
        self._data = data

    def get_all_data(self):
        return self._data

    def read(self, size):
        """Read the first 'size' bytes in packet and advance cursor past them."""
        result = self._data[self._position : (self._position + size)]
        if len(result) != size:
            error = (
                "Result length not requested length:\n"
                "Expected=%s.  Actual=%s.  Position: %s.  Data Length: %s"
                % (size, len(result), self._position, len(self._data))
            )
            if DEBUG:
                print(error)
                self.dump()
            raise AssertionError(error)
        self._position += size
        return result

    def read_all(self):
        """Read all remaining data in the packet.

        (Subsequent read() will return errors.)
        """
        result = self._data[self._position :]
        self._position = None  # ensure no subsequent read()
        return result

    def advance(self, length):
        """Advance the cursor in data buffer 'length' bytes."""
        new_position = self._position + length
        if new_position < 0 or new_position > len(self._data):
            raise Exception(
                "Invalid advance amount (%s) for cursor.  "
                "Position=%s" % (length, new_position)
            )
        self._position = new_position

    def rewind(self, position=0):
        """Set the position of the data buffer cursor to 'position'."""
        if position < 0 or position > len(self._data):
            raise Exception("Invalid position to rewind cursor to: %s." % position)
        self._position = position

    def get_bytes(self, position, length=1):
        """Get 'length' bytes starting at 'position'.

        Position is start of payload (first four packet header bytes are not
        included) starting at index '0'.

        No error checking is done.  If requesting outside end of buffer
        an empty string (or string shorter than 'length') may be returned!
        """
        return self._data[position : (position + length)]

    def read_int8(self):
        result = struct.unpack_from(">b", self._data, self._position)[0]
        self._position += 1
        return result

    def read_uint8(self):
        result = struct.unpack_from(">B", self._data, self._position)[0]
        self._position += 1
        return result

    def read_int16(self):
        result = struct.unpack_from(">h", self._data, self._position)[0]
        self._position += 2
        return result

    def read_uint16(self):
        result = struct.unpack_from(">H", self._data, self._position)[0]
        self._position += 2
        return result

    def read_int32(self):
        result = struct.unpack_from(">i", self._data, self._position)[0]
        self._position += 4
        return result

    def read_uint32(self):
        result = struct.unpack_from(">I", self._data, self._position)[0]
        self._position += 4
        return result

    def read_int64(self):
        result = struct.unpack_from(">q", self._data, self._position)[0]
        self._position += 8
        return result

    def read_uint64(self):
        result = struct.unpack_from(">Q", self._data, self._position)[0]
        self._position += 8
        return result

    def read_float(self):
        result = struct.unpack_from(">f", self._data, self._position)[0]
        self._position += 4
        return result
    
    def read_double(self):
        result = struct.unpack_from(">d", self._data, self._position)[0]
        self._position += 8
        return result

    def read_string(self):
        end_pos = self._data.find(b"\0", self._position)
        if end_pos < 0:
            return None
        result = self._data[self._position : end_pos]
        self._position = end_pos + 1
        return result

    def read_bytes(self, length):
        result = self._data[self._position : self._position+length]
        self._position += length
        return result

    def read_integer(self, column=4):
        """Read a column number from the data buffer.

        Length coded numbers can be anywhere from 1 to 9 bytes depending
        on the value of the first byte.
        """
        if column == 1:
            return self.read_int8()
        elif column == 2:
            return self.read_int16()
        elif column == 4:
            return self.read_int32()
        elif column == 8:
            return self.read_int64()
        return None

    def read_struct(self, fmt):
        s = struct.Struct(fmt)
        result = s.unpack_from(self._data, self._position)
        self._position += s.size
        return result

    def decimal_to_string(self, decimal, scale, returnstr=False):
        # decimal is int type
        dr = ''
        if scale > 0:
            if decimal < 0:
                dr = '-'
                decimal = - decimal
            ds = str(decimal)
            length = len(ds)
            if length <= scale:
                dr += '0.'
                if length < scale:
                    dr = dr + bytes(scale - length)
            else:
                dr = dr + ds[0:length-scale] + '.' + ds[length-scale:]

            if dr.count(".") > 0:  # 去除小数点后的 0
                l = len(dr) - 1
                while l >= 0 and dr[l] == '0':
                    l -= 1
                if dr[l] == '.':
                    l -= 1
                dr = dr[0 : l + 1]
            if returnstr == False or scale == 0:
                dr = eval(dr)
        else:
            if returnstr and scale > 0:
                dr = str(decimal)
            else:
                dr = decimal
        return dr

    def read_big_integer(self):
        if self.read_uint8() == 0:
            value = self.read_integer(8)
        else:
            n = self.read_int8()
            if n > 0:
                minus = False
                d = self.read_bytes(n)
                if (d[0] & 0x80):  # 处理负数
                    dd = b''
                    minus = True
                    i = n - 1
                    while i >= 0:
                        if minus:
                            d1 = bytes([0xff & (256 - d[i])])
                            if d1 != 0:
                                minus = False
                        else:
                            d1 = bytes([0xff ^ d[i]])
                        dd = d1 + dd
                        i -= 1
                    minus = True
                else:
                    dd = d
                value = 0
                for i in range(n):
                    value = value * 256 + dd[i]
                if minus:
                    value = -value
            else:
                value = None
        return value

    def read_length_coded_string(self):
        """Read a 'Length Coded String' from the data buffer.

        A 'Length Coded String' consists first of a length coded
        (unsigned, positive) integer represented in 1-9 bytes followed by
        that many bytes of binary data.  (For example "cat" would be "3cat".)
        """
        length = self.read_integer()
        if length is None:
            return None
        return self.read(length)

    def read_length_coded_bytes(self, nullFlag=True):
        if nullFlag:
            if self.read_uint8() != 0:
                return None
        length = self.read_integer()
        if length is None:
            return None
        return self.read(length)

    def read_ucs2_to_utf8(self):
        length = self.read_integer()
        if length is None:
            return None

        utf8 = b""
        pos_ucs2 = self._position
        size = 0
        for i in range(length):
            if self._data[pos_ucs2] == 0 and (self._data[pos_ucs2 + 1] & 0x80) == 0:
                utf8 += struct.pack(">B", self._data[pos_ucs2+1])
                pos_ucs2 += 2
            elif (self._data[pos_ucs2] & 0xf8) == 0:
                b1 = 0xc0 | ((self._data[pos_ucs2] & 0x07) << 2) | ((self._data[pos_ucs2+1] & 0xc0) >> 6)
                b2 = 0x80 | (self._data[pos_ucs2 + 1] & 0x3f)
                utf8 += struct.pack(">2B", b1, b2)
                pos_ucs2 += 2
            else:
                b1 = 0xe0 | (self._data[pos_ucs2] & 0xf0) >> 4
                b2 = 0x80 | ((self._data[pos_ucs2] & 0x0f) << 2) | ((self._data[pos_ucs2+1] & 0xc0) >> 6)
                b3 = 0x80 | (self._data[pos_ucs2+1] & 0x3f)
                utf8 += struct.pack(">3B", b1, b2, b3)
                pos_ucs2 += 2

        self._position = pos_ucs2
        return str(utf8, 'utf-8')

    #def Utf8ToUcs2(self):

    def read_object(self):
        if self.read_uint8() != 0:
            return [-1, None]

        tp = self.read_uint8()
        value = None
        scale = 0
        if tp == FIELD_TYPE.CLOUD_TYPE_SINGLE_CHAR:
            value = self.read_bytes(2)
        elif tp == FIELD_TYPE.CLOUD_TYPE_CHAR or tp == FIELD_TYPE.CLOUD_TYPE_VARCHAR:
            value = self.read_ucs2_to_utf8()

        elif tp == FIELD_TYPE.CLOUD_TYPE_SINGLE_BYTE:
            value = self.read_uint8()
        elif tp == FIELD_TYPE.CLOUD_TYPE_BINARY or tp == FIELD_TYPE.CLOUD_TYPE_VARBINARY:
            value = self.read_length_coded_string()

        elif tp == FIELD_TYPE.CLOUD_TYPE_INTEGER or tp == FIELD_TYPE.CLOUD_TYPE_TINY_INTEGER:
            value = self.read_integer()
        elif tp == FIELD_TYPE.CLOUD_TYPE_LONG or tp == FIELD_TYPE.CLOUD_TYPE_SMALL_INTEGER:
            value = self.read_integer(8)

        elif tp == FIELD_TYPE.CLOUD_TYPE_FLOAT:
            value = self.read_float()
        elif tp == FIELD_TYPE.CLOUD_TYPE_DOUBLE:
            value = self.read_double()
        elif tp == FIELD_TYPE.CLOUD_TYPE_DATE:
            t = self.read_integer()
            value = date(int(t / 10000),int((t % 10000) / 100 + 1),int(t % 100)).isoformat()

        elif tp == FIELD_TYPE.CLOUD_TYPE_TIMESTAMP or tp == FIELD_TYPE.CLOUD_TYPE_TIME:
            t = self.read_integer(8)
            d = str(t % 1000).zfill(3)
            value = time.strftime("%Y-%m-%d %H:%M:%S.", time.localtime(t / 1000)) + d

        elif tp == FIELD_TYPE.CLOUD_TYPE_BOOLEAN:
            value = self.read_uint8() != 0

        elif tp == FIELD_TYPE.CLOUD_TYPE_TINY_DECIMAL:
            value = self.read_integer(4)
            scale = self.read_integer(1)
            value = self.decimal_to_string(value, scale)
            #if scale > 0:
            #    value /= (10 ** scale)
        elif tp == FIELD_TYPE.CLOUD_TYPE_SMALL_DECIMAL:
            value = self.read_integer(8)
            scale = self.read_integer(1)
            value = self.decimal_to_string(value, scale)
            #if scale > 0:
            #    value /= (10 ** scale)
        elif tp == FIELD_TYPE.CLOUD_TYPE_BIG_DECIMAL:
            value = self.read_big_integer()
            scale = self.read_integer(1)
            value = self.decimal_to_string(value, scale, True)
            #if scale > 0:
            #    value /= (10 ** scale)
        elif tp == FIELD_TYPE.CLOUD_TYPE_BIG_INTEGER:
            value = self.read_big_integer()
            value = self.decimal_to_string(value, 0)

        elif tp == FIELD_TYPE.CLOUD_TYPE_ZONE_AUTO_SEQUENCE:
            t = self.read_integer(4)
            t = self.read_integer(8)

        elif tp == FIELD_TYPE.CLOUD_TYPE_JSON_OBJECT:
            jsonElementSize = self.read_integer(4)
            value = ''
            for i in range(jsonElementSize):
                key = self.read_length_coded_string()
                t, val = self.read_object()
                value += '{ \'%s\' : %s }' % (key, val)

        else:
            raise err.DataError("readObject field type(%d) can not be processed." % tp)

        return [tp, value]

    def is_ok_packet(self):
        # https://dev.cloudwave.com/doc/internals/en/packet-OK_Packet.html
        return self._data[0] == COMMAND.iOK and len(self._data) > 0

    def is_eof_packet(self):
        # http://dev.cloudwave.com/doc/internals/en/generic-response-packets.html#packet-EOF_Packet
        # Caution: \xFE may be LengthEncodedInteger.
        # If \xFE is LengthEncodedInteger header, 8bytes followed.
        return self._data[0] == 0xFE and len(self._data) < 9

    def is_auth_switch_request(self):
        # http://dev.cloudwave.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchRequest
        return self._data[0] == 0xFE

    def is_extra_auth_data(self):
        # https://dev.cloudwave.com/doc/internals/en/successful-authentication.html
        return self._data[0] == 1

    def is_resultset_packet(self):
        field_count = self._data[0]
        return 1 <= field_count <= 250

    def is_load_local_packet(self):
        return self._data[0] == 0xFB

    def is_error_packet(self):
        return self._data[0] == COMMAND.iERR

    def check_error(self):
        if self.is_error_packet():
            self.raise_for_error()

    def raise_for_error(self):
        self.rewind()
        self.advance(1)  # field_count == error (we already know that)
        errno = self.read_uint16()
        if DEBUG:
            print("errno =", errno)
        err.raise_cloudwave_exception(self._data)

    def dump(self):
        dump_packet(self._data)

class OKPacketWrapper:
    """
    OK Packet Wrapper. It uses an existing packet object, and wraps
    around it, exposing useful variables while still providing access
    to the original packet objects variables and methods.
    """

    def __init__(self, from_packet):
        if not from_packet.is_ok_packet():
            raise ValueError(
                "Cannot create "
                + str(self.__class__.__name__)
                + " object from invalid packet type"
            )

        self.packet = from_packet
        self.packet.advance(1)

        self.affected_rows = self.packet.read_integer()
        self.insert_id = self.packet.read_integer()
        self.server_status, self.warning_count = self.read_struct("<HH")
        self.message = self.packet.read_all()
        self.has_next = self.server_status & SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS

    def __getattr__(self, key):
        return getattr(self.packet, key)


class EOFPacketWrapper:
    """
    EOF Packet Wrapper. It uses an existing packet object, and wraps
    around it, exposing useful variables while still providing access
    to the original packet objects variables and methods.
    """

    def __init__(self, from_packet):
        if not from_packet.is_eof_packet():
            raise ValueError(
                f"Cannot create '{self.__class__}' object from invalid packet type"
            )

        self.packet = from_packet
        self.warning_count, self.server_status = self.packet.read_struct("<xhh")
        if DEBUG:
            print("server_status=", self.server_status)
        self.has_next = self.server_status & SERVER_STATUS.SERVER_MORE_RESULTS_EXISTS

    def __getattr__(self, key):
        return getattr(self.packet, key)


class LoadLocalPacketWrapper:
    """
    Load Local Packet Wrapper. It uses an existing packet object, and wraps
    around it, exposing useful variables while still providing access
    to the original packet objects variables and methods.
    """

    def __init__(self, from_packet):
        if not from_packet.is_load_local_packet():
            raise ValueError(
                f"Cannot create '{self.__class__}' object from invalid packet type"
            )

        self.packet = from_packet
        self.filename = self.packet.get_all_data()[1:]
        if DEBUG:
            print("filename=", self.filename)

    def __getattr__(self, key):
        return getattr(self.packet, key)
