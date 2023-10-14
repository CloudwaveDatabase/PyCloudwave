# Python implementation of the CloudwaveDB client-server protocol

from . import connections
from . import cursors
from .constants import CLIENT, COMMAND, CR, ER, FIELD_TYPE, SERVER_STATUS
from . import converters

from .protocol import (
    dump_packet,
    CloudwavePacket,
    OKPacketWrapper,
    EOFPacketWrapper,
    LoadLocalPacketWrapper,
)
from . import err, VERSION_STRING

class CloudwaveResult:
    def __init__(self, caller):   #connection, execType=0):
        """
        :type connection: Connection
        """

        if isinstance(caller, connections.Connection):
            conn = caller
        elif isinstance(caller, cursors.Cursor):
            conn = caller.connection
        else:
            raise err.OperationalError("Can not find connection handle.")

        self.requestType = caller.requestType
        self.execType = caller.execType
        self.encoding = conn.encoding

        self.affected_rows = 0
        self.insert_id = None
        self.server_status = None
        self.warning_count = 0
        self.message = None
        self.field_count = 0
        self.description = None
        self.rows = None
        self.has_next = None
        self.unbuffered_active = False

        self._data = conn._read_packet()
        self._position = 0

    def __del__(self):
        if self.unbuffered_active:
            self._finish_unbuffered_query()

    def read(self):
        r = None
        try:
            packet = CloudwavePacket(self._data)
            isOk = packet.read_uint8()
            self.packet_ok = isOk == 0x01
            r = False
            if self.packet_ok:
                if self.requestType == COMMAND.B_REQ_BUILD_CONNECTION:
                    r = self._read_firstResponse_packet(packet)
                elif self.requestType == COMMAND.CONNECTION_CREATE_STATEMENT:
                    r = self._read_statement_packet(packet)
                elif self.requestType == COMMAND.CLOSE_STATEMENT:
                    r = self._read_close_statement_packet(packet)
                elif self.requestType == COMMAND.EXECUTE_STATEMENT:
                    r = self._read_result_head_packet(packet)
                elif self.requestType == COMMAND.EXECUTE_BATCH:
                    pass
                elif self.requestType == COMMAND.EXECUTE_PREPARED_STATEMENT:
                    pass
                elif self.requestType == COMMAND.RESULT_SET_QUERY_NEXT:
                    r = self._read_result_packet(packet)
                elif self.requestType == COMMAND.GET_SERVER_VERSION:
                    r = self._read_ping_packet(packet)

                else: # 仅读一个字节
                    pass

            else:
                self.errorId = packet.read_length_coded_string().decode(self.encoding)
                self.errorMessage, self.errorDebugInfo = packet.read_length_coded_string().decode(self.encoding).split('\r\n', 1)
                if ':' in self.errorMessage:
                    s, self.errorMessage = self.errorMessage.split(':', 1)
                self.errorMessage = self.errorMessage.lstrip()
        finally:
            #self.connection = None
            pass
        del self._data
        return self.packet_ok

    def init_unbuffered_query(self):
        """
        :raise OperationalError: If the connection to the Cloudwave server is lost.
        :raise InternalError:
        """
        self.unbuffered_active = True
        packet = self.connection._read_packet()

        if packet.is_ok_packet():
            self._read_ok_packet(packet)
            self.unbuffered_active = False
            self.connection = None
        elif packet.is_load_local_packet():
            self._read_load_local_packet(packet)
            self.unbuffered_active = False
            self.connection = None
        else:
            self.field_count = packet.read_integer()
            self._get_descriptions(packet)

            # Apparently, CloudwaveDB picks this number because it's the maximum
            # value of a 64bit unsigned integer. Since we're emulating CloudwaveDB,
            # we set it to this instead of None, which would be preferred.
            self.affected_rows = 18446744073709551615

    def _read_ok_packet(self, packet):
        ok_packet = OKPacketWrapper(packet)
        self.affected_rows = ok_packet.affected_rows
        self.insert_id = ok_packet.insert_id
        self.server_status = ok_packet.server_status
        self.warning_count = ok_packet.warning_count
        self.message = ok_packet.message
        self.has_next = ok_packet.has_next

    def _read_load_local_packet(self, packet):
        if not self.connection._local_infile:
            raise RuntimeError(
                "**WARN**: Received LOAD_LOCAL packet but local_infile option is false."
            )
        load_packet = LoadLocalPacketWrapper(packet)
        sender = LoadLocalFile(load_packet.filename, self.connection)
        try:
            sender.send_data()
        except:
            self.connection._read_packet()  # skip ok packet
            raise

        ok_packet = self.connection._read_packet()
        if (
            not ok_packet.is_ok_packet()
        ):  # pragma: no cover - upstream induced protocol error
            raise err.OperationalError(
                CR.CR_COMMANDS_OUT_OF_SYNC,
                "Commands Out of Sync",
            )
        self._read_ok_packet(ok_packet)

    def _check_packet_is_eof(self, packet):
        if not packet.is_eof_packet():
            return False
        # TODO: Support CLIENT.DEPRECATE_EOF
        # 1) Add DEPRECATE_EOF to CAPABILITIES
        # 2) Mask CAPABILITIES with server_capabilities
        # 3) if server_capabilities & CLIENT.DEPRECATE_EOF: use OKPacketWrapper instead of EOFPacketWrapper
        wp = EOFPacketWrapper(packet)
        self.warning_count = wp.warning_count
        self.has_next = wp.has_next
        return True

    def _read_firstResponse_packet(self, packet):
        self._sessionTime = packet.read_integer(8)
        self._sessionSequence = packet.read_integer(8)
        self._sessionToken = packet.read_integer(8)
        return None

    def _read_ping_packet(self, packet):
        self._version = packet.read_length_coded_string().decode(self.encoding)
        self._buildtime = packet.read_length_coded_string().decode(self.encoding)

    def _read_close_statement_packet(self, packet):
        self._closedStatementId = packet.read_integer()

    def _read_statement_packet(self, packet):
        self._statementId = packet.read_integer()

    def _read_result_head_packet(self, packet):
        self.localSessionTime = packet.read_integer(8)
        self.localSessionSequence = packet.read_integer(8)
        self.stmtId = packet.read_integer()
        self.cursorId = packet.read_integer()
        self.affected_rows = packet.read_integer()  # 此处从服务器返回的数据总是0
        self.isQuery = packet.read_uint8()  # 为0表示后续不需要用命令 RESULT_SET_QUERY_NEXT(11) 取检索数据
        self.correlationName = packet.read_length_coded_bytes()
        self.field_count = packet.read_integer()

        n = 0
        description = []
        for i in range(self.field_count):
            name = packet.read_length_coded_bytes().decode(self.encoding)
            length = packet.read_integer()
            typeName = packet.read_length_coded_bytes().decode(self.encoding)
            decimals = packet.read_integer()
            colScale = packet.read_integer()
            className = packet.read_length_coded_bytes().decode(self.encoding)
            if name != "__WISDOM_AUTO_KEY__":
                description.append(tuple([name, length, typeName, decimals, colScale, className]))
                n += 1

        self.field_count = n
        self.description = tuple(description)
        return self.affected_rows

    def _read_result_packet(self, packet):
        if packet.read_uint8() == 0:
            self._rows = ()
            return None
        readFetchSize = packet.read_integer()
        rows = []
        for i in range(readFetchSize):
            row = []
            for j in range(self.field_count):
                if packet._position > 2200:
                    pass
                tp, r = packet.read_object()
                if tp == FIELD_TYPE.CLOUD_TYPE_ZONE_AUTO_SEQUENCE:
                    tp, r = packet.read_object()
                row.append(r)
            rows.append(tuple(row))

        self._rows = tuple(rows)
        return None

    def _read_rowdata_packet_unbuffered(self):
        # Check if in an active query
        if not self.unbuffered_active:
            return

        # EOF
        packet = self.connection._read_packet()
        if self._check_packet_is_eof(packet):
            self.unbuffered_active = False
            self.connection = None
            self.rows = None
            return

        row = self._read_row_from_packet(packet)
        self.affected_rows = 1
        self.rows = (row,)  # rows should tuple of row for Cloudwave-python compatibility.
        return row

    def _finish_unbuffered_query(self):
        # After much reading on the Cloudwave protocol, it appears that there is,
        # in fact, no way to stop Cloudwave from sending all the data after
        # executing a query, so we just spin, and wait for an EOF packet.
        while self.unbuffered_active:
            packet = self.connection._read_packet()
            if self._check_packet_is_eof(packet):
                self.unbuffered_active = False
                self.connection = None  # release reference to kill cyclic reference.

    def _read_row_from_packet(self, packet):
        row = []
        for encoding, converter in self.converters:
            try:
                data = packet.read_length_coded_string()
            except IndexError:
                # No more columns in this row
                # See https://github.com/PyCloudwave/PyCloudwave/pull/434
                break
            if data is not None:
                if encoding is not None:
                    data = data.decode(encoding)
                if DEBUG:
                    print("DEBUG: DATA = ", data)
                if converter is not None:
                    data = converter(data)
            row.append(data)
        return tuple(row)

    def _get_descriptions(self, packet):
        """Read a column descriptor packet for each column in the result."""
        self.fields = []
        self.converters = []
        use_unicode = self.connection.use_unicode
        conn_encoding = self.connection.encoding
        description = []
        #localSessionTime = self.connection._read_packet

        for i in range(self.field_count):
            self.name = packet.read_length_coded_string().decode(conn_encoding)
            self.length = packet.read_integer()
            self.typeName = packet.read_length_coded_bytes()
            self.decimals = packet.read_integer()
            self.colScale = packet.read_integer()
            self.className = packet.read_length_coded_bytes()

            #packet_type = ResultPacket
            #packet_type.

            #field = self.connection._read_packet(ResultPacket)
            self.fields.append(field)
            description.append(field.description())
            field_type = field.type_code
            if use_unicode:
                if field_type == FIELD_TYPE.JSON:
                    # When SELECT from JSON column: charset = binary
                    # When SELECT CAST(... AS JSON): charset = connection encoding
                    # This behavior is different from TEXT / BLOB.
                    # We should decode result by connection encoding regardless charsetnr.
                    # See https://github.com/PyCloudwave/PyCloudwave/issues/488
                    encoding = conn_encoding  # SELECT CAST(... AS JSON)
                elif field_type in TEXT_TYPES:
                    if field.charsetnr == 63:  # binary
                        # TEXTs with charset=binary means BINARY types.
                        encoding = None
                    else:
                        encoding = conn_encoding
                else:
                    # Integers, Dates and Times, and other basic data is encoded in ascii
                    encoding = "ascii"
            else:
                encoding = None
            converter = self.connection.decoders.get(field_type)
            if converter is converters.through:
                converter = None
            if DEBUG:
                print(f"DEBUG: field={field}, converter={converter}")
            self.converters.append((encoding, converter))

        eof_packet = self.connection._read_packet()
        assert eof_packet.is_eof_packet(), "Protocol error, expecting EOF"
        self.description = tuple(description)

