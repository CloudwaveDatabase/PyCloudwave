# Python implementation of the CloudwaveDB client-server protocol

import struct
import warnings

from . import _auth
from . import connections
from . import cursors

from . processresults import CloudwaveResult

from .constants import CLIENT, COMMAND, CR, ER, FIELD_TYPE, SERVER_STATUS
from .protocol import (
    dump_packet,
    CloudwavePacket,
    OKPacketWrapper,
    EOFPacketWrapper,
    LoadLocalPacketWrapper,
)
from . import err, VERSION_STRING

try:
    import ssl

    SSL_ENABLED = True
except ImportError:
    ssl = None
    SSL_ENABLED = False

try:
    import getpass

    DEFAULT_USER = getpass.getuser()
    del getpass
except (ImportError, KeyError):
    # KeyError occurs when there's no entry in OS database for a current user.
    DEFAULT_USER = None

DEBUG = False

TEXT_TYPES = {
    FIELD_TYPE.BIT,
    FIELD_TYPE.BLOB,
    FIELD_TYPE.LONG_BLOB,
    FIELD_TYPE.MEDIUM_BLOB,
    FIELD_TYPE.STRING,
    FIELD_TYPE.TINY_BLOB,
    FIELD_TYPE.VAR_STRING,
    FIELD_TYPE.VARCHAR,
    FIELD_TYPE.GEOMETRY,
}

MAX_PACKET_LEN = 2**24 - 1
SELECT_GET_MAX_RECORD = 1000


def _pack_int32(n):
    return struct.pack(">I", n)[:4]

class Operation:
    """
    Representation of a socket with a cloudwaveDB server.

    The proper way to get an instance of this class is to call
    connect().

    Establish a connection to the cloudwave database. Accepts several
    arguments:

    :param host: Host where the database server is located.
    :param user: Username to log in as.
    :param password: Password to use.
    :param database: Database to use, None to not use a particular one.
    :param port: cloudwaveDB port to use, default is usually OK. (default: 3306)
    :param bind_address: When the client has multiple network interfaces, specify
        the interface from which to connect to the host. Argument can be
        a hostname or an IP address.
    :param unix_socket: Use a unix socket rather than TCP/IP.
    :param read_timeout: The timeout for reading from the connection in seconds (default: None - no timeout)
    :param write_timeout: The timeout for writing to the connection in seconds (default: None - no timeout)
    :param charset: Charset to use.
    :param sql_mode: Default SQL_MODE to use.
    :param read_default_file:
        Specifies  my.cnf file to read these parameters from under the [client] section.
    :param conv:
        Conversion dictionary to use instead of the default one.
        This is used to provide custom marshalling and unmarshalling of types.
        See converters.
    :param use_unicode:
        Whether or not to default to unicode strings.
        This option defaults to true.
    :param client_flag: Custom flags to send to cloudwaveDB. Find potential values in constants.CLIENT.
    :param cursorclass: Custom cursor class to use.
    :param init_command: Initial SQL statement to run when connection is established.
    :param connect_timeout: The timeout for connecting to the database in seconds.
        (default: 10, min: 1, max: 31536000)
    :param ssl: A dict of arguments similar to cloudwave_ssl_set()'s parameters or an ssl.SSLContext.
    :param ssl_ca: Path to the file that contains a PEM-formatted CA certificate.
    :param ssl_cert: Path to the file that contains a PEM-formatted client certificate.
    :param ssl_disabled: A boolean value that disables usage of TLS.
    :param ssl_key: Path to the file that contains a PEM-formatted private key for the client certificate.
    :param ssl_verify_cert: Set to true to check the server certificate's validity.
    :param ssl_verify_identity: Set to true to check the server's identity.
    :param read_default_group: Group to read from in the configuration file.
    :param autocommit: Autocommit mode. None means use server default. (default: False)
    :param local_infile: Boolean to enable the use of LOAD DATA LOCAL command. (default: False)
    :param max_allowed_packet: Max size of packet sent to server in bytes. (default: 16MB)
        Only used to limit size of "LOAD LOCAL INFILE" data packet smaller than default (16KB).
    :param defer_connect: Don't explicitly connect on construction - wait for connect call.
        (default: False)
    :param auth_plugin_map: A dict of plugin names to a class that processes that plugin.
        The class will take the Connection object as the argument to the constructor.
        The class needs an authenticate method taking an authentication packet as
        an argument.  For the dialog plugin, a prompt(echo, prompt) method can be used
        (if no authenticate method) for returning a string from the user. (experimental)
    :param server_public_key: SHA256 authentication plugin public key value. (default: None)
    :param binary_prefix: Add _binary prefix on bytes and bytearray. (default: False)
    :param db: **DEPRECATED** Alias for database.
    :param passwd: **DEPRECATED** Alias for password.
    :sessionTime:
    :sessionSequence:
    :sessionToken:

    See `Connection <https://www.python.org/dev/peps/pep-0249/#connection-objects>`_ in the
    specification.
    """

    def __init__(self):
        charset="",
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        del exc_info
        #self.close()

    def _get_conn(self):
        if isinstance(self, connections.Connection):
            conn = self
        elif isinstance(self, cursors.Cursor):
            conn = self.connection
        else:
            conn = None
        return conn

    def readResult(self):
        result = CloudwaveResult(self)
        if isinstance(self, cursors.Cursor) and "_result" in vars(self) and self._result:
            result.field_count = self._result.field_count
        result.read()
        return result

    def createStatement(self):
        conn = Operation._get_conn(self)
        self.requestType = COMMAND.CONNECTION_CREATE_STATEMENT
        data = Operation.setCommandPacket(self, self.requestType, 25)
        conn._write_bytes(data)
        result = Operation.readResult(self)
        return result._statementId

    def closeStatement(self):
        conn = Operation._get_conn(self)
        data = struct.pack(">i", self.statementId)
        self.requestType = COMMAND.CLOSE_STATEMENT
        data = Operation.setCommandPacket(self, self.requestType, 29) + data
        conn._write_bytes(data)
        result = Operation.readResult(self)
        return result._closedStatementId

    # The following methods are INTERNAL USE ONLY (called from Cursor)
    def query(self, sql, unbuffered=False):
        # if DEBUG:
        #     print("DEBUG: sending query:", sql)
        conn = Operation._get_conn(self)
        #if isinstance(sql, str):
        #    sql = sql.encode(conn.encoding, "surrogateescape")
        Operation._execute_command(conn, self.execType, sql)
        self.requestType = COMMAND.EXECUTE_STATEMENT
        r = Operation._read_query_result(self, unbuffered=unbuffered)
        return r

    def next_result(self, unbuffered=False):
        self._affected_rows = self._read_query_result(unbuffered=unbuffered)
        return self._affected_rows

    def affected_rows(self):
        return self._affected_rows

    def sendFirstPacketToServer(self):
        """Writes an entire "cloudwave packet" in its entirety to the network
        adding its length and sequence number.
        """
        # Internal note: when you build packet manually and calls _write_bytes()
        # directly, you should set self._next_seq_id properly.

        encPwd = _auth.sha1_secret_bytes(self.password)
        timeZoneId = b"Asia/Shanghai"

        data_len = 1 + 4 + 4 + 4 * 3 + len(self.user) + len(encPwd) + len(timeZoneId)
        data = struct.pack(">B2i", COMMAND.B_REQ_TAG, data_len - 5, COMMAND.B_REQ_BUILD_CONNECTION)
        data += struct.pack(">i", len(self.user)) + self.user.encode("utf-8")
        data += struct.pack(">i", len(encPwd)) + encPwd
        data += struct.pack(">i", len(timeZoneId)) + timeZoneId
        if DEBUG:
            dump_packet(data)
        self._write_bytes(data)
        self.requestType = COMMAND.B_REQ_BUILD_CONNECTION
        result = Operation.readResult(self)
        return [result._sessionTime, result._sessionSequence, result._sessionToken]

    def getRecords(self):
        conn = Operation._get_conn(self)
        data_len = 25 + 4 * 3
        data = struct.pack(">3i", self.stmtId, self.cursorId, SELECT_GET_MAX_RECORD)
        self.requestType = COMMAND.RESULT_SET_QUERY_NEXT
        data = Operation.setCommandPacket(self, self.requestType, data_len) + data
        conn._write_bytes(data)
        result = Operation.readResult(self)
        self._rows = result._rows
        return len(self._rows)

    def _read_query_result(self, unbuffered=False):
        # self is Cursor

        self._result = None
        if unbuffered:
            try:
                result = CloudwaveResult(self)
                result.init_unbuffered_query()
            except:
                result.unbuffered_active = False
                result.connection = None
                raise
        else:
            result = CloudwaveResult(self)
            result.read()
        self._result = result
        if result.packet_ok:
            self._affected_rows = result.affected_rows
            if result.isQuery:
                self.stmtId = result.stmtId
                self.cursorId = result.cursorId

        if result.server_status is not None:
            self.server_status = result.server_status
        return result.affected_rows

    def insert_id(self):
        if self._result:
            return self._result.insert_id
        else:
            return 0

    def setCommandPacket(self, command, length):
        if isinstance(self, connections.Connection):
            head_packet = struct.pack(">B2i2Q", COMMAND.B_REQ_TAG, length-5, command, self.sessionTime, self.sessionSequence)
        elif isinstance(self, cursors.Cursor):
            head_packet = struct.pack(">B2i2Q", COMMAND.B_REQ_TAG, length-5, command, self.connection.sessionTime, self.connection.sessionSequence)
        else:
            pass
        return head_packet

    def _execute_command(self, command, sql):
        """
        :raise InterfaceError: If the connection is closed.
        :raise ValueError: If no username was specified.
        """
        if not self._sock:
            raise err.InterfaceError(0, "")

        # If the last query was unbuffered, make sure it finishes before
        # sending new commands
        if self._result is not None:
            if self._result.unbuffered_active:
                warnings.warn("Previous unbuffered result was left incomplete")
                self._result._finish_unbuffered_query()
            while self._result.has_next:
                self.next_result()
            self._result = None

        if isinstance(sql, str):
            sql = sql.encode(self.encoding)

        sql_len = len(sql)
        data_len = 25 + 4 * 2 + 4 + sql_len + 4 * 2
        data = struct.pack(">2i", self.pcursor.statementId, self.pcursor.executeSequence)
        self.pcursor.executeSequence += 1
        data += struct.pack(">i", sql_len) + sql
        data += struct.pack(">2i", command, 2)

        self.requestType = COMMAND.EXECUTE_STATEMENT
        data = Operation.setCommandPacket(self, self.requestType, data_len) + data
        self._write_bytes(data)

        if DEBUG:
            dump_packet(data)
        self._next_seq_id = 1

        if data_len < MAX_PACKET_LEN:
            return

    Warning = err.Warning
    Error = err.Error
    InterfaceError = err.InterfaceError
    DatabaseError = err.DatabaseError
    DataError = err.DataError
    OperationalError = err.OperationalError
    IntegrityError = err.IntegrityError
    InternalError = err.InternalError
    ProgrammingError = err.ProgrammingError
    NotSupportedError = err.NotSupportedError
