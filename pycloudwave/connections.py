# Python implementation of the CloudwaveDB client-server protocol

import errno
import os
import socket
import struct
import sys
import traceback
import warnings

from . import _auth

from .charset import charset_by_name, charset_by_id
from .constants import CLIENT, COMMAND, CR, ER, FIELD_TYPE, SERVER_STATUS
from . import converters
from .cursors import Cursor
from .operations import Operation
from .processresults import CloudwaveResult
from .optionfile import Parser
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

DEFAULT_CHARSET = "utf8mb4"

MAX_PACKET_LEN = 2**24 - 1


def _pack_int24(n):
    return struct.pack(">I", n)[:3]

def _pack_int32(n):
    return struct.pack(">I", n)[:4]

# https://dev.cloudwave.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
def _lenenc_int(i):
    if i < 0:
        raise ValueError(
            "Encoding %d is less than 0 - no representation in LengthEncodedInteger" % i
        )
    elif i < 0xFB:
        return bytes([i])
    elif i < (1 << 16):
        return b"\xfc" + struct.pack("<H", i)
    elif i < (1 << 24):
        return b"\xfd" + struct.pack("<I", i)[:3]
    elif i < (1 << 64):
        return b"\xfe" + struct.pack("<Q", i)
    else:
        raise ValueError(
            "Encoding %x is larger than %x - no representation in LengthEncodedInteger"
            % (i, (1 << 64))
        )


class Connection:
    """
    Representation of a socket with a cloudwave server.

    The proper way to get an instance of this class is to call
    connect().

    Establish a connection to the Cloudwave database. Accepts several
    arguments:

    :param host: Host where the database server is located.
    :param user: Username to log in as.
    :param password: Password to use.
    :param database: Database to use, None to not use a particular one.
    :param port: Cloudwave port to use, default is usually OK. (default: 3306)
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
    :param client_flag: Custom flags to send to Cloudwave. Find potential values in constants.CLIENT.
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

    _sock = None
    _auth_plugin_name = ""
    _closed = False
    _secure = False

    def __init__(
        self,
        *,
        user=None,  # The first four arguments is based on DB-API 2.0 recommendation.
        password="",
        host=None,
        database=None,
        unix_socket=None,
        port=0,
        charset="",
        sql_mode=None,
        read_default_file=None,
        conv=None,
        use_unicode=True,
        client_flag=0,
        cursorclass=Cursor,
        init_command=None,
        connect_timeout=10,
        read_default_group=None,
        autocommit=False,
        local_infile=False,
        max_allowed_packet=16 * 1024 * 1024,
        defer_connect=False,
        auth_plugin_map=None,
        read_timeout=None,
        write_timeout=None,
        bind_address=None,
        binary_prefix=False,
        program_name=None,
        server_public_key=None,
        ssl=None,
        ssl_ca=None,
        ssl_cert=None,
        ssl_disabled=None,
        ssl_key=None,
        ssl_verify_cert=None,
        ssl_verify_identity=None,
        passwd=None,  # deprecated
        db=None,  # deprecated
    ):
        self.sessionTime = None
        self.sessionSequence = None
        self.sessionToken = None
        self.pcursor = None
        self.requestType = 0
        self.execType = 0

        if db is not None and database is None:
            # We will raise warning in 2022 or later.
            # See https://github.com/PyCloudwave/PyCloudwave/issues/939
            # warnings.warn("'db' is deprecated, use 'database'", DeprecationWarning, 3)
            database = db
        if passwd is not None and not password:
            # We will raise warning in 2022 or later.
            # See https://github.com/PyCloudwave/PyCloudwave/issues/939
            # warnings.warn(
            #    "'passwd' is deprecated, use 'password'", DeprecationWarning, 3
            # )
            password = passwd

        self._local_infile = bool(local_infile)
        if self._local_infile:
            client_flag |= CLIENT.LOCAL_FILES

        if read_default_group and not read_default_file:
            if sys.platform.startswith("win"):
                read_default_file = "c:\\my.ini"
            else:
                read_default_file = "/etc/my.cnf"

        if read_default_file:
            if not read_default_group:
                read_default_group = "client"

            cfg = Parser()
            cfg.read(os.path.expanduser(read_default_file))

            def _config(key, arg):
                if arg:
                    return arg
                try:
                    return cfg.get(read_default_group, key)
                except Exception:
                    return arg

            user = _config("user", user)
            password = _config("password", password)
            host = _config("host", host)
            database = _config("database", database)
            unix_socket = _config("socket", unix_socket)
            port = int(_config("port", port))
            bind_address = _config("bind-address", bind_address)
            charset = _config("default-character-set", charset)
            if not ssl:
                ssl = {}
            if isinstance(ssl, dict):
                for key in ["ca", "capath", "cert", "key", "cipher"]:
                    value = _config("ssl-" + key, ssl.get(key))
                    if value:
                        ssl[key] = value

        self.ssl = False
        if not ssl_disabled:
            if ssl_ca or ssl_cert or ssl_key or ssl_verify_cert or ssl_verify_identity:
                ssl = {
                    "ca": ssl_ca,
                    "check_hostname": bool(ssl_verify_identity),
                    "verify_mode": ssl_verify_cert
                    if ssl_verify_cert is not None
                    else False,
                }
                if ssl_cert is not None:
                    ssl["cert"] = ssl_cert
                if ssl_key is not None:
                    ssl["key"] = ssl_key
            if ssl:
                if not SSL_ENABLED:
                    raise NotImplementedError("ssl module not found")
                self.ssl = True
                client_flag |= CLIENT.SSL
                self.ctx = self._create_ssl_ctx(ssl)

        self.host = host or "localhost"
        self.port = port or 3306
        if type(self.port) is not int:
            raise ValueError("port should be of type int")
        self.user = user or DEFAULT_USER
        self.password = password or b""
        if isinstance(self.password, str):
            self.password = self.password.encode("latin1")
        self.db = database
        self.unix_socket = unix_socket
        self.bind_address = bind_address
        if not (0 < connect_timeout <= 31536000):
            raise ValueError("connect_timeout should be >0 and <=31536000")
        self.connect_timeout = connect_timeout or None
        if read_timeout is not None and read_timeout <= 0:
            raise ValueError("read_timeout should be > 0")
        self._read_timeout = read_timeout
        if write_timeout is not None and write_timeout <= 0:
            raise ValueError("write_timeout should be > 0")
        self._write_timeout = write_timeout

        self.charset = charset or DEFAULT_CHARSET
        self.use_unicode = use_unicode

        self.encoding = charset_by_name(self.charset).encoding

        client_flag |= CLIENT.CAPABILITIES
        if self.db:
            client_flag |= CLIENT.CONNECT_WITH_DB

        self.client_flag = client_flag

        self.cursorclass = cursorclass

        self._result = None
        self._affected_rows = 0
        self.host_info = "Not connected"

        # specified autocommit mode. None means use server default.
        self.autocommit_mode = autocommit

        if conv is None:
            conv = converters.conversions

        # Need for CloudwaveDB compatibility.
        self.encoders = {k: v for (k, v) in conv.items() if type(k) is not int}
        self.decoders = {k: v for (k, v) in conv.items() if type(k) is int}
        self.sql_mode = sql_mode
        self.init_command = init_command
        self.max_allowed_packet = max_allowed_packet
        self._auth_plugin_map = auth_plugin_map or {}
        self._binary_prefix = binary_prefix
        self.server_public_key = server_public_key

        self._connect_attrs = {
            "_client_name": "pycloudwave",
            "_pid": str(os.getpid()),
            "_client_version": VERSION_STRING,
        }

        if program_name:
            self._connect_attrs["program_name"] = program_name

        if defer_connect:
            self._sock = None
        else:
            self.connect()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        del exc_info
        self.close()

    def _create_ssl_ctx(self, sslp):
        if isinstance(sslp, ssl.SSLContext):
            return sslp
        ca = sslp.get("ca")
        capath = sslp.get("capath")
        hasnoca = ca is None and capath is None
        ctx = ssl.create_default_context(cafile=ca, capath=capath)
        ctx.check_hostname = not hasnoca and sslp.get("check_hostname", True)
        verify_mode_value = sslp.get("verify_mode")
        if verify_mode_value is None:
            ctx.verify_mode = ssl.CERT_NONE if hasnoca else ssl.CERT_REQUIRED
        elif isinstance(verify_mode_value, bool):
            ctx.verify_mode = ssl.CERT_REQUIRED if verify_mode_value else ssl.CERT_NONE
        else:
            if isinstance(verify_mode_value, str):
                verify_mode_value = verify_mode_value.lower()
            if verify_mode_value in ("none", "0", "false", "no"):
                ctx.verify_mode = ssl.CERT_NONE
            elif verify_mode_value == "optional":
                ctx.verify_mode = ssl.CERT_OPTIONAL
            elif verify_mode_value in ("required", "1", "true", "yes"):
                ctx.verify_mode = ssl.CERT_REQUIRED
            else:
                ctx.verify_mode = ssl.CERT_NONE if hasnoca else ssl.CERT_REQUIRED
        if "cert" in sslp:
            ctx.load_cert_chain(sslp["cert"], keyfile=sslp.get("key"))
        if "cipher" in sslp:
            ctx.set_ciphers(sslp["cipher"])
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        return ctx

    def close(self):
        """
        Send the quit message and close the socket.

        See `Connection.close() <https://www.python.org/dev/peps/pep-0249/#Connection.close>`_
        in the specification.

        :raise Error: If the connection is already closed.
        """
        if self._closed:
            raise err.Error("Already closed")
        self._closed = True
        if self._sock is None:
            return False

        try:
            if self.pcursor is not None:
                self.pcursor.close()
            self.requestType = COMMAND.B_REQ_CLOSE_CONNECTION
            data = Operation.setCommandPacket(self, self.requestType, 25)
            self._write_bytes(data)
        except Exception:
            return False
        finally:
            self._force_close()
        return True

    @property
    def open(self):
        """Return True if the connection is open."""
        return self._sock is not None

    def _force_close(self):
        """Close connection without QUIT message."""
        if self._sock:
            try:
                self._sock.close()
            except:  # noqa
                pass
        self._sock = None
        self._rfile = None

    __del__ = _force_close

    def transCursorToConn(self, cur):
        self.pcursor = cur

    def autocommit(self, value=False):
        """Return True if the autocommit_mode is setted."""
        if value:
            mode = b'0x01'
        else:
            mode = b'0x00'
        self.autocommit_mode = bool(value)
        self.requestType = COMMAND.CONNECTION_SET_AUTO_COMMIT
        data = Operation.setCommandPacket(self, self.requestType, 26) + mode
        self._write_bytes(data)
        result = Operation.readResult(self)
        return result.packet_ok

    def get_autocommit(self):
        """Return autocommit_mode."""
        return self.autocommit_mode

    def _read_ok_packet(self):
        # cloudwave not use
        pkt = self._read_packet()
        if not pkt.is_ok_packet():
            raise err.OperationalError(
                CR.CR_COMMANDS_OUT_OF_SYNC,
                "Command Out of Sync",
            )
        ok = OKPacketWrapper(pkt)
        self.server_status = ok.server_status
        return ok

    def begin(self):
        """Begin transaction."""
        return self.autocommit(False)

    def commit(self):
        """
        Commit changes to stable storage.

        See `Connection.commit() <https://www.python.org/dev/peps/pep-0249/#commit>`_
        in the specification.
        """
        result = self._execute_command_only(COMMAND.CONNECTION_COMMIT)
        return result.packet_ok

    def rollback(self):
        """
        Roll back the current transaction.

        See `Connection.rollback() <https://www.python.org/dev/peps/pep-0249/#rollback>`_
        in the specification.
        """
        result = self._execute_command_only(COMMAND.CONNECTION_ROLLBACK)
        return result.packet_ok

    """
    def show_warnings(self):
        # cloudwave not use
        #Send the "SHOW WARNINGS" SQL command.
        self._execute_command_sql(COMMAND.COM_QUERY, "SHOW WARNINGS")
        result = CloudwaveResult(self, self.pcursor.requestType, self.pcursor.execType)
        result.read()
        return result.rows
    """

    def escape(self, obj, mapping=None):
        """Escape whatever value is passed.

        Non-standard, for internal use; do not use this in your applications.
        """
        if isinstance(obj, str):
            return "'" + self.escape_string(obj) + "'"
        if isinstance(obj, (bytes, bytearray)):
            ret = self._quote_bytes(obj)
            if self._binary_prefix:
                ret = "_binary" + ret
            return ret
        return converters.escape_item(obj, self.charset, mapping=mapping)

    def literal(self, obj):
        """Alias for escape().

        Non-standard, for internal use; do not use this in your applications.
        """
        return self.escape(obj, self.encoders)

    def escape_string(self, s):
        #if self.server_status & SERVER_STATUS.SERVER_STATUS_NO_BACKSLASH_ESCAPES:
        return s.replace("'", "''")
        return converters.escape_string(s)

    def _quote_bytes(self, s):
        if self.server_status & SERVER_STATUS.SERVER_STATUS_NO_BACKSLASH_ESCAPES:
            return "'%s'" % (s.replace(b"'", b"''").decode("ascii", "surrogateescape"),)
        return converters.escape_bytes(s)

    def cursor(self, cursor=None):
        """
        Create a new cursor to execute queries with.

        :param cursor: The type of cursor to create. None means use Cursor.
        :type cursor: :py:class:`Cursor`, :py:class:`SSCursor`, :py:class:`DictCursor`, or :py:class:`SSDictCursor`.
        """
        if cursor:
            return cursor(self)
        return self.cursorclass(self)

    def next_result(self, unbuffered=False):
        self._affected_rows = self._read_query_result(unbuffered=unbuffered)
        return self._affected_rows

    def affected_rows(self):
        return self._affected_rows

    """
    def kill(self, thread_id):
        # 需要数据库服务器支持

        arg = struct.pack("<I", thread_id)
        self._execute_command_sql(COMMAND.COM_PROCESS_KILL, arg)
        return self._read_ok_packet()
    """

    def ping(self, reconnect=True):
        """
        Check if the server is alive.

        :param reconnect: If the connection is closed, reconnect.
        :type reconnect: boolean

        :raise Error: If the connection is closed and reconnect=False.
        """
        if self._sock is None:
            if reconnect:
                self.connect()
                reconnect = False
            else:
                raise err.Error("Already closed")
        try:
            result = self._execute_command_only(COMMAND.GET_SERVER_VERSION)
        except Exception:
            if reconnect:
                self.connect()
                self.ping(False)
            else:
                raise
        return result.packet_ok

    """
    def set_charset(self, charset):
        # 需要数据库服务器支持
        # Make sure charset is supported.

        encoding = charset_by_name(charset).encoding

        self._execute_command_sql(COMMAND.COM_QUERY, "SET NAMES %s" % self.escape(charset))
        self._read_packet()
        self.charset = charset
        self.encoding = encoding
    """

    def connect(self, sock=None):
        self._closed = False
        try:
            if sock is None:
                if self.unix_socket:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(self.connect_timeout)
                    sock.connect(self.unix_socket)
                    self.host_info = "Localhost via UNIX socket"
                    self._secure = True
                    if DEBUG:
                        print("connected using unix_socket")
                else:
                    kwargs = {}
                    if self.bind_address is not None:
                        kwargs["source_address"] = (self.bind_address, 0)
                    while True:
                        try:
                            sock = socket.create_connection(
                                (self.host, self.port), self.connect_timeout, **kwargs
                            )
                            break
                        except (OSError, IOError) as e:
                            if e.errno == errno.EINTR:
                                continue
                            raise
                    self.host_info = "socket %s:%d" % (self.host, self.port)
                    if DEBUG:
                        print("connected using socket")
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.settimeout(None)

            self._sock = sock
            self._rfile = sock.makefile("rb")
            self._next_seq_id = 0

            r = Operation.sendFirstPacketToServer(self)
            if isinstance(r, list):
                self.sessionTime = r[0]
                self.sessionSequence = r[1]
                self.sessionToken = r[2]
            else:
                #raise err.DatabaseError("Can not connecnt database")
                pass
            #self._request_authentication()

            if self.sql_mode is not None:
                c = self.cursor()
                c.execute("SET sql_mode=%s", (self.sql_mode,))

            if self.init_command is not None:
                c = self.cursor()
                c.execute(self.init_command)
                c.close()
                self.commit()

            if self.autocommit_mode is not None:
                self.autocommit(self.autocommit_mode)

        except BaseException as e:
            self._rfile = None
            if sock is not None:
                try:
                    sock.close()
                except:  # noqa
                    pass

            if isinstance(e, (OSError, IOError)):
                exc = err.OperationalError(
                    CR.CR_CONN_HOST_ERROR,
                    "Can't connect to Cloudwave server on %r (%s)" % (self.host, e),
                )
                # Keep original exception and traceback to investigate error.
                exc.original_exception = e
                exc.traceback = traceback.format_exc()
                if DEBUG:
                    print(exc.traceback)
                raise exc

            # If e is neither DatabaseError or IOError, It's a bug.
            # But raising AssertionError hides original error.
            # So just reraise it.
            raise

    def write_packet(self, payload):
        # cloudwave not use
        """Writes an entire "cloudwave packet" in its entirety to the network
        adding its length and sequence number.
        """
        # Internal note: when you build packet manually and calls _write_bytes()
        # directly, you should set self._next_seq_id properly.
        data = _pack_int24(len(payload)) + bytes([self._next_seq_id]) + payload
        if DEBUG:
            dump_packet(data)
        self._write_bytes(data)
        self._next_seq_id = (self._next_seq_id + 1) % 256

    def _read_packet(self):
        """Read an entire "cloudwave packet" in its entirety from the network
        and return a CloudwavePacket type that represents the results.

        :raise OperationalError: If the connection to the Cloudwave server is lost.
        :raise InternalError: If the packet sequence number is wrong.
        """
        buff = bytearray()
        while True:
            packet_header = self._read_bytes(4)
            # if DEBUG: dump_packet(packet_header)

            bytes_to_read, = struct.unpack(">i", packet_header)
            bytes_to_read = bytes_to_read - 4

            recv_data = self._read_bytes(bytes_to_read)
            if DEBUG:
                dump_packet(recv_data)
            buff += recv_data
            # https://dev.cloudwave.com/doc/internals/en/sending-more-than-16mbyte.html
            if bytes_to_read == 0xFFFFFF:
                continue
            if bytes_to_read < MAX_PACKET_LEN:
                break

        return bytes(buff)

    def _read_bytes(self, num_bytes):
        self._sock.settimeout(self._read_timeout)
        while True:
            try:
                data = self._rfile.read(num_bytes)
                break
            except (IOError, OSError) as e:
                if e.errno == errno.EINTR:
                    continue
                self._force_close()
                raise err.OperationalError(
                    CR.CR_SERVER_LOST,
                    "Lost connection to Cloudwave server during query (%s)" % (e,),
                )
            except BaseException:
                # Don't convert unknown exception to CloudwaveError.
                self._force_close()
                raise
        if len(data) < num_bytes:
            self._force_close()
            raise err.OperationalError(
                CR.CR_SERVER_LOST, "Lost connection to Cloudwave server during query"
            )
        return data

    def _write_bytes(self, data):
        self._sock.settimeout(self._write_timeout)
        try:
            self._sock.sendall(data)
        except IOError as e:
            self._force_close()
            raise err.OperationalError(
                CR.CR_SERVER_GONE_ERROR, "Cloudwave server has gone away (%r)" % (e,)
            )

    def _read_query_result(self, unbuffered=False):
        #self._result = None
        if unbuffered:
            try:
                result = CloudwaveResult(self, COMMAND.EXECUTE_STATEMENT, self.pcursor.execType)
                result.init_unbuffered_query()
            except:
                result.unbuffered_active = False
                result.connection = None
                raise
        else:
            r = Operation.readResult(self, COMMAND.EXECUTE_STATEMENT, self.pcursor.execType) # ??????
            return r

    def insert_id(self):
        if self._result:
            return self._result.insert_id
        else:
            return 0

    def _execute_command_only(self, command):
        self.requestType = command
        data = Operation.setCommandPacket(self, self.requestType, 25)
        self._write_bytes(data)
        return Operation.readResult(self)

    def _execute_command_sql(self, command, sql):
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

    def _request_authentication(self):
        # https://dev.cloudwave.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
        if int(self.server_version.split(".", 1)[0]) >= 5:
            self.client_flag |= CLIENT.MULTI_RESULTS

        if self.user is None:
            raise ValueError("Did not specify a username")

        charset_id = charset_by_name(self.charset).id
        if isinstance(self.user, str):
            self.user = self.user.encode(self.encoding)

        data_init = struct.pack(
            "<iIB23s", self.client_flag, MAX_PACKET_LEN, charset_id, b""
        )

        if self.ssl and self.server_capabilities & CLIENT.SSL:
            self.write_packet(data_init)

            self._sock = self.ctx.wrap_socket(self._sock, server_hostname=self.host)
            self._rfile = self._sock.makefile("rb")
            self._secure = True

        data = data_init + self.user + b"\0"

        authresp = b""
        plugin_name = None

        if self._auth_plugin_name == "":
            plugin_name = b""
            authresp = _auth.scramble_native_password(self.password, self.salt)
        elif self._auth_plugin_name == "cloudwave_native_password":
            plugin_name = b"cloudwave_native_password"
            authresp = _auth.scramble_native_password(self.password, self.salt)
        elif self._auth_plugin_name == "caching_sha2_password":
            plugin_name = b"caching_sha2_password"
            if self.password:
                if DEBUG:
                    print("caching_sha2: trying fast path")
                authresp = _auth.scramble_caching_sha2(self.password, self.salt)
            else:
                if DEBUG:
                    print("caching_sha2: empty password")
        elif self._auth_plugin_name == "sha256_password":
            plugin_name = b"sha256_password"
            if self.ssl and self.server_capabilities & CLIENT.SSL:
                authresp = self.password + b"\0"
            elif self.password:
                authresp = b"\1"  # request public key
            else:
                authresp = b"\0"  # empty password

        if self.server_capabilities & CLIENT.PLUGIN_AUTH_LENENC_CLIENT_DATA:
            data += _lenenc_int(len(authresp)) + authresp
        elif self.server_capabilities & CLIENT.SECURE_CONNECTION:
            data += struct.pack("B", len(authresp)) + authresp
        else:  # pragma: no cover - not testing against servers without secure auth (>=5.0)
            data += authresp + b"\0"

        if self.db and self.server_capabilities & CLIENT.CONNECT_WITH_DB:
            if isinstance(self.db, str):
                self.db = self.db.encode(self.encoding)
            data += self.db + b"\0"

        if self.server_capabilities & CLIENT.PLUGIN_AUTH:
            data += (plugin_name or b"") + b"\0"

        if self.server_capabilities & CLIENT.CONNECT_ATTRS:
            connect_attrs = b""
            for k, v in self._connect_attrs.items():
                k = k.encode("utf-8")
                connect_attrs += _lenenc_int(len(k)) + k
                v = v.encode("utf-8")
                connect_attrs += _lenenc_int(len(v)) + v
            data += _lenenc_int(len(connect_attrs)) + connect_attrs

        self.write_packet(data)
        auth_packet = self._read_packet()

        # if authentication method isn't accepted the first byte
        # will have the octet 254
        if auth_packet.is_auth_switch_request():
            if DEBUG:
                print("received auth switch")
            # https://dev.cloudwave.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchRequest
            auth_packet.read_uint8()  # 0xfe packet identifier
            plugin_name = auth_packet.read_string()
            if (
                self.server_capabilities & CLIENT.PLUGIN_AUTH
                and plugin_name is not None
            ):
                auth_packet = self._process_auth(plugin_name, auth_packet)
            else:
                raise err.OperationalError("received unknown auth switch request")
        elif auth_packet.is_extra_auth_data():
            if DEBUG:
                print("received extra data")
            # https://dev.cloudwave.com/doc/internals/en/successful-authentication.html
            if self._auth_plugin_name == "caching_sha2_password":
                auth_packet = _auth.caching_sha2_password_auth(self, auth_packet)
            elif self._auth_plugin_name == "sha256_password":
                auth_packet = _auth.sha256_password_auth(self, auth_packet)
            else:
                raise err.OperationalError(
                    "Received extra packet for auth method %r", self._auth_plugin_name
                )

        if DEBUG:
            print("Succeed to auth")

    def _process_auth(self, plugin_name, auth_packet):
        handler = self._get_auth_plugin_handler(plugin_name)
        if handler:
            try:
                return handler.authenticate(auth_packet)
            except AttributeError:
                if plugin_name != b"dialog":
                    raise err.OperationalError(
                        CR.CR_AUTH_PLUGIN_CANNOT_LOAD,
                        "Authentication plugin '%s'"
                        " not loaded: - %r missing authenticate method"
                        % (plugin_name, type(handler)),
                    )
        if plugin_name == b"caching_sha2_password":
            return _auth.caching_sha2_password_auth(self, auth_packet)
        elif plugin_name == b"sha256_password":
            return _auth.sha256_password_auth(self, auth_packet)
        elif plugin_name == b"cloudwave_native_password":
            data = _auth.scramble_native_password(self.password, auth_packet.read_all())
        elif plugin_name == b"client_ed25519":
            data = _auth.ed25519_password(self.password, auth_packet.read_all())
        elif plugin_name == b"cloudwave_old_password":
            data = (
                _auth.scramble_old_password(self.password, auth_packet.read_all())
                + b"\0"
            )
        elif plugin_name == b"cloudwave_clear_password":
            # https://dev.cloudwave.com/doc/internals/en/clear-text-authentication.html
            data = self.password + b"\0"
        elif plugin_name == b"dialog":
            pkt = auth_packet
            while True:
                flag = pkt.read_uint8()
                echo = (flag & 0x06) == 0x02
                last = (flag & 0x01) == 0x01
                prompt = pkt.read_all()

                if prompt == b"Password: ":
                    self.write_packet(self.password + b"\0")
                elif handler:
                    resp = "no response - TypeError within plugin.prompt method"
                    try:
                        resp = handler.prompt(echo, prompt)
                        self.write_packet(resp + b"\0")
                    except AttributeError:
                        raise err.OperationalError(
                            CR.CR_AUTH_PLUGIN_CANNOT_LOAD,
                            "Authentication plugin '%s'"
                            " not loaded: - %r missing prompt method"
                            % (plugin_name, handler),
                        )
                    except TypeError:
                        raise err.OperationalError(
                            CR.CR_AUTH_PLUGIN_ERR,
                            "Authentication plugin '%s'"
                            " %r didn't respond with string. Returned '%r' to prompt %r"
                            % (plugin_name, handler, resp, prompt),
                        )
                else:
                    raise err.OperationalError(
                        CR.CR_AUTH_PLUGIN_CANNOT_LOAD,
                        "Authentication plugin '%s' not configured" % (plugin_name,),
                    )
                pkt = self._read_packet()
                pkt.check_error()
                if pkt.is_ok_packet() or last:
                    break
            return pkt
        else:
            raise err.OperationalError(
                CR.CR_AUTH_PLUGIN_CANNOT_LOAD,
                "Authentication plugin '%s' not configured" % plugin_name,
            )

        self.write_packet(data)
        pkt = self._read_packet()
        pkt.check_error()
        return pkt

    def _get_auth_plugin_handler(self, plugin_name):
        plugin_class = self._auth_plugin_map.get(plugin_name)
        if not plugin_class and isinstance(plugin_name, bytes):
            plugin_class = self._auth_plugin_map.get(plugin_name.decode("ascii"))
        if plugin_class:
            try:
                handler = plugin_class(self)
            except TypeError:
                raise err.OperationalError(
                    CR.CR_AUTH_PLUGIN_CANNOT_LOAD,
                    "Authentication plugin '%s'"
                    " not loaded: - %r cannot be constructed with connection object"
                    % (plugin_name, plugin_class),
                )
        else:
            handler = None
        return handler

    """
    # _cloudwave not support
    def thread_id(self):
        return self.server_thread_id[0]

    def character_set_name(self):
        return self.charset

    def get_host_info(self):
        return self.host_info

    def get_proto_info(self):
        return self.protocol_version

    def get_server_info(self):
        return self.server_version
    """

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

class LoadLocalFile:
    def __init__(self, filename, connection):
        self.filename = filename
        self.connection = connection

    def send_data(self):
        """Send data packets from the local file to the server"""
        if not self.connection._sock:
            raise err.InterfaceError(0, "")
        conn = self.connection

        try:
            with open(self.filename, "rb") as open_file:
                packet_size = min(
                    conn.max_allowed_packet, 16 * 1024
                )  # 16KB is efficient enough
                while True:
                    chunk = open_file.read(packet_size)
                    if not chunk:
                        break
                    conn.write_packet(chunk)
        except IOError:
            raise err.OperationalError(
                ER.FILE_NOT_FOUND,
                f"Can't find file '{self.filename}'",
            )
        finally:
            # send the empty packet to signify we are done sending data
            conn.write_packet(b"")
