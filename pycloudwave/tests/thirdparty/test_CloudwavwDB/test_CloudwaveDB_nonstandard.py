import sys
import unittest

import pycloudwave

_cloudwave = pycloudwave
from pycloudwave.constants import FIELD_TYPE
from pycloudwave.tests import base


class TestDBAPISet(unittest.TestCase):
    def test_set_equality(self):
        self.assertTrue(pycloudwave.STRING == pycloudwave.STRING)

    def test_set_inequality(self):
        self.assertTrue(pycloudwave.STRING != pycloudwave.NUMBER)

    def test_set_equality_membership(self):
        self.assertTrue(FIELD_TYPE.VAR_STRING == pycloudwave.STRING)

    def test_set_inequality_membership(self):
        self.assertTrue(FIELD_TYPE.DATE != pycloudwave.STRING)


class CoreModule(unittest.TestCase):
    """Core _cloudwave module features."""

    def test_NULL(self):
        """Should have a NULL constant."""
        self.assertEqual(_cloudwave.NULL, "NULL")

    def test_version(self):
        """Version information sanity."""
        self.assertTrue(isinstance(_cloudwave.__version__, str))

        self.assertTrue(isinstance(_cloudwave.version_info, tuple))
        self.assertEqual(len(_cloudwave.version_info), 5)

    def test_client_info(self):
        self.assertTrue(isinstance(_cloudwave.get_client_info(), str))

    def test_thread_safe(self):
        self.assertTrue(isinstance(_cloudwave.thread_safe(), int))


class CoreAPI(unittest.TestCase):
    """Test _cloudwave interaction internals."""

    def setUp(self):
        kwargs = base.PyCloudwaveTestCase.databases[0].copy()
        kwargs["read_default_file"] = "~/.my.cnf"
        self.conn = _cloudwave.connect(**kwargs)

    def tearDown(self):
        self.conn.close()

    def test_thread_id(self):
        tid = self.conn.thread_id()
        self.assertTrue(
            isinstance(tid, int), "thread_id didn't return an integral value."
        )

        self.assertRaises(
            TypeError,
            self.conn.thread_id,
            ("evil",),
            "thread_id shouldn't accept arguments.",
        )

    def test_affected_rows(self):
        self.assertEqual(
            self.conn.affected_rows(), 0, "Should return 0 before we do anything."
        )

    # def test_debug(self):
    ## FIXME Only actually tests if you lack SUPER
    # self.assertRaises(pycloudwave.OperationalError,
    # self.conn.dump_debug_info)

    def test_charset_name(self):
        self.assertTrue(
            isinstance(self.conn.character_set_name(), str), "Should return a string."
        )

    def test_host_info(self):
        assert isinstance(self.conn.get_host_info(), str), "should return a string"

    def test_proto_info(self):
        self.assertTrue(
            isinstance(self.conn.get_proto_info(), int), "Should return an int."
        )

    def test_server_info(self):
        self.assertTrue(
            isinstance(self.conn.get_server_info(), str), "Should return an str."
        )


if __name__ == "__main__":
    unittest.main()
