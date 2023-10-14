import unittest

from pycloudwave import err


__all__ = ["TestRaiseException"]


class TestRaiseException(unittest.TestCase):
    def raise_cloudwave_exception(self):
        data = b"\xff\x15\x04#28000Access denied"
        with self.assertRaises(err.OperationalError) as cm:
            err.raise_cloudwave_exception(data)
        self.assertEqual(cm.exception.args, (1045, "Access denied"))
