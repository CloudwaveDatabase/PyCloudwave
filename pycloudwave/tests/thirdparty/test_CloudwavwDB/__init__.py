from .test_CloudwaveDB_capabilities import test_CloudwaveDB as test_capabilities
from .test_CloudwaveDB_nonstandard import *
from .test_CloudwaveDB_dbapi20 import test_CloudwaveDB as test_dbapi2

if __name__ == "__main__":
    import unittest

    unittest.main()
