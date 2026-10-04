import os
import unittest
from importlib.machinery import SourceFileLoader

# Load the fwe script as a module
fwe = SourceFileLoader("fwe", "fwe").load_module()

class TestFWEEngine(unittest.TestCase):
    def setUp(self):
        # Provide a valid secret for testing
        os.environ["FWE_SECRET"] = "A_VALID_SECRET_THAT_IS_LONG_ENOUGH_12345"

    def tearDown(self):
        if "FWE_SECRET" in os.environ:
            del os.environ["FWE_SECRET"]

    def test_valid_initialization(self):
        config = fwe.FWEConfig()
        engine = fwe.FWEEngine(config)
        self.assertEqual(engine.config.secret, "A_VALID_SECRET_THAT_IS_LONG_ENOUGH_12345")

    def test_process_high_confidence(self):
        config = fwe.FWEConfig()
        engine = fwe.FWEEngine(config)
        result = engine.process(1.5, "Some test data")
        self.assertEqual(result, "Some test data")

    def test_process_low_confidence(self):
        config = fwe.FWEConfig()
        engine = fwe.FWEEngine(config)
        result = engine.process(0.5, "Some test data")
        self.assertEqual(result, "I DON'T KNOW.")

    def test_invalid_secret_length(self):
        os.environ["FWE_SECRET"] = "SHORT"
        with self.assertRaises(SystemExit):
            config = fwe.FWEConfig()
            fwe.FWEEngine(config)

    def test_invalid_secret_characters(self):
        os.environ["FWE_SECRET"] = "A_VALID_SECRET_THAT_IS_LONG_ENOUGH_12345!@#"
        with self.assertRaises(SystemExit):
            config = fwe.FWEConfig()
            fwe.FWEEngine(config)

if __name__ == "__main__":
    unittest.main()
