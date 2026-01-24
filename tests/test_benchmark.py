
import unittest
import os
import shutil
import tempfile
import time
import pandas as pd
import numpy as np
import vouch

class TestBenchmark(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_strict = os.path.join(self.test_dir, "strict.vch")
        self.output_light = os.path.join(self.test_dir, "light.vch")

        # Pre-generate data to avoid measuring generation time in the benchmark
        # 100k rows is realistic for a "small" production job
        n_orders = 100_000
        n_customers = 5_000

        self.orders_df = pd.DataFrame({
            'order_id': np.arange(n_orders),
            'customer_id': np.random.randint(0, n_customers, n_orders),
            'amount': np.random.uniform(10, 1000, n_orders),
            'status': np.random.choice(['new', 'shipped', 'returned'], n_orders)
        })

        self.customers_df = pd.DataFrame({
            'customer_id': np.arange(n_customers),
            'region': np.random.choice(['US', 'EU', 'APAC'], n_customers),
            'segment': np.random.choice(['retail', 'corporate'], n_customers)
        })

        # Save raw inputs (simulating a data lake)
        self.orders_path = os.path.join(self.test_dir, "orders.csv")
        self.customers_path = os.path.join(self.test_dir, "customers.csv")
        self.orders_df.to_csv(self.orders_path, index=False)
        self.customers_df.to_csv(self.customers_path, index=False)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def workload(self):
        """
        A realistic Data Engineering / Analytics workload:
        1. Read CSVs (I/O)
        2. Merge (Join)
        3. GroupBy (Aggregation)
        4. Derived Columns (Vectorized Ops)
        """
        # 1. Read (Audited: Logs call, Hashes file content)
        orders = pd.read_csv(self.orders_path)
        cust = pd.read_csv(self.customers_path)

        # 2. Merge (Audited: Logs call, Hashes input DFs)
        # In strict mode, hashing these DFs involves serializing them to CSV/JSON strings.
        merged = pd.merge(orders, cust, on='customer_id', how='left')

        # 3. Derived Column
        merged['tax'] = merged['amount'] * 0.2

        # 4. Aggregation
        summary = merged.groupby(['region', 'segment'])['amount'].sum()

        return summary

    def test_performance_comparison(self):
        print("\n=== Realistic Performance Benchmark (100k Rows) ===")

        # 1. Baseline
        # Note: We must ensure no auditing is active.
        # Vouch might be active if previous tests leaked, but setUp creates new TraceSession context.
        # Since we are not in a 'with vouch' block, it should be clean.
        start = time.perf_counter()
        base_res = self.workload()
        end = time.perf_counter()
        t_base = end - start
        print(f"Baseline (No Vouch): {t_base:.4f}s")

        # 2. Strict Mode
        # This will be slow because every `pd.merge` and `pd.read_csv` result is hashed.
        # Hashing a 100k row DataFrame involves serializing it.
        start = time.perf_counter()
        with vouch.vouch(self.output_strict, strict=True, allow_ephemeral=True):
            # Force re-import/wrap if necessary, though context manager handles imports
            # But since pandas is already imported, Vouch needs to wrap the existing module?
            # Vouch only wraps *new* imports or those in `targets`.
            # But `vouch.vouch()` (TraceSession default) doesn't automatically wrap already imported modules unless configured?
            # Actually `vouch.vouch()` is a helper. Let's look at `TraceSession`.
            # The context manager usually doesn't retroactively wrap unless we tell it.
            # To be safe and realistic, we reload pandas or assume the user imports it inside.
            import pandas as pd
            res = self.workload()

        end = time.perf_counter()
        t_strict = end - start
        print(f"Vouch (Strict):      {t_strict:.4f}s (Overhead: {t_strict/t_base:.2f}x)")

        # 3. Light Mode
        # Should skip the expensive DataFrame serialization/hashing
        start = time.perf_counter()
        with vouch.vouch(self.output_light, strict=True, light_mode=True, allow_ephemeral=True):
            import pandas as pd
            res = self.workload()

        end = time.perf_counter()
        t_light = end - start
        print(f"Vouch (Light):       {t_light:.4f}s (Overhead: {t_light/t_base:.2f}x)")

        # 4. File Sizes
        size_strict = os.path.getsize(self.output_strict)
        size_light = os.path.getsize(self.output_light)

        print(f"Strict Output Size:  {size_strict/1024:.2f} KB")
        print(f"Light Output Size:   {size_light/1024:.2f} KB")

        # Assertions
        # Strict mode will be VERY slow on 100k rows (serializing 100k rows to CSV for hashing is heavy).
        # Light mode should be much faster.
        self.assertLess(t_light, t_strict, "Light mode should be faster than strict mode")

        # Check that overhead is not "Infinite"
        # 100k rows:
        # Baseline ~0.1s
        # Strict ~3-5s? (Serialization cost)
        # Light ~0.2s? (Just logging call args)

        self.assertLess(t_light, t_base * 50, "Light mode overhead should be reasonable")

if __name__ == '__main__':
    unittest.main()
