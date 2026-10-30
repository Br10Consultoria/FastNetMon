import unittest
from fmn_filters.a10_syslog_capacity import estimate, GIB

class CapacityTests(unittest.TestCase):
    def test_interval_and_growth(self):
        result=estimate((1,2,1000),(1,2,11694507),30,80*GIB)
        self.assertTrue(result["valido"])
        self.assertAlmostEqual(result["projecao_gib_por_dia"],31.37,delta=.10)
        self.assertEqual(result["alerta_capacidade"],"critico")
        self.assertGreater(result["dias_livres_estimados_sem_compressao"],2.4)

    def test_rotation_never_fakes_growth(self):
        changed=estimate((1,2,999999),(1,3,300),30,80*GIB)
        self.assertFalse(changed["valido"])
        self.assertNotIn("projecao_gib_por_dia",changed)
        truncated=estimate((1,2,1000),(1,2,5),30,80*GIB)
        self.assertFalse(truncated["valido"])

    def test_zero_growth_not_divide_by_zero(self):
        result=estimate((1,2,1000),(1,2,1000),15,40*GIB)
        self.assertIsNone(result["dias_livres_estimados_sem_compressao"])
        self.assertEqual(result["alerta_capacidade"],"indeterminado")

    def test_no_sensitive_data_in_output(self):
        sample=estimate((1,2,1000),(1,2,2000),5,GIB)
        self.assertNotIn("ip",sample)
        self.assertNotIn("port",sample)

    def test_invalid_interval(self):
        with self.assertRaises(ValueError):
            estimate((1,2,0),(1,2,1),0,GIB)

if __name__=="__main__":
    unittest.main()
