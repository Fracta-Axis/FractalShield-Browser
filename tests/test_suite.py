import os
import sys
import time
import json
from pathlib import Path
from statistics import mean

# Importación robusta del motor
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    from fractalshield.core import fractal_shield_encrypt, fractal_shield_decrypt
except ImportError as e:
    print(f"❌ Error: No se pudo importar el motor FractalShield.")
    print(f"   Detalle: {e}")
    sys.exit(1)


def run_empirical_benchmark(runs: int = 5):
    print("=" * 70)
    print("  FractalShield-Argon2id — Suite de Estrés Empírico (Windows)")
    print("  Verificación de Asimetría de Costo y Oracle-Free Verification")
    print("=" * 70)

    pwd = b"mi_contrasena_fractal_2026"
    bad_pwd = b"clave_totalmente_falsa_fuerza_bruta_999"
    data = b"usuario_invisible_en_el_navegador_fractal"

    levels = [1, 2, 3]
    report = {
        "platform": "Windows",
        "message_len_bytes": len(data),
        "runs_per_level": runs,
        "levels": {}
    }

    for lvl in levels:
        print(f"\n→ Ejecutando benchmark Nivel {lvl} ({'Standard' if lvl==1 else 'Reinforced' if lvl==2 else 'Maximum'})...")
        
        def_times = []
        att_times = []

        for r in range(runs):
            # Costo del defensor (capa 0)
            start = time.perf_counter()
            blob = fractal_shield_encrypt(data, pwd, level=lvl)
            decrypted = fractal_shield_decrypt(blob, pwd, level=lvl)
            end = time.perf_counter()
            def_times.append(end - start)

            # Costo del atacante (descifrado ciego completo con contraseña falsa)
            start = time.perf_counter()
            _ = fractal_shield_decrypt(blob, bad_pwd, level=lvl)
            end = time.perf_counter()
            att_times.append(end - start)

        def_avg = mean(def_times)
        att_avg = mean(att_times)
        asymmetry = att_avg / def_avg if def_avg > 0 else 0
        N = 3 if lvl == 1 else 4 if lvl == 2 else 5
        geom_factor = (1 << N) - 1

        report["levels"][f"level_{lvl}"] = {
            "layers": N,
            "geometric_factor_theoretical": geom_factor,
            "defender_time_avg_seconds": round(def_avg, 4),
            "attacker_time_avg_seconds": round(att_avg, 4),
            "asymmetry_ratio": round(asymmetry, 2),
            "attempts_per_second": round(1.0 / att_avg, 2) if att_avg > 0 else 0
        }

        print(f"   Defensor (Layer 0)     : {def_avg:.4f} s")
        print(f"   Atacante (OFV completo): {att_avg:.4f} s")
        print(f"   Ratio de asimetría     : {asymmetry:.2f}×  (teórico {geom_factor}×)")

    # Guardar reporte
    output_path = Path(__file__).resolve().parent.parent / "tests" / "vectors.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("\n" + "=" * 70)
    print("✅ Benchmark completado exitosamente en Windows")
    print(f"   Reporte guardado en: tests/vectors.json")
    print("=" * 70)


if __name__ == "__main__":
    run_empirical_benchmark(runs=5)   # Puedes subir a 10 para más precisión
