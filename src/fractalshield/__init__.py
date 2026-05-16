"""
FractalShield-Browser
Core Framework Component — v1.1

Semilla de Seguridad Soberana
Oracle-Free Verification + Geometric Cost Escalation

El motor criptográfico del futuro Navegador Fractal.
Usuario invisible. Capas indistinguibles. Ningún oráculo.

https://github.com/Fracta-Axis/FractalShield-Phantom
"""

from .core import (
    fractal_shield_encrypt,
    fractal_shield_decrypt,
)

__version__ = "1.1.0"
__author__ = "Miguel Angel Franco León (Fracta-Axis)"
__all__ = [
    "fractal_shield_encrypt",
    "fractal_shield_decrypt",
]

# Mensaje de bienvenida al importar el paquete
if __name__ != "__main__":
    print("🔥 FractalShield-Argon2id v1.1 cargado — Motor oracle-free activado")
