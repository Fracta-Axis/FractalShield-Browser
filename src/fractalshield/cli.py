import os
import sys
import argparse
from pathlib import Path
from getpass import getpass

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from core import fractal_shield_encrypt, fractal_shield_decrypt
except ImportError as e:
    print(f"❌ Error: No se pudo importar el motor criptográfico")
    print(f"   → {e}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="FractalShield-Argon2id v1.0 — Motor oracle-free",
        epilog="Usuario invisible. Capas fractales."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt
    enc = subparsers.add_parser("encrypt", help="Cifra un archivo")
    enc.add_argument("-f", "--file", required=True, help="Archivo a cifrar")
    enc.add_argument("-l", "--level", type=int, choices=[1,2,3], default=1,
                     help="Nivel de protección")
    enc.add_argument("-o", "--output", help="Archivo de salida (.fs)")

    # Decrypt
    dec = subparsers.add_parser("decrypt", help="Descifra un archivo .fs")
    dec.add_argument("-f", "--file", required=True, help="Archivo .fs")
    dec.add_argument("-l", "--level", type=int, choices=[1,2,3], default=1,
                     help="Nivel usado")
    dec.add_argument("-o", "--output", help="Archivo de salida")

    args = parser.parse_args()

    input_path = Path(args.file)
    if not input_path.exists():
        print(f"❌ Error: El archivo '{args.file}' no existe.")
        sys.exit(1)

    # ←←← ULTRA SEGURO: contraseña nunca va por comando
    password = getpass("🔑 Ingresa tu contraseña Fractal: ")
    pwd_bytes = password.encode("utf-8")

    if args.command == "encrypt":
        print(f"🔒 Bloqueando estadio... Nivel {args.level} FractalShield activado...")
        try:
            data = input_path.read_bytes()
            encrypted = fractal_shield_encrypt(data, pwd_bytes, level=args.level)
            
            output = args.output or f"{args.file}.fs"
            Path(output).write_bytes(encrypted)
            print(f"✅ Blindado → {output} ({len(encrypted):,} bytes)")
        except Exception as e:
            print(f"❌ Error en cifrado: {e}")

    elif args.command == "decrypt":
        print(f"🔓 Penetrando capas ciegas (OFV)... Sentencia de Franco ejecutándose...")
        try:
            blob = input_path.read_bytes()
            decrypted = fractal_shield_decrypt(blob, pwd_bytes, level=args.level)
            
            if decrypted is None:
                print("❌ Contraseña incorrecta o archivo corrupto.")
                sys.exit(1)
            
            output = args.output or str(input_path).replace(".fs", ".dec")
            Path(output).write_bytes(decrypted)
            print(f"✅ Descifrado exitoso → {output}")
        except Exception as e:
            print(f"❌ Error en descifrado: {e}")

if __name__ == "__main__":
    main()
