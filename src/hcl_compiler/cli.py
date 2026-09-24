import argparse
import sys
from .compiler import HCLCompiler

def main():
    parser = argparse.ArgumentParser(description="SMAOS Declarative Governance HCL Compiler")
    parser.add_argument("hcl_file", help="Path to smaos.hcl specification")
    parser.add_argument("--out-dir", default="build/governance", help="Output directory for compiled artifacts")
    args = parser.parse_args()

    try:
        compiler = HCLCompiler.from_file(args.hcl_file)
        res = compiler.compile_all(args.out_dir)
        print("🏛️ SMAOS Governance HCL Compilation Successful:")
        for k, v in res.items():
            print(f"  • {k}: {v}")
    except Exception as e:
        print(f"❌ Error during HCL compilation: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
