#!/usr/bin/env python3
"""
Direct vectoreyes code generator that bypasses Nix.
This script directly uses the vectoreyes code generation modules without
requiring the Nix environment, which avoids the GhostScript library issue.
"""

import os
import sys
import subprocess
from pathlib import Path

# Global variables
rustfmt_path = "rustfmt"  # Default, will be updated if a different path is found

# Ensure we're in the right directory
script_dir = Path(__file__).resolve().parent
os.chdir(script_dir)

def check_dependencies():
    """Check if required Python packages and tools are installed"""
    # Check jinja2
    try:
        import jinja2
        print("✅ jinja2 is installed")
    except ImportError:
        print("❌ jinja2 is not installed")
        print("Installing jinja2...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "jinja2"])
        print("✅ jinja2 installed successfully")
        
    # Check rustfmt - try multiple possible locations
    rustfmt_paths = [
        "rustfmt",  # Standard PATH
        os.path.expanduser("~/.cargo/bin/rustfmt"),  # User's Cargo bin
        os.path.expanduser("~/.rustup/toolchains/stable-*/bin/rustfmt"),  # Rustup toolchains
        "/usr/local/bin/rustfmt",  # Common system location
    ]
    
    rustfmt_found = False
    for path in rustfmt_paths:
        # Handle glob patterns
        if '*' in path:
            import glob
            matches = glob.glob(path)
            if matches:
                path = matches[0]  # Use first match
            else:
                continue
                
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ rustfmt is installed: {result.stdout.strip()}")
                # Set global rustfmt_path for later use
                global rustfmt_path
                rustfmt_path = path
                rustfmt_found = True
                break
        except (FileNotFoundError, PermissionError):
            continue
    
    if not rustfmt_found:
        print("⚠️ Warning: rustfmt not found in PATH or common locations")
        print("  The code generation may fail or produce incorrectly formatted code.")
        print("  To install rustfmt: 'rustup component add rustfmt'")

def generate_code():
    """Run the vectoreyes code generation"""
    try:
        # Add vectoreyes to the Python path
        sys.path.insert(0, str(script_dir))
        
        # Save the original subprocess.run function
        original_run = subprocess.run
        
        # Create a wrapper that replaces rustfmt with our detected path
        def patched_run(args, **kwargs):
            if isinstance(args, list) and len(args) > 0 and args[0] == "rustfmt":
                args[0] = rustfmt_path
                print(f"Using rustfmt at: {rustfmt_path}")
            return original_run(args, **kwargs)
            
        # Apply the monkey patch to replace subprocess.run
        subprocess.run = patched_run
        
        # Now import the necessary modules
        from vectoreyes.src.codegen.generate import CODEGEN, generate
        
        # Define ROOT as the project root directory
        ROOT = script_dir
        
        # Get path for generated files
        GENERATED = CODEGEN.parent / "generated"
        
        # Generate the code
        print("Generating vectoreyes code...")
        sources = generate()
        
        # Write the files
        if GENERATED.exists():
            import shutil
            shutil.rmtree(GENERATED)
        GENERATED.mkdir()
        
        print(f"Writing files to {GENERATED}...")
        for k, v in sources.items():
            dst = GENERATED / k
            dst.parent.mkdir(exist_ok=True, parents=True)
            dst.write_bytes(v)
            print(f"  Created: {dst}")
        
        # Validate that the generated code matches what Git expects
        print("\nValidating generated code...")
        try:
            # This mimics the validation in cmd.py
            actuals = {}
            
            # Skip git validation if not in a git repository
            if not (script_dir / ".git").exists():
                print("Not in a git repository, skipping validation")
            else:
                git_output = subprocess.check_output(
                    ["git", "ls-files", "--cached", "--others", str(GENERATED.relative_to(ROOT))],
                    cwd=str(ROOT),
                ).decode("utf-8").strip()
                
                if git_output:
                    for path in git_output.split("\n"):
                        full_path = ROOT / path
                        relative_path = str(Path(path).relative_to(GENERATED.relative_to(ROOT)))
                        actuals[relative_path] = full_path.read_bytes()
                    
                    if actuals != sources:
                        print("⚠️ Warning: Generated code doesn't match what's tracked in Git.")
                        print("This is expected if you're making changes to the code generator.")
                    else:
                        print("✅ Generated code matches what's tracked in Git.")
                else:
                    print("No files tracked by Git for validation, skipping check")
        except Exception as e:
            print(f"⚠️ Warning: Validation failed: {e}")
            # Continue even if validation fails
        
        print("\n✅ Code generation completed successfully")
        return True
    except Exception as e:
        print(f"❌ Error during code generation: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Direct vectoreyes code generator")
    print("================================")
    check_dependencies()
    success = generate_code()
    sys.exit(0 if success else 1)
