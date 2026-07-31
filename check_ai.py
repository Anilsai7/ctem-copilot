"""Diagnose why the AI narration toggle is not turning green.

    python check_ai.py

Checks each precondition in order and tells you exactly which one failed.
"""

import os
import sys


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("=" * 62)
    print("  AI NARRATION DIAGNOSTIC")
    print("=" * 62)

    print(f"\n1. Python interpreter\n   {sys.executable}")

    # --- 2. SDK installed, in THIS interpreter -----------------------------
    print("\n2. anthropic SDK")
    try:
        import anthropic
        print(f"   OK  installed, version {anthropic.__version__}")
        print(f"       at {os.path.dirname(anthropic.__file__)}")
        sdk = True
    except ImportError:
        print("   FAIL  not importable by THIS python.")
        print("         Fix:  python -m pip install anthropic")
        sdk = False

    # --- 3. API key present ------------------------------------------------
    print("\n3. ANTHROPIC_API_KEY environment variable")
    key = os.environ.get("ANTHROPIC_API_KEY") or ""
    tok = os.environ.get("ANTHROPIC_AUTH_TOKEN") or ""
    if key:
        print(f"   OK  set, {len(key)} chars, starts '{key[:7]}...' ends '...{key[-4:]}'")
        if " " in key or '"' in key or "'" in key:
            print("   WARN  contains a space or quote — that usually breaks auth.")
        if not key.startswith("sk-ant-"):
            print("   WARN  does not start with 'sk-ant-'. Is this an Anthropic key?")
    elif tok:
        print(f"   OK  ANTHROPIC_AUTH_TOKEN set ({len(tok)} chars)")
    else:
        print("   FAIL  not set in THIS process.")
        print("         Fix (Git Bash):  export ANTHROPIC_API_KEY=sk-ant-...")
        print("         Then run streamlit FROM THE SAME WINDOW.")

    # --- 4. what the app checks -------------------------------------------
    print("\n4. What app.py sees")
    try:
        import llm_layer
        ok, msg = llm_layer.status()
        print(f"   {'OK  ' if ok else 'FAIL'}  llm_layer.status() -> {ok} : {msg}")
    except Exception as e:
        ok = False
        print(f"   FAIL  could not import llm_layer: {e}")

    # --- 5. live call ------------------------------------------------------
    print("\n5. Live API call")
    if not (sdk and (key or tok)):
        print("   SKIPPED  fix steps 2 and 3 first.")
    else:
        try:
            import anthropic
            r = anthropic.Anthropic().messages.create(
                model="claude-opus-5",
                max_tokens=20,
                messages=[{"role": "user", "content": "Reply with the word: OK"}],
            )
            txt = "".join(b.text for b in r.content if b.type == "text").strip()
            print(f"   OK  Claude replied: {txt!r}")
            print(f"       model={r.model}  tokens in/out="
                  f"{r.usage.input_tokens}/{r.usage.output_tokens}")
        except Exception as e:
            name = type(e).__name__
            print(f"   FAIL  {name}: {str(e)[:220]}")
            if "authentication" in name.lower() or "401" in str(e):
                print("         The key was rejected. Check for a typo, a truncated")
                print("         paste, or a deleted key in console.anthropic.com.")
            elif "credit" in str(e).lower() or "billing" in str(e).lower():
                print("         Account has no credit. Add billing at")
                print("         console.anthropic.com -> Plans & Billing.")

    print("\n" + "=" * 62)
    if sdk and (key or tok) and ok:
        print("  ALL CHECKS PASSED")
        print("  Restart Streamlit FROM THIS SAME WINDOW:")
        print("      python -m streamlit run app.py")
    else:
        print("  Fix the FAIL lines above, then re-run: python check_ai.py")
    print("=" * 62)


if __name__ == "__main__":
    main()
