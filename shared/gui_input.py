"""
GUI Input Bridge
----------------
When labs run from the GUI, environment variables replace input() calls.
When labs run from the terminal directly, input() works as normal.

Usage in any lab:
    from shared.gui_input import gui_input
    answer = gui_input("Approve exploitation? (yes/no): ")
"""
import os

def gui_input(prompt: str = "", env_key: str = None) -> str:
    """
    Try environment variable first (GUI mode), fall back to input() (terminal mode).
    env_key is auto-derived from the prompt text if not given.
    """
    # Auto-derive env key from prompt
    if not env_key:
        env_key = "GUI_INPUT_" + "".join(
            c if c.isalnum() else "_" for c in prompt.upper()
        )[:40]

    val = os.environ.get(env_key, "").strip()
    if val:
        print(f"{prompt}{val}")   # echo so output log shows it
        return val

    # Fall back to real input() in terminal mode
    return input(prompt)
