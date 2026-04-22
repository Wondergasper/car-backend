import traceback

try:
    import main
    print("SUCCESS!")
except Exception as e:
    print("EXCEPTION:", repr(e))
    traceback.print_exc()
