# test.py

print("Starting test...")

try:
    import psycopg2
    print("SUCCESS: psycopg2 imported successfully")
except Exception as e:
    print("FAILED:", str(e))
    raise
