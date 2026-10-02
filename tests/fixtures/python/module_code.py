import os

def main():
    pass

if __name__ == "__main__" and (os.environ.get("X") or not DEBUG):
    main()
