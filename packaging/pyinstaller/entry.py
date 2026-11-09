"""PyInstaller entry point for the ``portregistry`` bundle."""

import multiprocessing

from portregistry.cli.main import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
