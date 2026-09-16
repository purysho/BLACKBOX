from __future__ import annotations

import argparse
import tkinter as tk
from pathlib import Path

from blackbox_ui import BlackboxApp


def parse_args(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--repo')
    return parser.parse_known_args(argv)[0]


def main(argv=None):
    args = parse_args(argv)
    root = tk.Tk()
    app = BlackboxApp(root)
    if args.repo:
        repo = str(Path(args.repo).expanduser().resolve())
        app.path_var.set(repo)
        root.after(120, app.scan)
    root.mainloop()


if __name__ == '__main__':
    main()
