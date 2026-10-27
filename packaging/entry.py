"""Entrada do executável: sem argumentos abre o aplicativo; com argumentos vira CLI."""

import sys

from url_listening import app, cli

if __name__ == "__main__":
    sys.exit(cli.main(sys.argv[1:]) if len(sys.argv) > 1 else app.main())
