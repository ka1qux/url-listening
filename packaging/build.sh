#!/usr/bin/env bash
# Gera os instaladores do URL Listening usando containers (podman ou docker).
#
#   packaging/build.sh            # Linux (.deb, .rpm, .tar.gz) + Windows (Setup.exe)
#   packaging/build.sh linux      # só Linux
#   packaging/build.sh windows    # só Windows
#
# Saída em dist/. Linux: executável PyInstaller. Windows: Python embutido oficial
# + app + instalador NSIS (gerado no Linux, sem precisar de Windows).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-all}"
ENGINE="${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/url_listening/__init__.py")"
LINUX_IMAGE="${LINUX_IMAGE:-docker.io/library/python:3.12-slim-bullseye}"  # glibc 2.31: roda em Ubuntu 20.04+, Debian 11+, RHEL 9
WIN_PYTHON_VERSION="${WIN_PYTHON_VERSION:-3.12.10}"  # última 3.12 com instalador/embeddable para Windows
NSIS_IMAGE="${NSIS_IMAGE:-docker.io/library/debian:bookworm-slim}"
PYINSTALLER_VERSION="${PYINSTALLER_VERSION:-6.11.1}"
PKG="url-listening"
BUILD="$ROOT/build"
DIST="$ROOT/dist"

[ -n "$ENGINE" ] || { echo "erro: instale podman ou docker" >&2; exit 1; }
mkdir -p "$BUILD" "$DIST"
run() { "$ENGINE" run --rm -v "$ROOT:/src:Z" -w /src "$@"; }
# No podman sem root o root do container já é o usuário do host; só o docker precisa de chown.
OWN="true"
case "$ENGINE" in *docker) OWN="chown -R $(id -u):$(id -g)" ;; esac

make_icon() {
  [ -f "$BUILD/icon/icon.ico" ] && return
  echo ">> gerando ícone"
  run "$LINUX_IMAGE" sh -c "pip install -q --root-user-action=ignore pillow && python packaging/make_icon.py build/icon"
}

build_linux() {
  echo ">> PyInstaller (Linux)"
  rm -rf "$BUILD/linux"
  run "$LINUX_IMAGE" sh -c "
    apt-get update -qq >/dev/null && apt-get install -y -qq binutils >/dev/null &&
    pip install -q --root-user-action=ignore pyinstaller==$PYINSTALLER_VERSION &&
    pyinstaller --noconfirm --clean --onedir --name $PKG \
      --distpath build/linux/dist --workpath build/linux/work --specpath build/linux \
      --add-data /src/url_listening/static:url_listening/static \
      --paths /src packaging/entry.py &&
    $OWN build/linux"
  local app="$BUILD/linux/dist/$PKG"

  echo ">> tar.gz"
  tar -C "$BUILD/linux/dist" -czf "$DIST/${PKG}_${VERSION}_linux_x86_64.tar.gz" "$PKG"

  echo ">> .deb"
  local deb="$BUILD/linux/deb"
  rm -rf "$deb"
  install -d "$deb/DEBIAN" "$deb/opt" "$deb/usr/bin" "$deb/usr/share/applications" "$deb/usr/share/icons/hicolor/256x256/apps"
  cp -a "$app" "$deb/opt/$PKG"
  ln -s "/opt/$PKG/$PKG" "$deb/usr/bin/$PKG"
  install -m 644 "$ROOT/packaging/url-listening.desktop" "$deb/usr/share/applications/"
  install -m 644 "$BUILD/icon/icon.png" "$deb/usr/share/icons/hicolor/256x256/apps/$PKG.png"
  cat > "$deb/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: amd64
Maintainer: Kaique Oliveira <80919110+ka1qux@users.noreply.github.com>
Depends: xdg-utils
Section: net
Priority: optional
Installed-Size: $(du -sk "$deb" | cut -f1)
Description: Mapeia todos os dominios por tras de um site para bloqueio no webfilter
 Segue redirecionamentos, le certificado, pagina e DNS, testa espelhos e gera
 a lista de dominios para o objeto de bloqueio.
EOF
  dpkg-deb --root-owner-group --build "$deb" "$DIST/${PKG}_${VERSION}_amd64.deb" >/dev/null

  echo ">> .rpm"
  if command -v rpmbuild >/dev/null; then
    local top="$BUILD/linux/rpm"
    rm -rf "$top"
    mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    sed "s/@VERSION@/$VERSION/" "$ROOT/packaging/url-listening.spec" > "$top/SPECS/$PKG.spec"
    rpmbuild -bb --quiet --define "_topdir $top" --define "_appdir $app" \
      --define "_desktop $ROOT/packaging/url-listening.desktop" --define "_icon $BUILD/icon/icon.png" \
      "$top/SPECS/$PKG.spec"
    cp "$top"/RPMS/x86_64/*.rpm "$DIST/"
  else
    echo "   rpmbuild não encontrado: .rpm ignorado"
  fi
}

build_windows() {
  # Windows: Python embutido oficial (python.org) + pacote do app + instalador NSIS.
  # Não usa PyInstaller: exe "congelado" costuma ser barrado por antivírus corporativo.
  local embed="python-$WIN_PYTHON_VERSION-embed-amd64.zip"
  local stage="$BUILD/windows/app"
  mkdir -p "$BUILD/cache"
  if [ ! -f "$BUILD/cache/$embed" ]; then
    echo ">> baixando $embed"
    curl -fsSL -o "$BUILD/cache/$embed" "https://www.python.org/ftp/python/$WIN_PYTHON_VERSION/$embed"
  fi

  echo ">> montando app Windows"
  rm -rf "$BUILD/windows"
  mkdir -p "$stage/python"
  (cd "$stage/python" && unzip -q "$BUILD/cache/$embed")
  # O ._pth do Python embutido já inclui "." (a pasta python/), então o pacote vai ali.
  cp -r "$ROOT/url_listening" "$stage/python/"
  find "$stage" -name "__pycache__" -type d -prune -exec rm -rf {} +
  cp "$BUILD/icon/icon.ico" "$stage/icon.ico"
  printf '@echo off\r\n"%%~dp0python\\python.exe" -m url_listening %%*\r\n' > "$stage/url-listening.cmd"
  printf '@echo off\r\nstart "" "%%~dp0python\\pythonw.exe" -m url_listening.app\r\n' > "$stage/Abrir URL Listening.cmd"

  echo ">> zip portátil"
  rm -f "$DIST/URLListening_${VERSION}_windows_portable.zip"
  (cd "$BUILD/windows" && mv app URLListening && zip -qr "$DIST/URLListening_${VERSION}_windows_portable.zip" URLListening && mv URLListening app)

  echo ">> instalador NSIS"
  run "$NSIS_IMAGE" sh -c "
    apt-get update -qq >/dev/null && apt-get install -y -qq nsis >/dev/null &&
    makensis -V2 -DVERSION=$VERSION -DSRCDIR=/src/build/windows/app \
      -DICON=/src/build/icon/icon.ico -DOUTFILE=/src/dist/URLListening_${VERSION}_Setup.exe \
      packaging/installer.nsi &&
    $OWN /src/dist/URLListening_${VERSION}_Setup.exe"
}

make_icon
case "$TARGET" in
  linux) build_linux ;;
  windows) build_windows ;;
  all) build_linux; build_windows ;;
  *) echo "uso: $0 [all|linux|windows]" >&2; exit 2 ;;
esac
echo ">> pronto:"
ls -lh "$DIST"
