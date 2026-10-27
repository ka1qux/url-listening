# Empacota o executável já gerado pelo PyInstaller (ver packaging/build.sh).
%global debug_package %{nil}
%global __os_install_post %{nil}
%global __strip /bin/true

Name:           url-listening
Version:        @VERSION@
Release:        1
Summary:        Mapeia todos os dominios por tras de um site para bloqueio no webfilter
License:        Proprietary
BuildArch:      x86_64
AutoReqProv:    no
Requires:       xdg-utils

%description
Segue redirecionamentos, le certificado, pagina e DNS, testa espelhos e gera
a lista de dominios para o objeto de bloqueio do webfilter.

%install
mkdir -p %{buildroot}/opt %{buildroot}%{_bindir} %{buildroot}%{_datadir}/applications %{buildroot}%{_datadir}/icons/hicolor/256x256/apps
cp -a %{_appdir} %{buildroot}/opt/url-listening
ln -s /opt/url-listening/url-listening %{buildroot}%{_bindir}/url-listening
install -m 644 %{_desktop} %{buildroot}%{_datadir}/applications/url-listening.desktop
install -m 644 %{_icon} %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/url-listening.png

%files
/opt/url-listening
%{_bindir}/url-listening
%{_datadir}/applications/url-listening.desktop
%{_datadir}/icons/hicolor/256x256/apps/url-listening.png
