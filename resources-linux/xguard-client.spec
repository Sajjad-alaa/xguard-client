Name:     xguard-client
Version:  %{version}
Release:  1%{?dist}
Summary:  XGuard desktop client

License:  Apache-2.0
URL:      https://xguard.local/
Requires: libayatana-appindicator3-dev webkit2gtk4.1

%description
Desktop client for managing WireGuard VPN connections

%install
%{__mkdir} -p %{buildroot}/%{_bindir}
%{__mkdir} -p %{buildroot}/%{_sbindir}
%{__mkdir} -p %{buildroot}/%{_prefix}/lib/systemd/system
%{__mkdir} -p %{buildroot}/%{_prefix}/lib/xguard-client/resources/icons/tray
%{__mkdir} -p %{buildroot}/%{_datadir}/applications
%{__mkdir} -p %{buildroot}/%{_datadir}/icons/hicolor/128x128/apps
%{__mkdir} -p %{buildroot}/%{_datadir}/icons/hicolor/256x256@2/apps
%{__mkdir} -p %{buildroot}/%{_datadir}/icons/hicolor/32x32/apps
%{__install} -m 755 src-tauri/target/release/xguard-client %{buildroot}/%{_bindir}/
%{__install} -m 755 src-tauri/target/release/xguard-service %{buildroot}/%{_sbindir}/
%{__install} -m 644 src-tauri/target/release/resources/icons/tray/blue.png %{buildroot}/%{_prefix}/lib/xguard-client/resources/icons/tray/blue.png
%{__install} -m 644 src-tauri/target/release/resources/icons/tray/blue-connected.png %{buildroot}/%{_prefix}/lib/xguard-client/resources/icons/tray/blue-connected.png
%{__install} -m 644 src-tauri/target/release/resources/icons/tray/dark.png %{buildroot}/%{_prefix}/lib/xguard-client/resources/icons/tray/dark.png
%{__install} -m 644 src-tauri/target/release/resources/icons/tray/dark-connected.png %{buildroot}/%{_prefix}/lib/xguard-client/resources/icons/tray/dark-connected.png
%{__install} -m 644 src-tauri/target/release/resources/icons/tray/white.png %{buildroot}/%{_prefix}/lib/xguard-client/resources/icons/tray/white.png
%{__install} -m 644 src-tauri/target/release/resources/icons/tray/white-connected.png %{buildroot}/%{_prefix}/lib/xguard-client/resources/icons/tray/white-connected.png
%{__install} -m 644 resources-linux/xguard-service.service %{buildroot}/%{_prefix}/lib/systemd/system/
%{__install} -m 644 resources-linux/xguard-client.desktop %{buildroot}/%{_datadir}/applications/xguard-client.desktop
%{__install} -m 644 src-tauri/icons/128x128.png %{buildroot}/%{_datadir}/icons/hicolor/128x128/apps/xguard-client.png
%{__install} -m 644 src-tauri/icons/128x128@2x.png %{buildroot}/%{_datadir}/icons/hicolor/256x256@2/apps/xguard-client.png
%{__install} -m 644 src-tauri/icons/32x32.png %{buildroot}/%{_datadir}/icons/hicolor/32x32/apps/xguard-client.png

%post
# %{systemd_post} xguard-service.service
if [ $1 -eq 1 ]; then
    systemctl daemon-reload
    systemctl enable xguard-service.service
    systemctl start xguard-service.service
fi

%preun
# %{systemd_preun} xguard-service.service
if [ $1 -eq 0 ]; then
    systemctl stop xguard-service.service
    systemctl disable xguard-service.service
fi

%postun
# %{systemd_postun} xguard-service.service
systemctl daemon-reload

%files
%{_bindir}/xguard-client
%{_sbindir}/xguard-service
%{_prefix}/lib/xguard-client/resources/icons/tray/blue.png
%{_prefix}/lib/xguard-client/resources/icons/tray/blue-connected.png
%{_prefix}/lib/xguard-client/resources/icons/tray/dark.png
%{_prefix}/lib/xguard-client/resources/icons/tray/dark-connected.png
%{_prefix}/lib/xguard-client/resources/icons/tray/white.png
%{_prefix}/lib/xguard-client/resources/icons/tray/white-connected.png
%{_prefix}/lib/systemd/system/xguard-service.service
%{_datadir}/applications/xguard-client.desktop
%{_datadir}/icons/hicolor/128x128/apps/xguard-client.png
%{_datadir}/icons/hicolor/256x256@2/apps/xguard-client.png
%{_datadir}/icons/hicolor/32x32/apps/xguard-client.png
