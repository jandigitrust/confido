Name: confido-cli
Version: 0.2.0
Release: 1%{?dist}
Summary: Confido CLI

License: Apache-2.0
URL: https://github.com/jandigitrust/confido
Source0: LICENSE
Source1: THIRD_PARTY_NOTICES.md
Source2: %{name}-third-party-licenses.tar.gz
Source3: %{name}

%description
Confido CLI

%prep

%build

%install
mkdir -p %{buildroot}/usr/local/bin
install -m 0755 %{SOURCE3} %{buildroot}/usr/local/bin/%{name}
install -d %{buildroot}%{_licensedir}/%{name}
install -m 0644 %{SOURCE0} %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/
tar -xzf %{SOURCE2} -C %{buildroot}%{_licensedir}/%{name}/

%files
%license %{_licensedir}/%{name}
/usr/local/bin/confido-cli

%changelog
* Mon Nov 23 2026 Pavel Nikonorov - 0.2.0-1
- Package the CLI and dependency attribution.
