%{!?pytho1_sitearch: %define python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}
%{!?python_ver: %define python_ver %(%{__python} -c "import sys ; print sys.version[:3]")}

Summary: Ethernet settings python bindings
Name: python-inet_diag
Version: 0.1
Release: 1%{?dist}
URL: https://rt.wiki.kernel.org/index.php/Tuna
Source: https://www.kernel.org/pub/software/libs/python/%{name}/%{name}-%{version}.tar.bz2
License: GPLv2
Group: System Environment/Libraries
BuildRequires: python-devel
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
Python bindings for the inet_diag kernel interface, that allows querying AF_INET
socket state.

%prep
%setup -q

%build
%{__python} setup.py build

%install
rm -rf %{buildroot}
%{__python} setup.py install --skip-build --root %{buildroot}
mkdir -p %{buildroot}%{_sbindir}
cp -p pss.py %{buildroot}%{_sbindir}/pss
cp -p psk.py %{buildroot}%{_sbindir}/psk

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc COPYING
%{_sbindir}/pss
%{_sbindir}/psk
%{python_sitearch}/inet_diag.so
%if "%{python_ver}" >= "2.5"
%{python_sitearch}/*.egg-info
%endif

%changelog
* Wed May 13 2009 * Arnaldo Carvalho de Melo <acme@redhat.com> - 0.1-1
- Initial package
