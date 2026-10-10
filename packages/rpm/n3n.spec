Summary: n3n BE peer-to-peer VPN
Name: n3n-be
Version: %{VERSION}
Release: 1
License: GPL-3.0-only
Group: Networking/Utilities
URL: https://github.com/HoneyBunnyQT/n3n
Source: n3n-be-%{version}.tgz
Packager: Honey Bunny QT <honeybunnyqt.official@proton.me>
# Temporary location where the RPM will be built
BuildRoot:  %{_tmppath}/%{name}-%{version}-root
Requires: libzstd
# n3n BE, a fork of n3n, installs the same files
Provides: n3n
Conflicts: n3n

# Make sure .build-id is not part of the package
%define _build_id_links none

%description
n3n peer-to-peer VPN: n3n BE (Bunny Edition), a fork of n3n

%prep

# This is expecting to build from the checked-out source, so there is no prep

%build

cd %TOPDIR
./autogen.sh
%configure
%make_build

%install

cd %TOPDIR
# where the system has its sbin: /usr/bin since Fedora 42
%make_install CONFIG_SBINDIR=$RPM_BUILD_ROOT%{_sbindir}
chmod u+w $RPM_BUILD_ROOT%{_sbindir}/*

#find $RPM_BUILD_ROOT -name ".git" | xargs /bin/rm -rf
#find $RPM_BUILD_ROOT -name ".svn" | xargs /bin/rm -rf
#find $RPM_BUILD_ROOT -name "*~"   | xargs /bin/rm -f

%clean
# Clean out our build directory
rm -fr $RPM_BUILD_ROOT

%files
/usr/bin/n3nctl
/usr/lib/systemd/system/n3n-edge.service
/usr/lib/systemd/system/n3n-edge@.service
/usr/lib/systemd/system/n3n-supernode.service
/usr/lib/sysusers.d/n3n.conf
%{_sbindir}/n3n
%{_sbindir}/n3n-edge
%{_sbindir}/n3n-supernode
/usr/share/doc/n3n/Contributing.md
/usr/share/doc/n3n/FAQ.md
/usr/share/doc/n3n/LICENSE.md
/usr/share/doc/n3n/README.md
/usr/share/doc/n3n/ReleaseProcess.md
/usr/share/doc/n3n/Scripts.md
/usr/share/doc/n3n/Tools.md
/usr/share/doc/n3n/community.list.sample
/usr/share/doc/n3n/edge.conf.sample
/usr/share/doc/n3n/supernode.conf.sample
/usr/share/man/man7/n3n.7.gz
/usr/share/man/man8/n3n.8.gz
/usr/share/man/man8/n3n-edge.8.gz
/usr/share/man/man8/n3n-supernode.8.gz

# Set the default attributes of all of the files specified to have an
# owner and group of root and to inherit the permissions of the file
# itself.
%defattr(-, root, root)

%changelog
* Sun Oct 31 2021 Hamish Coleman <hamish@zot.org> 3.1.0
- Last stable release

# Execution order:
# install:    pre -> (copy) -> post
# upgrade:    pre -> (copy) -> post -> preun (old) -> (delete old) -> postun (old)
# un-install:                          preun       -> (delete)     -> postun

%pre

if ! grep -q n3n /etc/group; then
  echo 'Creating n3n group'
  /usr/sbin/groupadd -r n3n
fi

if ! /usr/bin/id -u n3n > /dev/null 2>&1; then
  echo 'Creating n3n user'
  /usr/sbin/useradd -M -N -g n3n -r -s /bin/false n3n
fi

%post
if [ -f /bin/systemctl ]; then
  if [ ! -f /.dockerenv ]; then
      /bin/systemctl daemon-reload
      # NOTE: do not enable any services during first installation
  fi
fi

%preun
if [ -f /bin/systemctl ]; then
  if [ ! -f /.dockerenv ]; then
      # possibly remove the installed services
      %systemd_preun supernode.service n3n-edge.service 'edge@*.service'
  fi
fi

%postun
if [ -f /bin/systemctl ]; then
  if [ ! -f /.dockerenv ]; then
      # possibly restart the running services
      %systemd_postun_with_restart n3n-supernode.service n3n-edge.service 'n3n-edge@*.service'
  fi
fi
