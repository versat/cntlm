Summary:        Fast NTLM authentication proxy with tunneling
Name:           cntlm
Version:		0.94.0
Release:        1%{?dist}
License:        GNU GPL V2
%if 0%{?suse_version}
Group:			Productivity/Networking/Web/Proxy
%else
Group:          System/Daemons
%endif
URL:            http://cntlm.sourceforge.net/
Source0:        %{name}-%{version}.tar.bz2
Source1:        %{name}.init
Source2:        %{name}.sysconfig


%if 0%{?suse_version}
Prereq: util-linux %{?insserv_prereq} %{?fillup_prereq}
%else
Prereq: which /sbin/chkconfig
%endif
Prereq: /usr/sbin/useradd /usr/bin/getent

Provides: cntlm = %{version}

BuildRoot:      %{_tmppath}/%{name}-%{version}-root

%description
Cntlm is a fast and efficient NTLM proxy, with support for TCP/IP tunneling,
authenticated connection caching, ACLs, proper daemon logging and behaviour
and much more. It has up to ten times faster responses than similar NTLM
proxies, while using by orders or magnitude less RAM and CPU. Manual page 
contains detailed information.

%prep
%setup -q -n %{name}-%{version}

%build			
./configure
make SYSCONFDIR=%{_sysconfdir} \
             BINDIR=%{_sbindir} \
             MANDIR=%{_mandir}

%install
# Clean up in case there is trash left from a previous build
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT

# Create the target build directory hierarchy
%if 0%{?suse_version}
  mkdir -p ${RPM_BUILD_ROOT}/var/adm/fillup-templates
%else
  mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
%endif

mkdir -p $RPM_BUILD_ROOT/sbin

%makeinstall SYSCONFDIR=$RPM_BUILD_ROOT/%{_sysconfdir} \
             BINDIR=$RPM_BUILD_ROOT/%{_sbindir} \
             MANDIR=$RPM_BUILD_ROOT/%{_mandir}
%if 0%{?suse_version}
  install -D -m 755 %{SOURCE1} $RPM_BUILD_ROOT/%{_initrddir}/cntlm
  install -D -m 644 %{SOURCE2} $RPM_BUILD_ROOT/var/adm/fillup-templates/sysconfig.cntlm
  ln -sf %{_initrddir}/cntlm $RPM_BUILD_ROOT/sbin/rccntlm
%else
  install -D -m 755 %{SOURCE1} $RPM_BUILD_ROOT/%{_initrddir}/cntlmd
  install -D -m 644 %{SOURCE2} $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/cntlmd
  ln -sf %{_initrddir}/cntlmd $RPM_BUILD_ROOT/sbin/rccntlmd
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ "$1" -eq 1 ]; then
	[ -z  "`%{_bindir}/getent passwd "cntlm"`" ] && {
    useradd -s /sbin/nologin -m -r -d /var/run/cntlm cntlm 2>/dev/null
	}
fi
:

%post
%if 0%{?suse_version}
%{fillup_and_insserv cntlm}
%else
  if [ "$1" -eq 1 ]; then
    if [ -x /usr/lib/lsb/install_initd ]; then
        /usr/lib/lsb/install_initd /etc/init.d/cntlmd
    elif [ -x /sbin/chkconfig ]; then
        /sbin/chkconfig --add cntlmd
    else
        for i in 2 3 4 5; do
            ln -sf /etc/init.d/cntlmd /etc/rc.d/rc${i}.d/S26cntlmd
        done
        for i in 1 6; do
            ln -sf /etc/init.d/cntlmd /etc/rc.d/rc${i}.d/K89cntlmd
        done
    fi
  fi 
  :
%endif

%preun
%if 0%{?suse_version}
%{stop_on_removal cntlm}
%else
  if [ "$1" -eq 0 ]; then
    /etc/init.d/cntlmd stop  > /dev/null 2>&1
    if [ -x /usr/lib/lsb/remove_initd ]; then
      /usr/lib/lsb/install_initd /etc/init.d/cntlmd
    elif [ -x /sbin/chkconfig ]; then
      /sbin/chkconfig --del cntlmd
    else
      rm -f /etc/rc.d/rc?.d/???cntlmd
    fi
  fi
  :
%endif

%postun
if [ "$1" -eq 0 ]; then
   /usr/sbin/userdel -r cntlm 2>/dev/null
fi
:
%if 0%{?suse_version}
%{insserv_cleanup}
%else
  if [ -x /usr/lib/lsb/remove_initd ]; then
    /usr/lib/lsb/install_initd /etc/init.d/cntlmd
  elif [ -x /sbin/chkconfig ]; then
    /sbin/chkconfig --del cntlmd
  else
    rm -f /etc/rc.d/rc?.d/???cntlmd
  fi
  :
%endif

%files
%defattr(-,root,root,-)
%doc LICENSE README COPYRIGHT
%{_sbindir}/cntlm
%{_mandir}/man1/cntlm.1*
%config(noreplace) %{_sysconfdir}/cntlm.conf
%if 0%{?suse_version}
 %config(noreplace) /var/adm/fillup-templates/sysconfig.cntlm
 %{_initrddir}/cntlm
 /sbin/rccntlm
%else
 %config(noreplace) %{_sysconfdir}/sysconfig/cntlmd
 %{_initrddir}/cntlmd
 /sbin/rccntlmd
%endif

%changelog
* Thu Mar 18 2010 : Version 0.90
- Major rewrite of proxy code
- NoProxy option added to bypass proxy for certain addresses
- Ability to work as a standalone proxy added
- few changes in spec file to package successfully for SuSE
  and RedHat distros using openSuSE BuildService by
  Michal Strnad
