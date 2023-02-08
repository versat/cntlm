# Cntlm

|Linux Build|AppVeyor Build (Cygwin)|Coverity Scan|Codacy Analysis|CodeQL|License|
|:--:|:--:|:--:|:--:|:--:|:--:|
|[![C/C++ CI](https://github.com/versat/cntlm/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/versat/cntlm/actions/workflows/c-cpp.yml)|[![AppVeyor Build status](https://ci.appveyor.com/api/projects/status/rthu5vjr0ksalyls/branch/master?svg=true)](https://ci.appveyor.com/project/versat/cntlm/branch/master)|[![Coverity Scan Build Status](https://img.shields.io/coverity/scan/15940.svg)](https://scan.coverity.com/projects/versat-cntlm)|[![Codacy Badge](https://api.codacy.com/project/badge/Grade/c506885b133047d38cd2c9dd4505320b)](https://www.codacy.com/app/versat/cntlm?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=versat/cntlm&amp;utm_campaign=Badge_Grade)|[![CodeQL](https://github.com/versat/cntlm/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/versat/cntlm/actions/workflows/codeql-analysis.yml)|[![License](https://img.shields.io/badge/license-GPL2.0-blue.svg)](https://opensource.org/licenses/GPL-2.0)|

SonarCloud:
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=versat_cntlm&metric=ncloc)](https://sonarcloud.io/dashboard?id=versat_cntlm)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=versat_cntlm&metric=bugs)](https://sonarcloud.io/dashboard?id=versat_cntlm)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=versat_cntlm&metric=code_smells)](https://sonarcloud.io/dashboard?id=versat_cntlm)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=versat_cntlm&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=versat_cntlm)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=versat_cntlm&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=versat_cntlm)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=versat_cntlm&metric=security_rating)](https://sonarcloud.io/dashboard?id=versat_cntlm)

## Installation using packages

Most of the popular distros contain cntlm packages in their repositories.
For Windows an installer is available.

You can use the procedures described below to prepare a package of current cntlm
version if desired.

NOTE: generating packages traditionally requires root privileges (to be able to set
proper ownership and permissions on package members). You can overcome that using
fakeroot. However, to install your packages you have to be root.

## Creating a SOURCE TARBALL

    make tgz

or

    make tbz2

## Creating DEBIAN PACKAGES

### 1) Quick way to create debian package

    make deb

### 2) From Debian/Ubuntu repository

Get these files (e.g. apt-get source cntlm):

    cntlm_0.XX-X.diff.gz
    cntlm_0.XX-X.dsc
    cntlm_0.XX.orig.tar.gz

Compile:

    dpkg-source -x cntlm_0.XX-Y.dsc
    cd cntlm-0.XX/
    dpkg-buildpackage -b -rfakeroot

Upon installation, the package takes care of creating a dedicated user for
cntlm, init script integration, manages eventual configuration file updates
with new upstream versions, things like restart of the daemon after future
updates, etc. You can later revert all these changes with one command, should
you decide to remove cntlm from your system.

## Creating RPM FROM SCRATCH

### 1) Quick way to create RPM

    make rpm    # you'll need root privs. or fakeroot utility

### 2) Detailed howto (or if make rpm doesn't work for you)

To build an RPM package from scratch, as root change to
/usr/src/[redhat|rpm|whatever]/SOURCES

Copy there all files from cntlm's rpm/ directory plus appropriate version of
the source tar.bz2 (see Creating a SOURCE TARBALL section above) and type:

    rpmbuild -ba cntlm.spec

Shortly after, you'll have source and binary RPMs ready in your ../SRPMS, resp.
../RPMS directories.

If your build cannot find the default config file in /etc, you probably have
broken RPM build environment. You should add this to your ~/.rpmmacros:

    %_sysconfdir    /etc

## Creating RPM FROM *.src.rpm

If you just want to create a binary package from src.rpm, as root type:

    rpmbuild --rebuild pkgname.src.rpm

Resulting binary RPM will be at /usr/src/..../RPMS

If your build cannot find the default config file in /etc, you probably have
broken RPM build environment. You should add this to your ~/.rpmmacros:

    %_sysconfdir    /etc

## Creating WINDOWS INSTALLER

Install Cygwin and include at least the gcc-core, make, ghostscript, dos2unix, zip, and cygrunsrv
packages using, for example, the following options:

    setup-x86_64.exe -qgdO -l C:\cygwin64\var\cache\setup -R C:\cygwin64 -s http://cygwin.mirror.constant.com -P gcc-core -P make -P ghostscript -P dos2unix -P zip -P cygrunsrv

Start a Cygwin console by using the shortcut on your desktop or startup menu.

From within the Cygwin command shell:

    cd /cygdrive/yourdrive/your_ctnlm_src_location
    export CC=gcc
    ./configure
    make

Prepare all binaries, manuals, config templates, Start Menu links, InnoSetup
project definition file, installer:

    make win

Now this automatically creates the installer.

Alternative, run this command, which does these steps, too:

    C:\cygwin64\bin\bash -e -l -c "cd /cygdrive/yourdrive/your_ctnlm_src_location && make distclean && ./configure && make && make win"

For manually creating the installer you can do this:

Run InnoSetup compiler to pack it all into an automatic installer EXE:

    /your/path/to/ISCC.exe win/setup.iss

or

Open folder "win" in explorer, right click "setup.iss" and select "Compile".

Both will generate an installer in the "cntlm" folder.

## Traditional installation

First, you have to compile cntlm. Using the Makefile, this should be very easy:

    ./configure
    make
    make install

Cntlm does not require any dynamic libraries and there are no dependencies you
have to satisfy before compilation, except for libpthreads. This library is
required for all threaded applications and is very likely to be part of your
system already, because it comes with libc. Next, install cntlm onto your
system like so:

Default installation directories are /usr/local/sbin, /usr/local/share/man and /etc.
Should you want to install cntlm into a different location, change the DESTDIR
installation prefix (from "/") to add a different installation prefix.
To change the location of binaries and manual (from "/usr/local") use PREFIX.
To change individual directories, use BINDIR, MANDIR and SYSCONFDIR:

    make SYSCONFDIR=/etc BINDIR=/usr/bin MANDIR=/usr/share/man
    make install SYSCONFDIR=/etc BINDIR=/usr/bin MANDIR=/usr/share/man

Cntlm is compiled with system-wide configuration file by default. That means
whenever you run cntlm, it looks into a hardcoded path (SYSCONFDIR) and tries
to load cntml.conf. You cannot make it not to do so, unless you use -c with an
alternative file or /dev/null. This is standard behavior and probably what you
want. On the other hand, some of you might not want to use cntlm as a daemon
started by init scripts and you would prefer setting up everything on the
command line. This is possible, just comment out SYSCONFDIR variable definition
in the Makefile before you compile cntlm and it will remove this feature.

Installation includes the main binary, the man page (see "man cntlm") and if
the default config feature was not removed, it also installs a configuration
template. Please note that unlike bin and man targets, existing configuration
is never overwritten during installation. In the doc/ directory you can find
among other things a file called "cntlmd". It can be used as an init.d script.

## Architectures

The build system now has an autodetection of the build arch endianness. Every
common CPU and OS out there is supported, including Windows, MacOS X, Linux,
*BSD, AIX.

## Compilers

Cntlm is tested against GCC, Clang and IBM XL C/C++, other C compilers will work
for you too. There are no compiler specific directives and options AFAIK.
compilers might work for you (then again, they might not). Specific
Makefiles for different compilers are supported by the ./configure script
(e.g. Makefile.xlc)

## Contact

David Kubicek <dave@awk.cz> (seems to be no longer available)
