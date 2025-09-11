#
# You can tweak these three variables to make things install where you
# like, but do not touch more unless you know what you are doing. ;)
#
DESTDIR    	:=
PREFIX     	:= /usr/local
SYSCONFDIR 	:= $(DESTDIR)/etc
BINDIR     	:= $(DESTDIR)$(PREFIX)/sbin
MANDIR     	:= $(DESTDIR)$(PREFIX)/share/man

ifeq ($(wildcard configure-stamp),)
_ := $(shell ./configure)
endif

#
# Careful now...
# __BSD_VISIBLE is for FreeBSD AF_* constants
# _ALL_SOURCE is for AIX 5.3 LOG_PERROR constant
#
CC		:= $(shell head -n 1 configure-stamp)
VER		:= $(shell cat VERSION)
OS		:= $(shell uname -s)
OSLDFLAGS	:= $(shell [ $(OS) = "SunOS" ] && echo "-lrt -lsocket -lnsl")
LDFLAGS		:= -lpthread -lm $(OSLDFLAGS)
CYGWIN_REQS	:= cygwin1.dll cygrunsrv.exe

ifeq ($(OS),Darwin)
	ifndef ARCH
		ARCH := $(shell uname -m)
	endif
	CFLAGS := -arch $(ARCH)
# Change binary directory for macOS
	BINDIR := $(DESTDIR)$(PREFIX)/bin
endif

ifeq ($(CC),gcc)
GCC_VER := $(shell ${CC} -dumpfullversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/')
GCC_GTEQ_430 := $(shell expr ${GCC_VER} \>= 40300)
GCC_GTEQ_450 := $(shell expr ${GCC_VER} \>= 40500)
GCC_GTEQ_600 := $(shell expr ${GCC_VER} \>= 60000)
GCC_GTEQ_700 := $(shell expr ${GCC_VER} \>= 70000)
endif

CFLAGS	+= -std=c99 -D__BSD_VISIBLE -D_ALL_SOURCE -D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=200112 -D_ISOC99_SOURCE -D_REENTRANT -D_BSD_SOURCE -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -DVERSION=\"'$(VER)'\"
CFLAGS	+= -Wall -Wextra -pedantic -Wshadow -Wcast-qual -Wbad-function-cast -Wstrict-prototypes -Wno-overlength-strings
CFLAGS	+= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1
#CFLAGS  += -ftrapv
#CFLAGS  += -fsanitize=undefined -fsanitize-undefined-trap-on-error

ifeq ($(CC),gcc)
ifeq "$(GCC_GTEQ_430)" "1"
	CFLAGS += -Wlogical-op
endif
ifeq "$(GCC_GTEQ_450)" "1"
	CFLAGS += -Wjump-misses-init
endif
ifeq "$(GCC_GTEQ_600)" "1"
	CFLAGS += -Wduplicated-cond
	CFLAGS += -Wnull-dereference
	CFLAGS += -Werror=uninitialized
	CFLAGS += -Wformat=2
	CFLAGS += -Wformat-overflow=2
	CFLAGS += -Wformat-truncation=2
	CFLAGS += -Wformat-security
endif
ifeq "$(GCC_GTEQ_700)" "1"
	CFLAGS += -Wduplicated-branches
endif
endif

#CFLAGS	+= -fstack-protector-strong
#CFLAGS	+= -v
ifeq ($(COVERAGE),1)
	# COVERAGE REPORT
	CFLAGS  += -g --coverage
else ifeq ($(DEBUG),1)
	# DEBUG
	CFLAGS	+= -g -O0
else
	# RELEASE
	CFLAGS	+= -O3
endif

OBJS=main.o utils.o ntlm.o xcrypt.o config.o socket.o acl.o auth.o http.o forward.o direct.o scanner.o pages.o proxy.o pac.o duktape.o

CONFIG_GSS=$(shell grep -c "config_gss 1" config/config.h)
ifeq ($(CONFIG_GSS),1)
	OBJS+=kerberos.o
ifeq ($(OS),Darwin)
	LDFLAGS+=-framework GSS
else
	LDFLAGS+=-lgssapi_krb5
endif
endif

ifneq ($(findstring CYGWIN,$(OS)),)
	OBJS+=sspi.o win/resources.o
endif

ENABLE_STATIC=$(shell grep -c ENABLE_STATIC config/config.h)
ifeq ($(ENABLE_STATIC),1)
	LDFLAGS+=-static
endif

CFLAGS_DUKTAPE := -Wno-bad-function-cast -Wno-null-dereference -Wno-format-nonliteral -Wno-unused-but-set-variable
ifeq ($(CC),gcc)
	CFLAGS_DUKTAPE += -Wno-format-overflow 
endif

all: cntlm

cntlm: $(OBJS)
	@echo "Linking $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

main.o: main.c
	@echo "Compiling $<"
	@if [ -z "$(SYSCONFDIR)" ]; then \
		$(CC) $(CFLAGS) -c main.c -o $@; \
	else \
		$(CC) $(CFLAGS) -DSYSCONFDIR=\"$(SYSCONFDIR)\" -c main.c -o $@; \
	fi

%.o: %.c
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

duktape.o: duktape/duktape.c
	@echo "Compiling $<"
	@$(CC) $(CFLAGS) $(CFLAGS_DUKTAPE) -c -o $@ $<

win/resources.o: win/resources.rc
	@echo Win64: adding ICON resource
	@windres $^ -o $@

install: cntlm
	# Special handling for install(1)
	if [ "`uname -s`" = "AIX" ]; then \
		install -M 755 -S -f $(BINDIR) cntlm; \
		install -M 644 -f $(MANDIR)/man1 doc/cntlm.1; \
		install -M 600 -c $(SYSCONFDIR) doc/cntlm.conf; \
	elif [ "`uname -s`" = "Darwin" ]; then \
		install -d $(BINDIR)/; \
		install -m 755 -s cntlm $(BINDIR)/cntlm; \
		install -d $(MANDIR)/man1/; \
		install -m 644 doc/cntlm.1 $(MANDIR)/man1/cntlm.1; \
		[ -f $(SYSCONFDIR)/cntlm.conf -o -z "$(SYSCONFDIR)" ] \
			|| install -d $(SYSCONFDIR)/; \
			   install -m 600 doc/cntlm.conf $(SYSCONFDIR)/cntlm.conf; \
	else \
		install -D -m 755 -s cntlm $(BINDIR)/cntlm; \
		install -D -m 644 doc/cntlm.1 $(MANDIR)/man1/cntlm.1; \
		[ -f $(SYSCONFDIR)/cntlm.conf -o -z "$(SYSCONFDIR)" ] \
			|| install -D -m 600 doc/cntlm.conf $(SYSCONFDIR)/cntlm.conf; \
	fi
	@echo; echo "Cntlm will look for configuration in $(SYSCONFDIR)/cntlm.conf"

tgz:
	mkdir -p tmp
	rm -rf tmp/cntlm-$(VER)
	git checkout-index -a -f --prefix=./tmp/cntlm-$(VER)/
	tar zcvf cntlm-$(VER).tar.gz -C tmp/ cntlm-$(VER)
	rm -rf tmp/cntlm-$(VER)
	rmdir tmp 2>/dev/null || true

tbz2:
	mkdir -p tmp
	rm -rf tmp/cntlm-$(VER)
	git checkout-index -a -f --prefix=./tmp/cntlm-$(VER)/
	tar jcvf cntlm-$(VER).tar.bz2 -C tmp/ cntlm-$(VER)
	rm -rf tmp/cntlm-$(VER)
	rmdir tmp 2>/dev/null || true

deb:
	sed -i "s/^\(cntlm *\)([^)]*)/\1($(VER))/g" debian/changelog
	if [ `id -u` = 0 ]; then \
		debian/rules binary; \
		debian/rules clean; \
	else \
		fakeroot debian/rules binary; \
		fakeroot debian/rules clean; \
	fi
	mv ../cntlm_$(VER)*.deb .

rpm:
	sed -i "s/^\(Version:[\t ]*\)\(.*\)/\1$(VER)/g" rpm/cntlm.spec
	if [ `id -u` = 0 ]; then \
		rpm/rules binary; \
		rpm/rules clean; \
	else \
		fakeroot rpm/rules binary; \
		fakeroot rpm/rules clean; \
	fi

mac: cntlm cntlm-$(VER)-macos-$(ARCH).zip cntlm-$(VER)-macos-$(ARCH).pkg

cntlm-$(VER)-macos-$(ARCH).zip:
	@echo macOS: creating ZIP release for manual installs
	@mkdir -p cntlm-$(VER)
	@cp cntlm doc/cntlm.conf doc/cntlm.1 LICENSE cntlm-$(VER)/
	@zip -9 $@ cntlm-$(VER)/*
	@rm -rf cntlm-$(VER)
	@echo "Created $@"

cntlm-$(VER)-macos-$(ARCH).pkg:
	@echo macOS: preparing binaries for PKG installer
	@rm -rf pkgroot
	@mkdir -p pkgroot/$(BINDIR)
	@cp cntlm pkgroot/$(BINDIR)/cntlm
	@chmod 755 pkgroot/$(BINDIR)/cntlm
	@mkdir -p pkgroot/$(SYSCONFDIR)
	@cp doc/cntlm.conf pkgroot/$(SYSCONFDIR)/cntlm.conf
	@chmod 600 pkgroot/$(SYSCONFDIR)/cntlm.conf
	@mkdir -p pkgroot/$(MANDIR)/man1
	@cp doc/cntlm.1 pkgroot/$(MANDIR)/man1/cntlm.1
	@chmod 644 pkgroot/$(MANDIR)/man1/cntlm.1
	@pkgbuild --root pkgroot --identifier com.cntlm.proxy.$(ARCH) --version $(VER) --install-location / pkgbuild-cntlm-$(ARCH).pkg
	@echo '<?xml version="1.0" encoding="utf-8"?>' > distribution.xml
	@echo '<installer-gui-script minSpecVersion="1">' >> distribution.xml
	@echo '<title>cntlm $(VER) ($(ARCH))</title>' >> distribution.xml
	@echo '<options customize="never" require-scripts="false"/>' >> distribution.xml
	@echo '<domains enable_anywhere="true"/>' >> distribution.xml
	@echo '<choices-outline><line choice="default"/></choices-outline>' >> distribution.xml
	@echo '<choice id="default"><pkg-ref id="com.cntlm.proxy.$(ARCH)"/></choice>' >> distribution.xml
	@echo '<pkg-ref id="com.cntlm.proxy.$(ARCH)" version="$(VER)" onConclusion="none">pkgbuild-cntlm-$(ARCH).pkg</pkg-ref>' >> distribution.xml
	@echo '</installer-gui-script>' >> distribution.xml
	@productbuild --distribution distribution.xml --package-path . --resources . --version $(VER) cntlm-$(VER)-macos-$(ARCH).pkg
	@rm -rf pkgroot pkgbuild-cntlm-$(ARCH).pkg distribution.xml
	@echo "Created $@"

win: win/setup.iss cntlm win/cntlm_manual.pdf win/cntlm.ini win/LICENSE.txt cntlm-$(VER)-win64.exe cntlm-$(VER)-win64.zip

cntlm-$(VER)-win64.exe:
	@echo Win64: preparing binaries for GUI installer
	@cp $(patsubst %, /bin/%, $(CYGWIN_REQS)) win/
ifeq ($(DEBUG),1)
	@echo Win64: copy DEBUG executable
	@cp -p cntlm.exe win/
else
	@echo Win64: copy release executable
	@strip -o win/cntlm.exe cntlm.exe
endif
	@echo Win64: generating GUI installer
	@win/Inno5/ISCC.exe /Q win/setup.iss #/Q win/setup.iss
	@echo "Created $@"

cntlm-$(VER)-win64.zip:
	@echo Win64: creating ZIP release for manual installs
	@ln -s win cntlm-$(VER)
	@zip -9 $@ $(patsubst %, cntlm-$(VER)/%, cntlm.exe $(CYGWIN_REQS) cntlm.ini LICENSE.txt cntlm_manual.pdf)
	@rm -f cntlm-$(VER)
	@echo "Created $@"

win/cntlm.ini: doc/cntlm.conf
	@cat doc/cntlm.conf | unix2dos > $@

win/LICENSE.txt: COPYRIGHT LICENSE
	@cat COPYRIGHT LICENSE | unix2dos > $@

win/cntlm_manual.pdf: doc/cntlm.1
	@echo Win64: generating PDF manual
	@rm -f $@
	@groff -t -e -mandoc -Tps doc/cntlm.1 | ps2pdf - $@

win/setup.iss: win/setup.iss.in
ifeq ($(findstring CYGWIN,$(OS)),)
	@echo
	@echo "* This build target must be run from a Cywgin shell on Windows *"
	@echo
	@exit 1
endif
	@sed "s/\$$VERSION/$(VER)/g" $^ > $@

uninstall:
	@rm -f $(BINDIR)/cntlm $(MANDIR)/man1/cntlm.1 $(SYSCONFDIR)/cntlm.conf 2>/dev/null || true

clean:
	@rm -f $(patsubst %, config/%, endian gethostname socklen_t strdup arc4random_buf strlcat strlcpy memset_s gss) config/*.exe
	@rm -f *.o cntlm cntlm.exe configure-stamp config/config.h
	@rm -f $(patsubst %, win/%, $(CYGWIN_REQS) cntlm.exe cntlm.ini LICENSE.txt resources.o setup.iss cntlm_manual.pdf)

distclean: clean
ifeq ($(OS),Linux)
	if [ `id -u` = 0 ]; then \
		debian/rules clean; \
		rpm/rules clean; \
	else \
		fakeroot debian/rules clean; \
		fakeroot rpm/rules clean; \
	fi
endif
	@rm -f *.exe *.deb *.rpm *.tgz *.tar.gz *.tar.bz2 *.zip *.exe *.pkg tags ctags pid 2>/dev/null

.PHONY: all install tgz tbz2 deb rpm win uninstall clean distclean
