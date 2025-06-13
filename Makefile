#
# You can tweak these three variables to make things install where you
# like, but do not touch more unless you know what you are doing. ;)
#
DESTDIR    	:=
PREFIX     	:= /usr/local
SYSCONFDIR 	:= $(DESTDIR)/etc
BINDIR     	:= $(DESTDIR)$(PREFIX)/sbin
INST_BINDIR := $(PREFIX)/sbin
LIBEXECDIR  := $(DESTDIR)$(PREFIX)/libexec
MANDIR     	:= $(DESTDIR)$(PREFIX)/share/man

STAMP	:= configure-stamp
ifeq ($(wildcard $(STAMP)),)
_ := $(shell ./configure)
endif

#
# Careful now...
# __BSD_VISIBLE is for FreeBSD AF_* constants
# _ALL_SOURCE is for AIX 5.3 LOG_PERROR constant
#
NAME		:= cntlm
CC		:= $(shell head -n 1 $(STAMP))
VER		:= $(shell cat VERSION)
OS		:= $(shell uname -s)
OSLDFLAGS	:= $(shell [ $(OS) = "SunOS" ] && echo "-lrt -lsocket -lnsl")
LDFLAGS		:= -lpthread -lm $(OSLDFLAGS)
CYGWIN_REQS	:= cygwin1.dll cygrunsrv.exe

ifeq ($(CC),gcc)
GCC_VER := $(shell ${CC} -dumpfullversion -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/')
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
else ifeq ($(NOSTRIP),1)
	# Packaging, therefore optimization enabled but build with debug symbols
	# as RPM will strip these out into a -debuginfo package that can be optionally installed
	CFLAGS	+= -g -O3
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

all: $(NAME)

$(NAME): $(OBJS)
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

ifneq ($(NOSTRIP),1)
	STRIP="-s"
	STRIPAIX="-S"
else
	STRIP=""
	STRIPAIX="-S"
endif
install: $(NAME)
	# Special handling for install(1)
	if [ "`uname -s`" = "AIX" ]; then \
		install -M 755 $(STRIPAIX) -f $(BINDIR) $(NAME); \
		install -M 644 -f $(MANDIR)/man1 doc/$(NAME).1; \
		install -M 600 -c $(SYSCONFDIR) doc/$(NAME).conf; \
	elif [ "`uname -s`" = "Darwin" ]; then \
		install -d $(BINDIR)/; \
		install -m 755 $(STRIP) $(NAME) $(BINDIR)/$(NAME); \
		install -d $(MANDIR)/man1/; \
		install -m 644 doc/$(NAME).1 $(MANDIR)/man1/$(NAME).1; \
		[ -f $(SYSCONFDIR)/$(NAME).conf -o -z "$(SYSCONFDIR)" ] \
			|| install -d $(SYSCONFDIR)/; \
			   install -m 600 doc/$(NAME).conf $(SYSCONFDIR)/$(NAME).conf; \
	else \
		install -D -m 755 $(STRIP) $(NAME) $(BINDIR)/$(NAME); \
		sed "s#%BINDIR%#$(INST_BINDIR)#g" linux/cntlm-user.in > linux/cntlm-user; \
		install -D -m 755 linux/$(NAME)-user $(LIBEXECDIR)/$(NAME)-user; \
		install -D -m 644 doc/$(NAME).1 $(MANDIR)/man1/$(NAME).1; \
		[ -f $(SYSCONFDIR)/$(NAME).conf -o -z "$(SYSCONFDIR)" ] \
			|| install -D -m 600 doc/$(NAME).conf $(SYSCONFDIR)/$(NAME).conf; \
	fi
	@echo; echo "Cntlm will look for configuration in $(SYSCONFDIR)/$(NAME).conf"

tgz:
	mkdir -p tmp
	rm -rf tmp/$(NAME)-$(VER)
	git checkout-index -a -f --prefix=./tmp/$(NAME)-$(VER)/
	tar zcvf $(NAME)-$(VER).tar.gz -C tmp/ $(NAME)-$(VER)
	rm -rf tmp/$(NAME)-$(VER)
	rmdir tmp 2>/dev/null || true

tbz2:
	mkdir -p tmp
	rm -rf tmp/$(NAME)-$(VER)
	git checkout-index -a -f --prefix=./tmp/$(NAME)-$(VER)/
	tar jcvf $(NAME)-$(VER).tar.bz2 -C tmp/ $(NAME)-$(VER)
	rm -rf tmp/$(NAME)-$(VER)
	rmdir tmp 2>/dev/null || true

deb:
	ln -sf linux/debian
	sed "s/^\(cntlm *\)([^)]*)/\1($(VER))/g" linux/debian/changelog.in > linux/debian/changelog
	if [ `id -u` = 0 ] && [ -L debian ]; then \
		linux/debian/rules binary; \
		linux/debian/rules clean; \
	elif [ -L debian ]; then \
		fakeroot linux/debian/rules binary; \
		fakeroot linux/debian/rules clean; \
	fi
	mv ../cntlm_$(VER)*.deb .

rpm: tbz2
	sed "s/^\(Version:[\t ]*\)\(.*\)/\1$(VER)/g" linux/rpm/SPECS/cntlm.spec.in > linux/rpm/SPECS/cntlm.spec
	@cp $(NAME)-$(VER).tar.bz2 linux/rpm/SOURCES/
	rpmbuild --define '_topdir $(CURDIR)/linux/rpm' -ba linux/rpm/SPECS/cntlm.spec
	mv linux/rpm/RPMS/**/*.rpm .

win: win/setup.iss $(NAME) win/cntlm_manual.pdf win/cntlm.ini win/LICENSE.txt $(NAME)-$(VER)-win64.exe $(NAME)-$(VER)-win64.zip

$(NAME)-$(VER)-win64.exe:
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

$(NAME)-$(VER)-win64.zip:
	@echo Win64: creating ZIP release for manual installs
	@ln -s win $(NAME)-$(VER)
	zip -9 $@ $(patsubst %, $(NAME)-$(VER)/%, cntlm.exe $(CYGWIN_REQS) cntlm.ini LICENSE.txt cntlm_manual.pdf)
	@rm -f $(NAME)-$(VER)

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
	rm -f $(BINDIR)/$(NAME) $(MANDIR)/man1/$(NAME).1 2>/dev/null || true

clean:
	@rm -f config/endian config/gethostname config/socklen_t config/strdup config/arc4random_buf config/strlcat config/strlcpy config/memset_s config/gss config/*.exe
	@rm -f *.o cntlm cntlm.exe configure-stamp build-stamp config/config.h cntlm-user
	@rm -f $(patsubst %, win/%, $(CYGWIN_REQS) cntlm.exe cntlm.ini LICENSE.txt resources.o setup.iss cntlm_manual.pdf)

distclean: clean
ifeq ($(findstring CYGWIN,$(OS)),)
	if [ -L debian ]; then \
	    if command -v dh_testdir && [ `id -u` = 0 ]; then \
		    debian/rules clean; \
	    elif command -v dh_testdir; then \
		    fakeroot debian/rules clean; \
	    fi \
	fi
endif
	@rm -f *.exe *.deb *.rpm *.tgz *.tar.gz *.tar.bz2 *.zip *.exe \
	  linux/rpm/specs/cntlm.spec linux/cntlm-user linux/debian/changelog tags ctags pid 2>/dev/null
	@rm -rf linux/rpm/BUILD linux/rpm/BUILDROOT 2>/dev/null


.PHONY: all install tgz tbz2 deb rpm win uninstall clean distclean
