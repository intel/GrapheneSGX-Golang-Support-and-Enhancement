# Use one of the following commands to build the manifest for Python3:
#
# - make                Building for Linux
# - make DEBUG=1        Building for Linux (with Graphene debug output)
# - make SGX=1          Building for SGX
# - make SGX=1 DEBUG=1  Building for SGX (with Graphene debug output)
#
# Use `make clean` to remove Graphene-generated files.

include ../../Scripts/Makefile.configs

# Python constants are declared in Makefile.python
include ../../Scripts/Makefile.python

# Relative path to Graphene root
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: python.manifest pal_loader
ifeq ($(SGX),1)
all: python.manifest.sgx python.token python.sig
endif

# Python dependencies (generate from ldd):
#
# For SGX, the manifest needs to list all the libraries loaded during the
# execution, so that the signer can include the file checksums.
#
# The dependencies are generated from the ldd results.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc
# binaries are already listed in the manifest template, so we can skip them
# from the ldd results.
GLIBC_DEPS = linux-vdso /lib64/ld-linux-x86-64 libc libm librt libdl libutil libpthread

# Define the python libraries which are dynamically loaded.
PY_LIBS = $(MK_PYTHONHOME)/lib-dynload/_hashlib.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so \
	  $(MK_PYTHONHOME)/lib-dynload/_ctypes.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so \
	  $(MK_PYTHONHOME)/lib-dynload/_ssl.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so \
	  $(MK_PYTHONHOME)/lib-dynload/_bz2.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so \
	  $(MK_PYTHONHOME)/lib-dynload/_lzma.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so \
	  $(MK_PYTHONHOME)/lib-dynload/_json.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so

ifeq ($(SGX),1)
PY_LIBS += $(MK_PYTHONDISTHOME)/apt_pkg.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so
endif

PY_LIBS_TRUSTED_LIBS = "sgx.trusted_files.hashlib = file:$(MK_PYTHONHOME)/lib-dynload/_hashlib.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so\\\\n" \
	  "sgx.trusted_files.ctypes = file:$(MK_PYTHONHOME)/lib-dynload/_ctypes.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so\\\\n" \
	  "sgx.trusted_files.ssl = file:$(MK_PYTHONHOME)/lib-dynload/_ssl.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so\\\\n" \
	  "sgx.trusted_files.bz2 = file:$(MK_PYTHONHOME)/lib-dynload/_bz2.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so\\\\n" \
	  "sgx.trusted_files.lzma = file:$(MK_PYTHONHOME)/lib-dynload/_lzma.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so\\\\n" \
	  "sgx.trusted_files.json = file:$(MK_PYTHONHOME)/lib-dynload/_json.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so\\\\n" \
	  "sgx.trusted_files.aptpkg = file:$(MK_PYTHONDISTHOME)/apt_pkg.cpython-$(MK_PYTHONSHORTVERSION)m-$(MK_PYTHON_ARCH_LONG).so\\\\n"

ifeq ($(MK_PYTHONSHORTVERSION),35)
PYTHON_TRUSTED_SCRIPTS = "sgx.trusted_files.python21 = file:$(MK_PYTHONHOME)/_sysconfigdata.py\\\\n" \
	  "sgx.trusted_files.python22 = file:$(MK_PYTHONHOME)/plat-$(MK_PYTHON_ARCH_LONG)/_sysconfigdata_m.py\\\\n"
else
PYTHON_TRUSTED_SCRIPTS = "sgx.trusted_files.python21 = file:$(MK_PYTHONHOME)/_sysconfigdata_m_linux_$(MK_PYTHON_ARCH_LONG).py\\\\n"
endif

# Listing all the Python dependencies, besides Glibc libraries
.INTERMEDIATE: python-ldd
python-ldd:
	@for F in $(PY_LIBS); do ldd $$F >> $@ || exit 1; done

.INTERMEDIATE: python-deps
python-deps: python-ldd
	@cat $< | awk '{if ($$2 =="=>") {split($$1,s,/\./); print s[1]}}' \
		| sort | uniq | grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) > $@

# Generating manifest rules for Python dependencies
.INTERMEDIATE: python-trusted-libs
python-trusted-libs: python-deps
	@PY_LIBS="$(PY_LIBS)" && \
	for F in `cat python-deps`; do \
		P=`ldd $$PY_LIBS | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '+-'`; \
		echo -n "sgx.trusted_files.$$N = file:$$P\\\\n"; \
	done > $@
	echo -n "$(PY_LIBS_TRUSTED_LIBS)" >> $@

.INTERMEDIATE: python-trusted-scripts
python-trusted-scripts:
	echo -n "$(MK_PYTHON_TRUSTED_SCRIPTS)" >> $@

python.manifest: python.manifest.template python-trusted-libs python-trusted-scripts
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(MK_PYTHONDISTHOME)|'"$(MK_PYTHONDISTHOME)"'|g' \
		-e 's|$$(MK_PYTHONHOME)|'"$(MK_PYTHONHOME)"'|g' \
		-e 's|$$(MK_PYTHONEXEC)|'"$(MK_PYTHONEXEC)"'|g' \
		-e 's|$$(MK_PYTHON_TRUSTED_SCRIPTS)|'"`cat python-trusted-scripts`"'|g' \
		-e 's|$$(MK_PYTHON_TRUSTED_LIBS)|'"`cat python-trusted-libs`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		-e 's|$$(ARCH_LONG)|'"$(ARCH_LONG)"'|g' \
		$< > $@

# Python manifests for SGX:
#   Generating the SGX-specific manifest (python.manifest.sgx), the enclave signature,
#   and the token for enclave initialization.

python.manifest.sgx: python.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

python.sig: python.manifest.sgx

python.token: python.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

# Extra executables
pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: check
check: all
	./run-tests.sh > OUTPUT_TEST 2> /dev/null
	@grep -q "Success 1/3" OUTPUT_TEST
	@grep -q "Success 2/3" OUTPUT_TEST
	@grep -q "Success 3/3" OUTPUT_TEST
	@rm OUTPUT_TEST

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader OUTPUT* *.PID
	$(RM) -r scripts/__pycache__

.PHONY: distclean
distclean: clean
