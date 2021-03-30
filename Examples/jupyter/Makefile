# Use one of the following commands to build the manifest for Python3:
#
# - make                Building for Linux
# - make DEBUG=1        Building for Linux (with Graphene debug output)
# - make SGX=1          Building for SGX
# - make SGX=1 DEBUG=1  Building for SGX (with Graphene debug output)
#
# Use `make clean` to remove Graphene-generated files.

GRAPHENEDIR ?= ../..

LOCAL_IKERNEL_DIR := $(HOME)/.local/share/jupyter/kernels
IKERNEL_NAME_GRA := grapython
IKERNEL_NAME_SGX := sgxpython
IKERNEL_SGX_DIR := $(LOCAL_IKERNEL_DIR)/$(IKERNEL_NAME_SGX)
IKERNEL_GRA_DIR := $(LOCAL_IKERNEL_DIR)/$(IKERNEL_NAME_GRA)

include $(GRAPHENEDIR)/Scripts/Makefile.configs

# Python constants are declared in Makefile.python
include $(GRAPHENEDIR)/Scripts/Makefile.python

# Relative path to Graphene root
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

UBUNTU_VER = $(shell lsb_release --short --id)$(shell lsb_release --short --release)

.PHONY: all
all: python.manifest pal_loader
ifeq ($(SGX),1)
all: python.manifest.sgx python.sig python.token
endif

# Define the python libraries which are dynamically loaded.
PY_LIBS = $(PYTHONHOME)/lib-dynload/_hashlib.cpython-$(PYTHONSHORTVERSION)m-$(PYTHON_ARCH_LONG).so \
	  $(PYTHONHOME)/lib-dynload/_ctypes.cpython-$(PYTHONSHORTVERSION)m-$(PYTHON_ARCH_LONG).so \
	  $(PYTHONHOME)/lib-dynload/_ssl.cpython-$(PYTHONSHORTVERSION)m-$(PYTHON_ARCH_LONG).so \
	  $(PYTHONHOME)/lib-dynload/_bz2.cpython-$(PYTHONSHORTVERSION)m-$(PYTHON_ARCH_LONG).so \
	  $(PYTHONHOME)/lib-dynload/_lzma.cpython-$(PYTHONSHORTVERSION)m-$(PYTHON_ARCH_LONG).so \
	  $(PYTHONHOME)/lib-dynload/_json.cpython-$(PYTHONSHORTVERSION)m-$(PYTHON_ARCH_LONG).so

ifeq ($(SGX),1)
PY_LIBS += $(PYTHONDISTHOME)/apt_pkg.cpython-$(PYTHONSHORTVERSION)m-$(PYTHON_ARCH_LONG).so
endif

ifeq ($(PYTHONSHORTVERSION),35)
PYTHON_TRUSTED_SCRIPTS = sgx.trusted_files.python21 = \\\"file:$(PYTHONHOME)/_sysconfigdata.py\\\"\\n \
	  sgx.trusted_files.python22 = \\\"file:$(PYTHONHOME)/plat-$(PYTHON_ARCH_LONG)/_sysconfigdata_m.py\\\"\\n
else
PYTHON_TRUSTED_SCRIPTS = sgx.trusted_files.python21 = \\\"file:$(PYTHONHOME)/_sysconfigdata_m_linux_$(PYTHON_ARCH_LONG).py\\\"\\n
endif

# Generate manifest rules for Python dependencies.
# We'll duplicate some Glibc libraries (which Graphene provides in a customized version), but
# there's no harm in this.
.INTERMEDIATE: trusted-libs
trusted-libs: ../common_tools/get_deps.sh
	../common_tools/get_deps.sh $(PY_LIBS) > $@


python.manifest: python.manifest.template trusted-libs
	(sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
	     -e 's|$$(GRAPHENE_LOG_LEVEL)|'"$(GRAPHENE_LOG_LEVEL)"'|g' \
	     -e 's|$$(PYTHONDISTHOME)|'"$(PYTHONDISTHOME)"'|g' \
	     -e 's|$$(PYTHONHOME)|'"$(PYTHONHOME)"'|g' \
	     -e 's|$$(PYTHONEXEC)|'"$(PYTHONEXEC)"'|g' \
	     -e 's|$$(PYTHONSHORTVERSION)|'"$(PYTHONSHORTVERSION)"'|g' \
	     -e 's|$$(PYTHON_ARCH_LONG)|'"$(PYTHON_ARCH_LONG)"'|g' \
	     -e 's|$$(PYTHON_TRUSTED_SCRIPTS)|'"$(PYTHON_TRUSTED_SCRIPTS)"'|g' \
	     -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
	     -e 's|$$(ARCH_LONG)|'"$(ARCH_LONG)"'|g' \
	     $<; \
	cat trusted-libs) > $@

# Python manifests for SGX:
#   Generating the SGX-specific manifest (python.manifest.sgx), the enclave signature,
#   and the token for enclave initialization.

python.manifest.sgx: python.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< \
		-output $@

python.sig: python.manifest.sgx

python.token: python.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output $@ -sig $<

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

$(IKERNEL_GRA_DIR):
	mkdir -p $(IKERNEL_GRA_DIR)

$(IKERNEL_SGX_DIR):
	mkdir -p $(IKERNEL_SGX_DIR)

.PHONY: FORCE
FORCE:

ifeq ($(SGX),1)
kernel.json: kernel.json.template FORCE
	(sed -e 's|$$(IKERNEL_NAME)|'"$(IKERNEL_NAME_SGX)"'|g' \
	     -e 's|$$(PAL_LOADER)|'"$(realpath $(GRAPHENEDIR))/Runtime/pal-Linux-SGX"'|g' \
	     -e 's|$$(PAL_LIB)|'"$(realpath $(GRAPHENEDIR))/Pal/src/host/Linux-SGX/libpal.so"'|g' \
	     $<) > $@
else
kernel.json: kernel.json.template FORCE
	(sed -e 's|$$(IKERNEL_NAME)|'"$(IKERNEL_NAME_GRA)"'|g' \
	     -e 's|$$(PAL_LOADER)|'"$(realpath $(GRAPHENEDIR))/Runtime/pal-Linux"'|g' \
	     -e 's|$$(PAL_LIB)|'"$(realpath $(GRAPHENEDIR))/Pal/src/host/Linux/libpal.so"'|g' \
	     $<) > $@
endif

.PHONY: deploy
ifeq ($(SGX),1)
deploy: kernel.json python.manifest.sgx python.sig python.token | $(IKERNEL_SGX_DIR)
	cp $^ $(IKERNEL_SGX_DIR)
else
deploy: kernel.json python.manifest | $(IKERNEL_GRA_DIR)
	cp $^ $(IKERNEL_GRA_DIR)
endif

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
	$(RM) kernel.json
	$(RM) -r $(IKERNEL_GRA_DIR)
	$(RM) -r $(IKERNEL_SGX_DIR)

.PHONY: distclean
distclean: clean
