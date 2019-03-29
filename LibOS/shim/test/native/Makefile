special_executables = static pie
c_executables = $(filter-out $(special_executables),$(patsubst %.c,%,$(wildcard *.c)))
cxx_executables = $(patsubst %.cpp,%,$(wildcard *.cpp))
manifests = $(patsubst %.template,%,$(wildcard *.manifest.template)) manifest

STATIC_EXECUTABLES_SOURCES = \
	alarm.c \
	alarm_loop.c \
	clone.c \
	exec_fork.c \
	fork.c \
	fork_bomb.c \
	fork_exec.c \
	vfork.c \
	vfork_exec.c
STATIC_EXECUTABLES = $(patsubst %.c, static-%, $(STATIC_EXECUTABLES_SOURCES))
special_executables += $(STATIC_EXECUTABLES)

exec_target = $(special_executables) $(c_executables) $(cxx_executables) ls.manifest
target = $(exec_target) $(manifests)

level = ../
include ../Makefile

ifeq ($(findstring x86_64,$(SYS))$(findstring linux,$(SYS)),x86_64linux)

%: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(CFLAGS-$@) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

%.m: %.m.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(CFLAGS-$@) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

%: %.cpp
	@echo [ $@ ]
	@$(CXX) $(CXXFLAGS) $(CXXFLAGS-$@) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

$(c_executables): CFLAGS += $(if $(findstring .libos,$@),$(CFLAGS-libos),)
$(cxx_executables): CXXFLAGS += $(if $(findstring .libos,$@),$(CFLAGS-libos),)
CFLAGS-static = -static
CFLAGS-pie = -fPIC --pie
CFLAGS-syscall = -I$(PALDIR)/../include -I$(PALDIR)/host/$(PAL_HOST)

$(STATIC_EXECUTABLES): CFLAGS += -static
$(STATIC_EXECUTABLES): static-%: %.c
	@echo [ $@ ]
	@$(CC) $(CFLAGS) $(CFLAGS-$@) -o $@ $< \
	$(shell echo $@ | sed 's/^[^\.]*//g' | sed 's/\./ -l/g')

else
.IGNORE: $(special_executables) $(c_executables) $(cxx_executables)
$(special_executables) $(c_executables) $(cxx_executables):
endif
