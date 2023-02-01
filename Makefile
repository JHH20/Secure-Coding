.DELETE_ON_ERROR:

# Disable PIE and Use Partial RELRO: -no-pie
# Disable canary: -fno-stack-protector
# Disable NX: -z execstack
# Debugging symbol: -g (for stepping through at source level in gdb)
OPTS = -g -no-pie -fno-stack-protector

TARGETS_OUT = $(subst src/,build/,$(wildcard src/*))
TARGETS = $(subst build/,,$(TARGETS_OUT))

.PHONY: help clean all $(TARGETS)

help:
	@echo 'Valid targets: $(TARGETS) ; all clean help(this)'

clean:
	rm -rf build
	rm -f core
	mkdir build

all: $(TARGETS)

$(TARGETS): %: build/%
	@echo 'Built [$@] into [build/$@]'

.SECONDEXPANSION:
FSRC = $(wildcard src/$1/*.cpp)
HSRC = $(wildcard src/$1/*.h) $(wildcard src/$1/*.hpp)

$(TARGETS_OUT): build/%: $$(call FSRC,%) $$(call HSRC,%)
	@echo 'Building [$@]...'
	@echo 'Detected change in:' $?
	g++ $(OPTS) -o $@ $(call FSRC,$(subst build/,,$@))
