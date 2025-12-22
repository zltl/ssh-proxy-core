# SSH Proxy Core - Makefile
# Modern C Project Build System

# Compiler and flags
CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror
CFLAGS += -D_POSIX_C_SOURCE=200809L
LDFLAGS :=
LIBS :=

# libssh dependency
LIBSSH_CFLAGS := $(shell pkg-config --cflags libssh 2>/dev/null)
LIBSSH_LIBS := $(shell pkg-config --libs libssh 2>/dev/null)
CFLAGS += $(LIBSSH_CFLAGS)
LIBS += $(LIBSSH_LIBS)

# Directories
SRC_DIR := src
INC_DIR := include
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
LIB_DIR := lib
TEST_DIR := tests

# Target
TARGET := ssh-proxy-core
LIB_TARGET := libsshproxy.a

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

# Test files
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# Build types
DEBUG_FLAGS := -g -O0 -DDEBUG
RELEASE_FLAGS := -O2 -DNDEBUG

# Default to debug build
BUILD_TYPE ?= debug

ifeq ($(BUILD_TYPE),release)
    CFLAGS += $(RELEASE_FLAGS)
else
    CFLAGS += $(DEBUG_FLAGS)
endif

# Include paths
CFLAGS += -I$(INC_DIR) -I$(TEST_DIR)

# Phony targets
.PHONY: all clean test run install uninstall dirs debug release help check-deps

# Default target
all: check-deps dirs $(BIN_DIR)/$(TARGET)

# Check dependencies
check-deps:
	@pkg-config --exists libssh || { \
		echo "Error: libssh not found. Please install:"; \
		echo "  Ubuntu/Debian: sudo apt-get install libssh-dev"; \
		echo "  RHEL/CentOS:   sudo yum install libssh-devel"; \
		echo "  macOS:         brew install libssh"; \
		echo "  Or build from source: https://www.libssh.org/get-it/"; \
		exit 1; \
	}

# Debug build
debug:
	$(MAKE) BUILD_TYPE=debug all

# Release build
release:
	$(MAKE) BUILD_TYPE=release all

# Create directories
dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Link executable
$(BIN_DIR)/$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Build static library
lib: dirs $(filter-out $(OBJ_DIR)/main.o,$(OBJS))
	ar rcs $(BIN_DIR)/$(LIB_TARGET) $(filter-out $(OBJ_DIR)/main.o,$(OBJS))

# Build and run tests
test: dirs $(TEST_BINS)
	@echo "Running tests..."
	@for test in $(TEST_BINS); do \
		echo ""; \
		$$test || exit 1; \
	done

$(BIN_DIR)/test_%: $(TEST_DIR)/test_%.c $(filter-out $(OBJ_DIR)/main.o,$(OBJS))
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(filter-out $(OBJ_DIR)/main.o,$(OBJS)) $(LIBS)

# Run the program
run: all
	@$(BIN_DIR)/$(TARGET)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Install (requires root)
PREFIX ?= /usr/local
install: release
	install -d $(PREFIX)/bin
	install -m 755 $(BIN_DIR)/$(TARGET) $(PREFIX)/bin/
	install -d $(PREFIX)/include/ssh_proxy
	install -m 644 $(INC_DIR)/*.h $(PREFIX)/include/ssh_proxy/

# Uninstall
uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)
	rm -rf $(PREFIX)/include/ssh_proxy

# Format code (requires clang-format)
format:
	@find $(SRC_DIR) $(INC_DIR) $(TEST_DIR) -name '*.c' -o -name '*.h' | xargs clang-format -i

# Static analysis (requires cppcheck)
check:
	@cppcheck --enable=all --std=c11 -I$(INC_DIR) $(SRC_DIR) $(TEST_DIR)

# Include dependency files
-include $(DEPS)

# Help
help:
	@echo "SSH Proxy Core - Build System"
	@echo ""
	@echo "Usage: make [target] [BUILD_TYPE=debug|release]"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the project (default)"
	@echo "  debug    - Build with debug flags"
	@echo "  release  - Build with release flags"
	@echo "  lib      - Build static library"
	@echo "  test     - Build and run tests"
	@echo "  run      - Build and run the program"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system (PREFIX=/usr/local)"
	@echo "  format   - Format source code"
	@echo "  check    - Run static analysis"
	@echo "  help     - Show this help message"
