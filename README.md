# SSH Proxy Core

A C implementation of an SSH proxy core library.

## Project Structure

```
ssh-proxy-core/
├── src/           # Source files
├── include/       # Header files
├── tests/         # Test files
├── build/         # Build output directory
├── Makefile       # Build configuration
└── README.md      # This file
```

## Building

### Prerequisites

- GCC compiler
- Make

### Build Commands

```bash
# Build debug version (default)
make

# Build release version
make release

# Build and run tests
make test

# Clean build artifacts
make clean

# Build and run the program
make run
```

## Usage

After building, you can run the program:

```bash
./build/ssh-proxy-core
```

## Development

### Adding New Features

1. Add header declarations to `include/ssh_proxy.h`
2. Implement functions in `src/ssh_proxy.c`
3. Add tests in `tests/test_ssh_proxy.c`
4. Run tests with `make test`

### Debugging

Build with debug flags:
```bash
make debug
gdb ./build/ssh-proxy-core
```

## License

[Add your license here]
# ssh-proxy-core
