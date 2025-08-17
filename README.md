# SSH Proxy Core

A C implementation of an SSH proxy core library with C++ Google Test integration.

## Project Structure

```
ssh-proxy-core/
├── src/              # Source files (.c)
├── include/          # Header files (.h)
├── tests/            # Test files (.cpp with Google Test)
├── build/            # Build output directory (CMake)
├── CMakeLists.txt    # CMake build configuration
└── README.md         # This file
```

## Building

### Prerequisites

- CMake (>= 3.14)
- GCC/G++ compiler
- Google Test (libgtest-dev)
- pkg-config

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y cmake libgtest-dev pkg-config build-essential
```

### Build Commands

```bash
# Create build directory
mkdir build && cd build

# Configure (Debug build by default)
cmake ..

# Build the project
cmake --build .

# Or for release build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

### Alternative: Out-of-source build
```bash
# Debug build
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug

# Release build  
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
```

### Running Tests

```bash
# From build directory
ctest

# Or run tests with verbose output
ctest --verbose

# Or run the test executable directly
./test_runner
```

## Usage

After building, you can run the program:

```bash
# From build directory
./ssh-proxy-core

# Or using CMake custom target
cmake --build . --target run
```

## Development

### Adding New Features

1. Add header declarations to `include/ssh_proxy.h`
2. Implement functions in `src/ssh_proxy.c`
3. Add tests in `tests/test_ssh_proxy.cpp` (using Google Test)
4. Run tests with `ctest` or `ctest --verbose`

### Debugging

Build with debug flags and use GDB:
```bash
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
gdb ./build-debug/ssh-proxy-core
```

### Project Management

```bash
# Clean build artifacts
rm -rf build/

# Install to system (requires sudo)
cmake --build . --target install

# Create distribution packages
cmake --build . --target package
```

### CMake Targets

- `ssh-proxy-core` - Main executable
- `ssh_proxy_lib` - Core library
- `test_runner` - Test executable
- `run` - Custom target to build and run the main program
- `install` - Install to system
- `package` - Create distribution packages

## Testing

This project uses Google Test for unit testing. Tests are written in C++ but test the C library through proper extern "C" linkage.

### Running Specific Tests

```bash
# Run with test filtering
./test_runner --gtest_filter="SshProxyTest.*"

# Run with different output formats
./test_runner --gtest_output=xml:test_results.xml
```

## License

[Add your license here]
