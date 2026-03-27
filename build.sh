#!/bin/bash

set -e

# Build configuration
BINARY_NAME="darkscan"
BIN_DIR="./bin"
INSTALL_BASE="/usr/local/darkscan"
SYMLINK_TARGET="/usr/local/bin/darkscan"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

# Build function
build() {
    print_info "Building ${BINARY_NAME}..."

    # Create bin directory
    mkdir -p "${BIN_DIR}"

    # Download dependencies
    print_info "Downloading dependencies..."
    go mod download
    go mod tidy

    # Build the binary
    print_info "Compiling binary..."
    go build -o "${BIN_DIR}/${BINARY_NAME}" ./cmd/darkscan

    print_success "Build complete: ${BIN_DIR}/${BINARY_NAME}"
}

# Install function
install() {
    # Check if binary exists
    if [ ! -f "${BIN_DIR}/${BINARY_NAME}" ]; then
        print_error "Binary not found. Building first..."
        build
    fi

    print_info "Installing ${BINARY_NAME}..."

    # Check for sudo privileges
    if [ "$EUID" -ne 0 ]; then
        print_error "Installation requires sudo privileges"
        print_info "Rerunning with sudo..."
        sudo "$0" install
        exit $?
    fi

    # Create base directory structure
    print_info "Creating directory structure at ${INSTALL_BASE}..."
    mkdir -p "${INSTALL_BASE}/bin"
    mkdir -p "${INSTALL_BASE}/rules"
    mkdir -p "${INSTALL_BASE}/signatures"
    mkdir -p "${INSTALL_BASE}/config"

    # Copy binary
    print_info "Copying binary to ${INSTALL_BASE}/bin/..."
    cp "${BIN_DIR}/${BINARY_NAME}" "${INSTALL_BASE}/bin/${BINARY_NAME}"
    chmod 755 "${INSTALL_BASE}/bin/${BINARY_NAME}"

    # Create symlink
    print_info "Creating symlink ${SYMLINK_TARGET} -> ${INSTALL_BASE}/bin/${BINARY_NAME}"
    ln -sf "${INSTALL_BASE}/bin/${BINARY_NAME}" "${SYMLINK_TARGET}"

    # Set proper ownership (root:wheel on macOS, root:root on Linux)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        chown -R root:wheel "${INSTALL_BASE}"
    else
        chown -R root:root "${INSTALL_BASE}"
    fi

    print_success "Installation complete!"
    print_info "Binary installed to: ${INSTALL_BASE}/bin/${BINARY_NAME}"
    print_info "Symlink created: ${SYMLINK_TARGET}"
    print_info "You can now run 'darkscan' from anywhere"
}

# Uninstall function
uninstall() {
    print_info "Uninstalling ${BINARY_NAME}..."

    # Check for sudo privileges
    if [ "$EUID" -ne 0 ]; then
        print_error "Uninstallation requires sudo privileges"
        print_info "Rerunning with sudo..."
        sudo "$0" uninstall
        exit $?
    fi

    # Remove symlink
    if [ -L "${SYMLINK_TARGET}" ]; then
        print_info "Removing symlink ${SYMLINK_TARGET}..."
        rm -f "${SYMLINK_TARGET}"
    fi

    # Remove installation directory
    if [ -d "${INSTALL_BASE}" ]; then
        print_info "Removing ${INSTALL_BASE}..."
        rm -rf "${INSTALL_BASE}"
    fi

    print_success "Uninstallation complete!"
}

# Clean function
clean() {
    print_info "Cleaning build artifacts..."
    rm -rf "${BIN_DIR}"
    go clean
    print_success "Clean complete"
}

# Show help
show_help() {
    cat << EOF
DarkScan Build Script

Usage: $0 [command]

Commands:
    build       Build the binary (default, outputs to ${BIN_DIR}/)
    install     Install to ${INSTALL_BASE}/ with symlink to ${SYMLINK_TARGET}
    uninstall   Remove installation and symlink
    clean       Remove build artifacts
    help        Show this help message

Examples:
    $0              # Build binary
    $0 build        # Build binary
    $0 install      # Build and install (requires sudo)
    sudo $0 install # Install with sudo
    $0 clean        # Clean build artifacts

EOF
}

# Main logic
main() {
    case "${1:-build}" in
        build)
            build
            ;;
        install)
            install
            ;;
        uninstall)
            uninstall
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
