#
# Copyright (c) 2025 Igor Belwon
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from unicorn import *
from unicorn.arm64_const import *

# TODO: Tidy the other registers :(
UART_BASE = 0x10540000
UART_TX_REG = 0x20


def uart_char_out_handler(mu, address, size, value, user_data, shit):
    char = chr(user_data & 0xFF)
    if char == '\n':
        print('\r', end='')
    print(char, end='')


def print_cpu_state(mu):
    # Print the program counter (PC)
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f"PC: 0x{pc:016x}")

    for i in range(32):
        reg = mu.reg_read(UC_ARM64_REG_X0 + i)
        print(f"X{i}: 0x{reg:016x}")


def emulate_bootloader(binary_path):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Map memory for the binary
    memory_base = 0xF8800000
    mu.mem_map(memory_base, 0x00F00000)

    # Map memory for the MMU and some peris
    mu.mem_map(0x80000000, 0x10000)

    # UART gpios
    mu.mem_map(0x10430000, 0x1000)

    # UART IP, USI, etc.
    mu.mem_map(UART_BASE, 0x1000)
    mu.mem_write(UART_BASE + UART_TX_REG, b'')
    mu.hook_add(UC_HOOK_MEM_WRITE, uart_char_out_handler,
                begin=UART_BASE, end=UART_BASE + 0x1000)

    # ChipID
    mu.mem_map(0x10000000, 0x400)
    mu.mem_write(0x10000000 + 0x05, b'\x30')
    mu.mem_write(0x10000000 + 0x06, b'\xE9')

    # GIC
    mu.mem_map(0x10100000, 0x3000)

    # MCT
    mu.mem_map(0x10040000, 0x400)

    with open(binary_path, "rb") as f:
        binary = f.read()

    mu.mem_write(memory_base, binary)
    mu.reg_write(UC_ARM64_REG_PC, memory_base)

    # Start emulation
    try:
        print("Starting emulation...")
        mu.emu_start(memory_base, memory_base + len(binary))

    except UcError as e:
        print(f"Error: {e}")
        print_cpu_state(mu)


# Path to your bootloader binary
binary_path = 'build-universal9830_bringup/lk.bin'

# Start the emulation
emulate_bootloader(binary_path)
