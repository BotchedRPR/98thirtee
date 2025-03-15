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

def hook_mem_read_unmapped(uc, access, address, size, value, user_data):
    print("INVALID MEMORY READ")
    print("ADDR: " + hex(address))
    pass

def emulate_bootloader(binary_path):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Map memory for the binary
    memory_base = 0xF8800000
    mu.mem_map(memory_base, 0x00F00000)

    # Map memory for the MMU and some peris
    mu.mem_map(0x80000000, 0x10000)

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

    # Power
    mu.mem_map(0x15860000, 0x1000)

    # ECT
    mu.mem_map(0x90000000, 0x14000)

    # ACPM (FlexPMU)
    mu.mem_map(0x90014000, 0xf0000)

    # iRAM
    mu.mem_map(0x02020000, 0x40000)
    mu.mem_write(0x02039000, b'\xe8')
    mu.mem_write(0x02039000 + 0x01, b'\x00')

    # ADC
    mu.mem_map(0x15C40000, 0x400)

    # GPIO - PERIC0
    mu.mem_map(0x10430000, 0x100000)

    # GPIO - PERIC1
    mu.mem_map(0x10720000, 0x200000)

    # GPIO - ALIVE
    mu.mem_map(0x15840000, 0x20000)

    # SPEEDY1
    mu.mem_map(0x15940000, 0x10000)

    # SPEEDY2
    mu.mem_map(0x15950000, 0x10000)

    # MMC block - to be split
    mu.mem_map(0x13040000, 0x10000)

    # MMC base
    mu.mem_map(0x132E0000, 0x1000)

    # CMU_TOP
    mu.mem_map(0x1a330000, 0x8000)

    # CMU_HSI1
    mu.mem_map(0x13000000, 0x8000)

    # Debug stuff
    mu.mem_map(0x80000000 + 0x7D900000, 0x10000)

    # exynos_boot bases
    mu.mem_map(0x84000000, 0x6000000)
    mu.mem_map(0x8a000000, 0x1000000)
    mu.mem_map(0x80080000, 0x3f80000)
    mu.mem_map(0x8B000000, 0x1000000)
    mu.mem_map(0x94000000, 0x1000000)

    # Debug mailbox
    mu.mem_map(0x158D0000, 0x400)

    # More dfd debug stuff... Eh
    mu.mem_map(0xBFFFE000, 0xf000)

    # TMU TOP
    mu.mem_map(0x10090000, 0x10000)
    mu.mem_map(0x100A0000, 0x10000)

    # ACPM
    mu.mem_map(0x206bc00, 0x400)

    # USB (Please hook me)
    mu.mem_map(0x10a00000, 0x100000)
    mu.mem_map(0x10c00000, 0x100000)
    mu.mem_map(0x10e00000, 0x100000)

    with open(binary_path, "rb") as f:
        binary = f.read()

    mu.mem_write(memory_base, binary)
    mu.reg_write(UC_ARM64_REG_PC, memory_base)

    # Debug aids
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped, None)

    # Start emulation
    try:
        print("Starting emulation...")
        mu.emu_start(memory_base, memory_base + len(binary))

    except UcError as e:
        print(f"Error: {e}")
        print_cpu_state(mu)


binary_path = 'build-universal9830_bringup/lk.bin'

# Start the emulation
emulate_bootloader(binary_path)
