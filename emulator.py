import math

from unicorn import *
from unicorn.arm_const import *


# we need to align the firmware size to 4KB for memory mapping
def align_size(bytes_size, four_kb=4096):
    return math.ceil(bytes_size / four_kb) * four_kb


# hooks for tracing basic blocks and instructions (debugging)
def hook_block(uc, address, size, user_data):
    print(">>> Basic block at 0x%x, size = 0x%x" % (address, size))


# hooking code for svc instructions to handle system calls
def hook_code(uc, address, size, user_data):
    print(">>> Instruction at 0x%x, size = 0x%x" % (address, size))


def hook_memory_invalid(uc, memory_type, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    print(f">>> Memory error at 0x{hex(address)}, PC=0x{hex(pc)}, LR=0x{hex(lr)}")
    return False


# load the firmware into memory
FIRMWARE = open("modem_firmware.bin", "rb").read()
BASE_ADDRESS = 0x50000

# start at modem_system_ram end
STACK_ADDRESS = 0x20000000 + 0x8000 - 4

process_message = 0x000DA7E0

print("Emulating modem firmware...")
print(f"Emulating: process_message - 0x{process_message:x}")

try:
    # initialize emulator in ARM mode and thumb mode for Cortex-M
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    print(f"Firmware size: {hex(len(FIRMWARE))}")
    print(f"Aligned size: {hex(align_size(len(FIRMWARE)))}")

    # map memory for the firmware
    mu.mem_map(0x50000, align_size(len(FIRMWARE)))  # firmware ram

    # write the firmware to the mapped memory
    mu.mem_write(BASE_ADDRESS, FIRMWARE)

    # map memory regions
    mu.mem_map(0x0, 0x1000)  # modem_reg_dump
    mu.mem_map(0x240000, 0x40000)  # modem_fota_area
    mu.mem_map(0x800000, 0x40000)  # modem_m4_data_tcm
    mu.mem_map(0x20000000, 0x8000)  # modem_system_ram
    mu.mem_map(0x22000000, 0x20000)  # modem_DSP_ram
    mu.mem_map(0x40000000, 0x20000000)  # peripheral
    mu.mem_map(0xE0000000, 0x20000000)  # system_SYS

    # initialize to 0 for now, but this should be the message_data pointer
    mu.reg_write(UC_ARM_REG_R0, 0x0)
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
    mu.reg_write(UC_ARM_REG_LR, process_message + 0x1000)

    # add hooks
    mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_memory_invalid)

    # start emulation at the process_message function
    # emulate 4kb only for now
    mu.emu_start(process_message | 1, process_message + 0x1000)

except UcError as e:
    print(f"Failed: {e}")
    exit(1)
