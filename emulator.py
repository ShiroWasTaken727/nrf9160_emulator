import math
import struct

from unicorn import *
from unicorn.arm_const import *


# we need to align the firmware size to 4KB for memory mapping
def align_size(bytes_size, four_kb=4096):
    return math.ceil(bytes_size / four_kb) * four_kb


def align_4_bytes(requested_size):
    return math.ceil(requested_size / 4) * 4


# hooks for tracing basic blocks and instructions (debugging)
def hook_block(uc, address, size, user_data):
    print(">>> Basic block at 0x%x, size = 0x%x" % (address, size))


# hooking code for svc instructions to handle system calls
def hook_code(uc, address, size, user_data):
    # print(">>> Instruction at 0x%x, size = 0x%x" % (address, size))
    global HEAP_PTR

    free = 0x000D770E
    message_malloc = 0x000D7C16
    FUN_000dd190 = 0x000DD190
    FUN_000d84bc = 0x000D84BC
    FUN_000db380 = 0x000DB380
    if address == 0xDA7E0:

        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> At function entry, LR={hex(lr)}")

    if address == free:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Skipping free()")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == FUN_000dd190:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Skipping FUN_000dd190")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d84bc:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Found FUN_000d84bc. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000db380:
        print(">>> Entered the parser function (FUN_000db380)")
        r0 = uc.reg_read(UC_ARM_REG_R0)
        print(f">>> Parser function argument R0: {hex(r0)}")

    if address == message_malloc:
        requested_size = uc.reg_read(UC_ARM_REG_R0)
        print(
            f">>> Found message_malloc. Allocating {requested_size} bytes at {hex(HEAP_PTR)}"
        )
        if HEAP_PTR + requested_size > HEAP_MAX:
            print(">>> Heap overflow detected. Cannot allocate more memory.")
            uc.reg_write(UC_ARM_REG_R0, 0)  # return null pointer
        else:
            uc.reg_write(UC_ARM_REG_R0, HEAP_PTR)  # return heap pointer
            HEAP_PTR += align_4_bytes(requested_size)

        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == 0x0:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> ERROR: CPU jumped to 0x0. LR: {hex(lr)}")

        # force the emulator to stop instantly for a clean terminal output
        uc.emu_stop()
        return

    if address == 0xC0FFEE:
        print(">>> Reached exit address ☕. Stopping emulation.")
        uc.emu_stop()
        return


def hook_memory_invalid(uc, memory_type, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    lr = uc.reg_read(UC_ARM_REG_LR)
    print(f">>> Memory error at {hex(address)}, PC={hex(pc)}, LR={hex(lr)}")
    return False


# load the firmware into memory
FIRMWARE = open("modem_firmware.bin", "rb").read()
BASE_ADDRESS = 0x50000

# start at modem_system_ram end - 4 to avoid going over the edge
STACK_ADDRESS = 0x20000000 + 0x8000 - 4

# start the heap in the middle of the ram
HEAP_ADDRESS = 0x20005000
HEAP_MAX = 0x20007000  # heap size 8KB (arbitrary)
HEAP_PTR = HEAP_ADDRESS

# write AT string outside of heap to avoid overwriting in case of malloc
AT_STRING_ADDRESS = 0x20004000
MESSAGE_DATA_ADDR = 0x0  # we will write the message structure here later

# emulation starting point: start of the process_message function in the firmware
process_message = 0x000DA7E0

print("Emulating modem firmware...")
print(f"Emulating: process_message - 0x{process_message:x}")

# set up Unicorn emulator
try:
    # initialize emulator in ARM mode and thumb mode for Cortex-M ISA
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    print(f"Firmware size: {hex(len(FIRMWARE))}")
    print(f"Aligned size: {hex(align_size(len(FIRMWARE)))}")

    # map memory for the firmware needs to be aligned 4KB
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

    # prepare AT command payload for testing
    payload = b"AT+CFUN?\x00"  # simple payload for testing read
    # payload = b"AT+CFUN=0\x00"  # dummy payload for testing set
    # payload = b'AT+CGAUTH=1,1,"' + (b'"' * 255) + b';+CFUN=0;","password"\x00' # payload for testing quote vulnerability (no vulnerability yet)

    # write the payload to memory at AT_STRING_ADDRESS
    mu.mem_write(AT_STRING_ADDRESS, payload)

    # define outside of heap to avoid overwriting in case of malloc again
    MESSAGE_DATA_ADDR = 0x20003000

    # source: https://docs.python.org/3/library/struct.html
    # construct the message structure for process_message
    # format: command_id (2 bytes) [0], flags (2 bytes) [1], padding (4 bytes) [2],
    # payload pointer (4 bytes) [3], payload length (4 bytes) [4]
    message_data = struct.pack("<HHIII", 1, 0xFFFF, 0, AT_STRING_ADDRESS, len(payload))

    # load the message structure into MESSAGE_DATA_ADDR
    mu.mem_write(MESSAGE_DATA_ADDR, message_data)

    # load message pointer into r0 and payload length into r1 (first arg for process_message)
    mu.reg_write(UC_ARM_REG_R0, MESSAGE_DATA_ADDR)

    # set the stack pointer to the address
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)

    # use magic number 0xC0FFEE as the exit address for the end of the emulation (arbitrarily defined)
    EXIT_ADDRESS = 0xC0FFEE
    mu.reg_write(UC_ARM_REG_LR, EXIT_ADDRESS)

    # add hooks for memory errors, basic blocks (debugging) and for svc instructions
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_memory_invalid)
    mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # start emulation at the process_message function and end at the exit address we set in LR
    # | 1 to set thumb mode bit in the address
    mu.emu_start(process_message | 1, EXIT_ADDRESS)

except UcError as e:
    print(f"Failed: {e}")
    exit(1)
