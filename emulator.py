import math
import struct
import sys

from unicorn import *
from unicorn.arm_const import *

allocs = {}

# load the firmware into memory
FIRMWARE = open("modem_firmware.bin", "rb").read()
BASE_ADDRESS = 0x50000

# start at modem_system_ram end - 4 to avoid going over the edge
STACK_ADDRESS = 0x20000000 + 0x8000 - 4

HEAP_ADDRESS = 0x30000000
HEAP_MAX = 0x30100000  # heap size 1MB
HEAP_PTR = HEAP_ADDRESS

# write AT string outside of heap to avoid overwriting in case of malloc
AT_STRING_ADDRESS = 0x20004000
MESSAGE_DATA_ADDR = 0x0  # we will write the message structure here later

# emulation starting point: start of the process_message function in the firmware
process_message = 0x000DA7E0

print("Emulating modem firmware...")
print(f"Emulating: process_message - 0x{process_message:x}")


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

    # Todo: remove later
    TEST_HEAP_OVERFLOW = 0xDA896

    sleep = 0x000D7EE6

    guard_size = 0x20
    free = 0x000D770E
    message_malloc = 0x000D7C16
    alloc_000d753e = 0x000D753E
    alloc_0005c0f4 = 0x0005C0F4

    send_AT_response = 0x000DCF5C

    FUN_000dd190 = 0x000DD190
    FUN_000d84bc = 0x000D84BC
    FUN_000db380 = 0x000DB380
    FUN_000d7ebc = 0x000D7EBC
    FUN_000da004 = 0x000DA004
    FUN_000131ce8 = 0x00131CE8  # pal_msg_send_to
    FUN_000d8562 = 0x000D8562
    FUN_000d84c4 = 0x000D84C4
    FUN_000d84ac = 0x000D84AC
    FUN_000d7f10 = 0x000D7F10
    FUN_000d7748 = 0x000D7748

    diag_tracing_functions = [
        0x0012D534,
        0x0012D55E,
        0x00066998,
        0x0012D348,
        0x0012CF40,
        0x00066A24,
    ]

    if address == TEST_HEAP_OVERFLOW:
        # overwrite first malloc backguard to be 0xBB instead pf the default guard size 0xAA
        front_guard_size = guard_size
        back_guard = 0x30000000 + front_guard_size + align_4_bytes(28)
        uc.mem_write(back_guard, b"\xbb")

    if address == FUN_000da004:
        lr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_R0, 0)  # return 0 = modem not busy
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == 0xDA7E0:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> At function entry, LR={hex(lr)}")

    if address == sleep:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Skipping sleep()")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == free:
        malloc_ptr = uc.reg_read(UC_ARM_REG_R0)

        # Double free could occur if this function already called free with a pointer and gets called again with the same pointer.
        # or if it frees something without a malloc call first so the entry does not exist in the dictionary.
        if malloc_ptr not in allocs:
            print(f">>> Double free or unknown pointer detected: {hex(malloc_ptr)}")
        else:
            requested_size = allocs[malloc_ptr]
            front_guard = uc.mem_read(malloc_ptr - guard_size, guard_size)
            back_guard = uc.mem_read(
                malloc_ptr + align_4_bytes(requested_size), guard_size
            )

            if bytes(front_guard) != b"\xaa" * guard_size:
                print(
                    f">>> Front guard does not match. Heap underflow detected: {hex(malloc_ptr)}"
                )
            if bytes(back_guard) != b"\xaa" * guard_size:
                print(
                    f">>> Back guard does not match. Heap overflow detected: {hex(malloc_ptr)}"
                )
            else:
                print(f">>> Freed: {hex(malloc_ptr)}")

            del allocs[malloc_ptr]

        lr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == FUN_000dd190:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Found FUN_000dd190. Skipping and returning to LR: {hex(lr)}")
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
    if address == FUN_000d7ebc:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Found FUN_000d7ebc. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000131ce8:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Found pal_msg_send_to. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d8562:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Found FUN_000d8562. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d84c4:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Found FUN_000d84c4. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d84ac:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Found FUN_000d84ac. Skipping and returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d7f10:
        lr = uc.reg_read(UC_ARM_REG_LR)
        r0 = uc.reg_read(UC_ARM_REG_R0)
        uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == FUN_000d7748:
        mu.mem_write(0x20002000, b"unknown string\x00")
        lr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_R0, 0x20002000)
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address in diag_tracing_functions:
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(
            f">>> Found diag tracing function at {hex(address)}. Skipping and returning to LR: {hex(lr)}"
        )
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == message_malloc or address == alloc_0005c0f4:
        requested_size = uc.reg_read(UC_ARM_REG_R0)
        malloc_size = guard_size + align_4_bytes(requested_size) + guard_size
        print(
            f">>> Found message_malloc. Allocating {requested_size} bytes at {hex(HEAP_PTR)}"
        )
        if HEAP_PTR + malloc_size > HEAP_MAX:
            print(">>> Heap overflow detected. Cannot allocate more memory.")
            uc.reg_write(UC_ARM_REG_R0, 0)  # return null pointer
        else:
            # write front guard page
            uc.mem_write(HEAP_PTR, b"\xaa" * guard_size)
            HEAP_PTR += guard_size

            req_size_ptr = HEAP_PTR
            HEAP_PTR += align_4_bytes(requested_size)

            # write back guard page
            uc.mem_write(HEAP_PTR, b"\xaa" * guard_size)
            HEAP_PTR += guard_size

            allocs[req_size_ptr] = requested_size
            uc.reg_write(UC_ARM_REG_R0, req_size_ptr)  # return heap pointer

        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f">>> Returning to LR: {hex(lr)}")
        uc.reg_write(UC_ARM_REG_PC, lr)
        return
    if address == alloc_000d753e:
        num = uc.reg_read(UC_ARM_REG_R0)
        type_size = uc.reg_read(UC_ARM_REG_R1)
        requested_size = align_4_bytes(num * type_size)

        malloc_size = guard_size + align_4_bytes(requested_size) + guard_size

        if requested_size == 0:
            print(
                f">>> Error: alloc_000d753e called with num={num}, type={type_size}. Returning null pointer."
            )
            uc.reg_write(UC_ARM_REG_R0, 0)  # return null pointer
        elif HEAP_PTR + malloc_size > HEAP_MAX:
            print(f">>> alloc_000d753e: Heap overflow. Returning null pointer.")
            uc.reg_write(UC_ARM_REG_R0, 0)
        else:
            # front guard
            uc.mem_write(HEAP_PTR, b"\xaa" * guard_size)
            HEAP_PTR += guard_size

            req_size_ptr = HEAP_PTR
            HEAP_PTR += align_4_bytes(requested_size)

            # back guard
            uc.mem_write(HEAP_PTR, b"\xaa" * guard_size)
            HEAP_PTR += guard_size

            allocs[req_size_ptr] = requested_size
            uc.reg_write(UC_ARM_REG_R0, req_size_ptr)  # return heap pointer

        lr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_PC, lr)
        return

    if address == send_AT_response:
        r0 = uc.reg_read(UC_ARM_REG_R0)
        response_bytes = bytes(uc.mem_read(r0, 32))
        response_text = response_bytes.split(b"\x00")[0]
        print(f">>> send_AT_response: {response_text}")

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
    mu.mem_map(0x800000, 0x8000)  # covers tcm_copy + tcm1
    mu.mem_map(0x80A000, 0x26000)  # covers tcm_copy2 + tcm2
    mu.mem_map(0x20000000, 0x8000)  # modem_system_ram
    mu.mem_map(0x22000000, 0x20000)  # modem_DSP_ram
    mu.mem_map(0x40000000, 0x20000000)  # peripheral
    mu.mem_map(0xE0000000, 0x20000000)  # system_SYS
    mu.mem_map(0x30000000, 0x100000)  # custom heap

    mu.mem_write(0x800000, FIRMWARE[0x19658 : 0x19658 + 0x7C8])
    mu.mem_write(0x80A000, FIRMWARE[0x16F238 : 0x16F238 + 0x1E88])

    # detect replay crash input from CLI argument or prepare a default payload for testing
    if len(sys.argv) > 1:
        print("Replaying crash from file:", sys.argv[1])
        file_path = sys.argv[1]
        crash_input = open(file_path, "rb").read()

        at_string_bytes = crash_input[14:]
        at_string = at_string_bytes + b"\x00"

        command_id = 1
        flags = 0x00FF
        unknown_bytes = 0
        data_ptr = AT_STRING_ADDRESS
        data_len = len(at_string_bytes)
        print(f"Data_len = 0x{data_len:x} ({data_len})")

        message_data = struct.pack(
            "<HHIII", command_id, flags, unknown_bytes, data_ptr, data_len
        )
        mu.mem_write(AT_STRING_ADDRESS, at_string)
    else:
        # prepare AT command payload
        payload = b'AT+CGAUTH=1,1,"username","password"\x00'

        # write the payload to memory at AT_STRING_ADDRESS
        mu.mem_write(AT_STRING_ADDRESS, payload)

        # source: https://docs.python.org/3/library/struct.html
        # construct the message structure for process_message
        # format: command_id (2 bytes) [0], flags (2 bytes) [1], padding (4 bytes) [2],
        # payload pointer (4 bytes) [3], payload length (4 bytes) [4]
        message_data = struct.pack(
            "<HHIII", 1, 0x00FF, 0, AT_STRING_ADDRESS, len(payload)
        )

    # define outside of heap to avoid overwriting in case of malloc again
    MESSAGE_DATA_ADDR = 0x20003000

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
    # mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # we need to set modem to 1 or else it returns 7 in AT_validate_dispatch meaning that the modem is not ready
    mu.mem_write(0x0080BE07, b"\x01")
    # start emulation at the process_message function and end at the exit address we set in LR
    # | 1 to set thumb mode bit in the address
    mu.emu_start(process_message | 1, EXIT_ADDRESS)

    r0 = mu.reg_read(UC_ARM_REG_R0)
    print(f">>> process_message returned: {hex(r0)} ({r0})")

    # read r0 value
    if r0 != 0:
        response = mu.mem_read(r0, 28)
        print(f">>> Response struct bytes: {bytes(response).hex()}")

        data_ptr = struct.unpack_from("<I", bytes(response), 8)[0]
        data_len = struct.unpack_from("<I", bytes(response), 12)[0]
        print(f">>> Response data_ptr: {hex(data_ptr)}, data_len: {data_len}")

        response_str = mu.mem_read(data_ptr, data_len)
        print(f">>> AT response string: {bytes(response_str)}")

except UcError as e:
    print(f"Failed: {e}")
    exit(1)
