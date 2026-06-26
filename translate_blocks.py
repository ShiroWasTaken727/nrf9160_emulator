#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


#TODO Add User Code Here

import json


from ghidra.program.model.block import BasicBlockModel
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import TaskMonitor
from ghidra.util import UndefinedFunction
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import ArmDisassembleCommand

from java.lang import IllegalArgumentException

try:
    jsonfile = str(askFile("Choose json coverage file", "json file"))

    with open(jsonfile, 'r') as file:
        data = json.load(file)

except IllegalArgumentException as error:
    print("Error: %s" % error.toString())
    exit()


fapi = FlatProgramAPI(currentProgram)
bbm = BasicBlockModel(currentProgram)
dummy_mon = TaskMonitor.DUMMY

# map translation block to ghidra basic block

basic_blocks = {}
discarded = set()

ghidra_basic_blocks = set()
for hex_block in data["blocks"]:
    block = int(hex_block, 16) # convert from str to hex

    if block in basic_blocks or block in discarded:
        continue

    address = fapi.toAddr(block)
    address_set = AddressSet(address)
    bbs = bbm.getCodeBlocksContaining(address_set, dummy_mon)
    
    number_of_blocks = 0
    while bbs.hasNext():
        ghidra_bb = bbs.next()
        basic_blocks[block] = int(ghidra_bb.firstStartAddress.toString(), 16)
        number_of_blocks += 1
        
    if number_of_blocks == 0:
        print("No Ghidra block for 0x%x" % block)
        discarded.add(block)
    elif number_of_blocks > 1:
        print("Multiple blocks found for for 0x%x" % block)
    else: 
        ghidra_basic_blocks.add(basic_blocks[block])

print("Translation blocks count: %d" % len(data["blocks"]))
print("Total mapped Ghidra blocks count: %d" % len(ghidra_basic_blocks))
print("Discarded blocks count: %d" % len(discarded))

data["ghidra unique blocks count"] = len(ghidra_basic_blocks)
data["ghidra blocks"] = sorted([hex(b) for b in ghidra_basic_blocks])

# go through each timestep and count cumulative ghidra blocks
cumulative_ghidra_blocks = set()
for entry in data["coverage over time"]:
    new_blocks = entry.get("new blocks", [])
    
    for hex_block in new_blocks:
        block = int(hex_block, 16)
        if block in basic_blocks:
            ghidra_block = basic_blocks[block]
            cumulative_ghidra_blocks.add(ghidra_block)
        
    entry["ghidra cumulative count"] = len(cumulative_ghidra_blocks)

outfile = jsonfile.replace(".json", "_ghidra.json")
with open(outfile, 'w') as file:
    json.dump(data, file, indent=2)

print("Saved to %s" % outfile)