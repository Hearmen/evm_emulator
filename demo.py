#
# Title: CFG reconstruction of ETH smart contract (evm)
# Date: 06/29/18
#
# Author: Patrick Ventuzelo - @Pat_Ventuzelo
#

from octopus.arch.evm.disassembler import EvmDisassembler
from octopus.platforms.ETH.emulator import EthereumSSAEngine
from octopus.platforms.ETH.vmstate import EthereumVMstate
from octopus.core.utils import bytecode_to_bytes


file_name = 'ctf.bytecode'

# read file
with open(file_name) as f:
    bytecode_hex = f.read()

# init code
initdata = "0x608060405234801561001057600080fd5b5060008054600160a060020a0319163317815560036002557feb3effabe9960401da2b4dbf9e92b0b40569c5f005f81491c9d92f574adb5b0b907f7e782580d29c5c8c2fc261c858906ff320bd5d2e005b5669cc140d42f15d9b08905b60108110156100845791811881019160010161006d565b505060015561023e806100986000396000f300"

callinfo = {'calldata':None,'callvalue':0}

state=EthereumVMstate()

emul = EthereumSSAEngine(initdata)
emul.emulate(callinfo, state)

emul = EthereumSSAEngine(bytecode_hex)
print("******************************************************************")
print("******************************************************************")
print("******************************************************************")
print("******************************************************************")
print("******************************************************************")
print("******************************************************************")
print("******************************************************************")

# Start Call

# calldata
calldata = bytecode_to_bytes("0xc6c58bcd95529edd28cb526ab5071fd2fdebd5fc4e08b2af6876dd33a57764a970157576")

callinfo = {'calldata':calldata,'callvalue':0}
emul.emulate(callinfo, state)

