# P4FastFlowSwitching
Fast flow switching with P4

Matches based on destination IP address and a register value (copied into packet metadata for the table match), for an action to output the packet on a specific port with a specific re-written destination IP address.

Changing the register should "instantly" change all flows matched in the table.
