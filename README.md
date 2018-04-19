# P4FastFlowSwitching
Fast flow switching with P4

Matches based on destination IP address and a register value (copied into packet metadata for the table match), for an action to output the packet on a specific port with a specific re-written destination IP address.

Changing the register should "instantly" change all flows matched in the table.

**Example Screenshots**

The example screenshots show three (identical) packets ingressing the switch with three different results.

At first the register r_flow_set is 0.  The first packet (ipv4dst 239.0.0.1) ingressing on Interface ID 0 (numbering as per Wireshark, actually veth1 in tofinobm) is not matched in schedule_table because there is no flow_set_id entry in the table that matches 0, and is dropped.

Then r_flow_set is set to 1.  The second packet ingressing on Interface ID 0 is matched in the schedule_table with flow_set_id==1, has its ipv4dst re-written to 239.1.1.1, and is set to egreess from interface ID 1 (veth3).

Then r_flow_set is set to 2.  The third packet ingressing on Interface ID 0 is matched with flow_set_id==2, has its ipv4dst re-written to 239.2.2.2, and is set to egress from interface ID 2 (veth5).
