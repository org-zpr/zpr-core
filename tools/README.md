# Tools

## Installing the dissectors

1. Getting the dissectors into Wireshark
    - Launch Wireshark
    - In the menu bar, click Help -> About Wireshark -> Folders
    - Under Folders, note the location on your computer of the 'Personal Lua Plugins' folder
    - Copy both the zdp dissector and the link layer header dissector into that folder
    - Restart Wireshark, or press Ctrl + Shift + L (Cmd + Shift + L on macos)
2. Setting up the dissectors
    - In the Wireshark menu bar again, click Edit -> Preferences
    - In the preferences window, expand the Protocols section
    - Find DLT_USER and edit the Encapsulations Table
    - Click the plus button to add a new user
    - Set the Payload dissector to zdp
    - Set the Header size to 1, and the Header protocol to zdp_link_p2p
    - Set the trailer size to 0 and leave the Trailer protocol blank
    - Click OK to add the User 0 profile, and you're done.

## Coloring for Wireshark

`zdp_coloring.txt` provides an example coloring for ZDP packets in Wireshark. 

`make_coloring.py` is a script that can be used to easily create or add coloring rules. It 
expects the desired color in RGB form, the label you want to use for the rule, and the ZDP packet type(s) you want to colorize.

## Other ways to capture data

Note that rather than capturing to a file, you can capture to a FIFO
(created using `mkfifo`).  You can open the FIFO in Wireshark via
Capture → Options → Manage Interfaces... → Pipes → + → double-click "New Pipe" →
Browse.  Note you'll need to open it in Wireshark before capturing to it,
else `ph-cli` will block when setting the capture file until you do so.



