########################################################################
Check the configuration in the file

    bochsrc

Set the path to the System.map file if you want bochs to
trap and checksum the files, otherwise comment out the line.

    integrity:   symbols=System.map-3.4.0-rc6

Set the paths to the boot disk image and the data partition.

    ata0-master: path="hdd.img"
    ata0-slave:  path="/dev/cluster3/bigfiles"

You must inform bochs of the disk geometry. Get it with parted

    sudo parted hdd.img u chs p | grep BIOS
    sudo parted /dev/cluster3/bigfiles u chs p | grep BIOS

For the networking to work you must have the correct path to the 
net device

    ne2k:   ethmod=tuntap, ethdev=/dev/net/tun, script=tunconfig-script

The tunconfig script sets up NAT for the tap device created by bochs.

    OPTIONAL: If you want to have the console prompt sent to a 
    pty (console=ttyS0): create a pty that you can connect to 
    with screen, minicom, etc. in another window.

        socat PTY,link=bochspty PTY,link=screenpty
	screen screenpty

    Configure bochs to use it for its serial port

        com1:       enabled=1, mode=term, dev="bochspty"

Start with 

    sudo ./bochs -f bochsrc -q

Messages about checksum digests are written into bochs' logfile.

    tail -f bochsout.txt | grep digest
