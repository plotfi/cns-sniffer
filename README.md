SNIFFER()                                                          SNIFFER()

NAME
       sniffer - dump traffic on a network, specify port numbers
		 network interfaces, or precaptured pcap files

SYNOPSIS
       sniffer [ -v ] [ -f FILE ] [ -p PORT ] [ -d DEVICE ]

DESCRIPTION
	Sniffer will print out the payload of packets in a
	network interface. It can be run with various flags 
	which make it behave differently. Sniffer can sniff 
	on the line, or offline from a precaptured pcap file.
	Sniffer also has built-in support to scan for the 
	eicar virus.

	The user must run sniffer as root or have 
	Berkeley Packet Filter device permissions. Sniffer
	will exit with "FIN" when it is finished sniffing.
        By default sniffer will automatically choose a 
        device and sniff on all ports unless a pcap file
        is specified where it will sniff on all ports that
        were captured to the file.
	
	To compile sniffer simply untar the hw0.tar.gz
	into a directory and do "make" in the src directory, 
	unless you are using Linux in which case you will 
	have to "make linux". Other than that there is 
	"make clean" to remove binaries, and "make bsd"
	which compiles with -ansi and works in BSD based
	Unix-like OSes. I couldn't port it to anything but
	BSD and linux because of various headers and libs, and
	I couldn't get it compiled in linux with -ansi in gcc.

OPTIONS
       -f     Specifies the filename of the pcap file to
	      read from.

       -v     Specifies that sniffer should parts the packet
              payload for the eicar virus in an email attachment.

       -d     Specifies the network device to sniff on.

       -p     Specifies the port to sniff on, 

EXAMPLES
       To print all traffic coming from a network interface 
       device, execute:

              sniffer

       To print all traffic coming from a specific network 
       interface device, execute:

             sniffer -d fxp0

       To print all traffic coming from a network specific port
       execute:

             sniffer -p "port 23"

       If you want to see what people are doing on the line on telnet 
       do this:

             sniffer -d fxp0 -p "port 23"

       If you want to sniff captured email traffic from a file:

             sniffer -f cs4803_hw0.pcap -p "port 25"

       To take this and scan for the eicar.com virus:

             sniffer -v -f cs4803_hw0.pcap -p "port 25" 


OUTPUT FORMAT
      The output format is simply the raw data in ascii format from the 
      packets off the line or from a file.
 
HISTORY
     An sniffer command never appeared on anything but Puyan Lotfi's FreeBSD system.

BUGS
     The email fields have statically inserted null terminators so the printed from
     and to for a virus scan could be off.

BSD                              Sept 5, 2004                              BSD



 


		
