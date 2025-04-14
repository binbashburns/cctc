# Range Diagram
![range-diagram](../../0-src/blue_range_complete.png)

# OSI Model Diagram
![osi-model](../../0-src/OSI.png)

## Internet Standards Organizations

Other than the OSI or TCP/IP models, it’s also important to understand some other organizations that have been developing Internet and Networking Standards.

   - Internet Engineering Task Force (IETF): The IETF is a large open international community of network designers, operators, vendors, and researchers who are concerned with the evolution and operation of the Internet. It focuses on the development of protocols and standards, with working groups dedicated to specific areas such as routing, security, and web technologies.

       - Main focus: repository of Request for Comment (RFC) which is a series of documents published by the Internet Engineering Task Force (IETF) and other organizations involved in the development of Internet standards and protocols. RFCs serve as the primary means for documenting specifications, protocols, procedures, and other technical aspects of the Internet.

       - Noteable RFCs:

           - RFC 768 - User Datagram Protocol (1980): This RFC defines the User Datagram Protocol (UDP), a core protocol used for low-latency communications where reliability is not a priority.

           - RFC 791 - Internet Protocol (1981): This RFC defines IPv4, the fourth version of the Internet Protocol. It’s foundational for the functioning of the modern Internet.

           - RFC 792 - Internet Control Message Protocol (1981): Defines ICMP, used for network diagnostics and error reporting (e.g., echo requests/replies).

           - RFC 793 - Transmission Control Protocol (1981): Defines TCP, including its connection-oriented features, reliability mechanisms, and flow control.

           - RFC 826 - Address Resolution Protocol (1982): Defines the Address Resolution Protocol (ARP), which is used to map IP addresses to MAC addresses in a local network.

           - RFC 854 - Telnet Protocol Specification (1983): Defines the Telnet protocol, which allows remote text-based communication over the Internet.

           - RFC 959 - File Transfer Protocol (FTP) (1985): Specifies the FTP protocol for transferring files between clients and servers.

           - RFC 1350 - Trivial File Transfer Protocol (TFTP) (1992): Defines TFTP, a simpler and less feature-rich file transfer protocol compared to FTP.

           - RFC 1918 - Address Allocation for Private Internets (1996): This RFC defines the private IP address ranges used within internal networks that are not routable on the public Internet.

           - RFC 1939 - Post Office Protocol - Version 3 (POP3) (1996): Defines POP3, a protocol for retrieving email from a server.

           - RFC 2131 - Dynamic Host Configuration Protocol (1997): Specifies DHCP for dynamically assigning IP addresses and other network configuration parameters to devices.

           - RFC 2460 - Internet Protocol, Version 6 (IPv6) Specification (1998): This RFC specifies IPv6, the successor to IPv4, designed to address limitations and exhaustion issues with IPv4.

           - RFC 3501 - Internet Message Access Protocol (IMAP) (2003): Specifies IMAP, a protocol for accessing and managing email on a server.

           - RFC 4251 - The Secure Shell (SSH) Protocol Architecture (2006): Describes the architecture of SSH, including its components for secure remote access and file transfer.

           - RFC 5321 - Simple Mail Transfer Protocol (2008): Defines SMTP for email transmission between servers.

Institute of Electrical and Electronics Engineers (IEEE): While the IEEE is a broader organization covering various fields of technology, it plays a significant role in developing standards for networking and communication technologies. The IEEE 802 working groups, for example, have developed standards for LANs and wireless networks.

   - Some of the standards they deal with:

       - IEEE 802.11: Wireless LAN standards, commonly known as Wi-Fi, specifying protocols for wireless communication between devices.

       - IEEE 802.3: Ethernet standards, defining specifications for wired local area network (LAN) communication.

       - IEEE 802.1Q: Virtual LAN (VLAN) standards, providing protocols for creating and managing virtual LANs within Ethernet networks.

       - IEEE 802.16: Broadband Wireless Access (BWA) standards, often referred to as WiMAX, for wireless metropolitan area networks (MANs).

       - IEEE 802.1X: Port-based network access control standards, used for authenticating and authorizing devices connecting to a LAN or WLAN.

       - IEEE 802.1ad: Provider Bridging (PB) standards, also known as "Q-in-Q," for implementing virtual LAN (VLAN) stacking in Ethernet networks.

## Decimal to Hexadecimal Conversion

When converting Decimal to Hexadecimal (or converting Hexacedimal to Decimal) it is easiest to convert to 8-bit, 16-bit, or 32-bit binary first.

   - Convert from Decimal to Hex

       - Convert the decimal number to its binary equivalent.

           - 0 - 255 will be contained within 1 byte

           - 256 - 65,535 will be contained within 2 bytes.

           - 65,536 - 4,294,967,296 will be contained within 4 bytes.

       - Split the byte(s) into 4-bit nibbles with values of 8, 4, 2, and 1 for each nibble.

           - 1 byte will have 2 nibbles, 2 bytes with have 4 nibbles, and 4 bytes will have 8 nibbles.

       - Convert the values of each 4-bit nibble back into decimal

           - Each nibble of 4 bits will give you a value from 0 to 15.

           - 10 = A, 11 = B, 12 = C, 13 = D, 14 = E, and 15 = F

       - Order each hexadecimal digit in order from left to right.

       - The symbol of 0x is placed in front of the value to designate it as a hexidecimal number.

   - Convert from Hex to Decimal

       - Align each Hex digit to the bit chart

           - 2 Hex to 1-byte, 4 Hex to 2-bytes, 8 hex to 4-bytes.

           - The leftmost Hex will align with the High order bits while the rightmost Hex will align with the lowest-order bits.

       - Convert each Hex to its decimal equivalent.

           - A = 10, B = 11, C = 12, D = 13, E = 14, F = 15

       - Convert each decimal to its binary equivalent and place into each 4-bit nibble.

       - Add up all the bits that are turned on.

           - 1 byte will return values from 0 - 255

           - 2 bytes will return values from 256 - 65,535

           - 4 bytes will return values from 65,536 - 4,294,967,296

![hex-dec](../../0-src/HEX_DEC_Conversion_Chart.png)

![one-byte](../../0-src/hex1.png)

![two-byte](../../0-src/hex2.png)

![four-byte](../../0-src/hex3.jpg)

   - Tetrasexagesimal (Base 64)

       - This system is conveniently coded into ASCII by using the 26 letters of the Latin alphabet in both upper and lower case (52 total) plus 10 numerals (62 total) and then adding two special characters

   - Common Format

       - Base 64 - Like HEX, it allows groupings up to 6-bits of binary (0-63 decimal).

       - Characters used are (A-Z), (a-z), (0-9), and (+, /). That is (26) + (26) + (10) + (2) respectively.

       - In order to be compatible with binary, it uses 4 groupings of 6-bits (24 total bits) so that it will equate to 3 bytes of binary ( 24 bits).

       - For data not consuming the full 24-bits, it will use "=" signs for each 6 unused bits at the end as padding. Not more than 2 "=" will be used.

       - MTI=, MTIzNA==, MTIzNDU2Nzg=, QmFzZSA2NA==

![base64table](../../0-src/base64table.png)

## Encapsulation and Decapsulation

   - The communication between every layer other than the Physical layer is logical in nature. Therefore in order to pass information between protocol layers a protocol data unit (PDU) must be used. Each PDU for each protocol layer has specifications for the features or requirements at its layer. The PDU is passed down to a lower layer for transmission, the next lower layer is providing the service of handling the previous layer’s PDU. This is why the previous layer’s PDU is now referred to as an service data unit (SDU).

       - Protocol Data Units for each OSI Layer:

           - Application, Presentation, and Session = Data

           - Transport = Segment (TCP) or Datagram (UDP)

           - Network = Packet

           - Data Link = Frame

           - Physical = Bits

![pdu-sdu](../../0-src/PDU_SDU.png)

1.3.4.1 MAC Spoofing

    Spoofing is the act of disguising a communication from an unknown source as being from a known or trusted source. Spoofing is an attack vector done at several different layers of the OSI. At the Data-link layer attackers will commonly spoof the MAC-address.

    Originally MAC addresses were hard coded into the firmware of the NIC and could not be easily changed. This is why MAC addresses were commonly called "Firmware", "Hardware", or "Burned-in" addresses. In order to facilitate MAC spoofing attacks it required crafting of special frames with the MAC address pre-programmed in.

    Today most MAC addresses are programmed using the software. This makes modification of a device’s MAC address much simpler. In order to perform a MAC spoofing attack the malicious actor can either change their MAC address to a known or trusted address or create crafted frames with the MAC address already programmed in. MAC spoofing can be used to perform:

## How MAC Spoofing Works

   - Changing MAC Address: The attacker modifies their device’s MAC address to match that of another device, such as an authorized network device. This can often be done using software tools or by altering network interface settings on the device.

       - Linux: Use `ifconfig` or `ip link set dev eth0 address XX:XX:XX:XX:XX:XX` to change the MAC address.

       - Windows: Use Device Manager or command-line utilities like netsh to modify MAC addresses.

       - Mac Spoofing Tools: Tools like `macchanger` on Linux can automate the process of changing MAC addresses.

   - Gaining Access: Once the attacker’s device appears to have the same MAC address as an authorized device, it can potentially gain unauthorized access to network resources or bypass MAC-based security measures.

   - Bypassing Filters and Controls: MAC address filters and access control lists (ACLs) that rely solely on MAC addresses for authentication can be circumvented by spoofing.

## VLAN Types

There are 5 main types of VLANs. Only 1 VLAN can be assigned to any switch port. The only exception to this is the voice VLAN. The voice VLAN can be assigned with a data VLAN.

The VLAN Types are:

   - Default - VLAN 1 is the default vlan. VLAN 1 will always be present on the switch and can not be deleted. All ports will be assigned to VLAN 1. When VLAN assignment is removed from a port it will automaticcally be assigned to VLAN 1.

   - Data - VLANs assigned for user traffic.

       - Data VLANs are used to separate user data traffic based on different groups, departments, or functions.

       - Devices within the same data VLAN can communicate with each other as if they are on the same physical network.

   - Voice - VLAN assigned for use for voice traffic only. Typically uses CDP messages from VOIP phones to be asigned.

       - Voice VLANs are used to separate voice traffic from data traffic in networks that support Voice over IP (VoIP) systems.

       - This VLAN is configured to carry voice traffic, ensuring quality of service (QoS) for voice communications.

   - Management - A form of data VLAN used for switch/router remote management purposes.

       - A management VLAN is a VLAN used for managing networking devices such as switches, routers, and access points.

       - This VLAN is often used for remote device management, configuration, and monitoring purposes.

       - It helps secure management traffic by segregating it from user data traffic.

   - Native - VLAN used for switch/router generated traffic.

       - These are used for control traffic such as CDP, VTP, DTP, and STP. These do not normally have "tags" applied.

       - Native VLANs by default is VLAN 1 but is highly recommended to change.

       - The native VLAN is used on trunk links to carry untagged frames.

       - Frames from the native VLAN are not tagged when traversing trunk links, while frames from other VLANs are tagged.

## Describe VLANS and Security vulnerabilities

   - VLAN hopping Attack

       - VLAN hopping is an exploit method of attacking networked devices on separate virtual LAN (VLAN) without traversing a router or other Layer 3 device. The concept behind VLAN hopping attacks is for the attacker on one VLAN to gain access to traffic on other VLANs that would normally not be accessible. Keep in mind that VLAN hopping is typically a one-way attack. It will not be possible to get any response from the target device unless methods are setup on the target to respond with similar vlan hopping methods.

       - There are three primary methods of VLAN hopping:

           - Switch Spoofing

               - In this attack, an attacking host imitates a trunking switch by crafting Dynamic Trunking Protocol (DTP) frames in order to form a trunk link with the switch. With a trunk link formed the attacker can then use tagging and trunking protocols such as ISL or 802.1q. Traffic for all VLANs is then accessible to the attacking host.
```
switch(config)# interface fastethernet 1/10
switch(config-if)# switchport mode access
switch(config-if)# switchport nonegotiate
switch(config-if)# switchport access vlan 10
switch(config)# interface gigabit 0/1
switch(config-if)# switchport trunk encapsulation dot1q
switch(config-if)# switchport mode trunk
switch(config-if)# switchport nonegotiate
```
           - Tagging

               - This attack typically requires the attacker add the target 802.1Q tag manually to an Ethernet frame even though it is an access port. This process is normally done by the switch. The switch will receive the frame and forward it out the trunk port leading to the target without it needing to be routed. This method requires that the attacker and victim are separated by a trunk and success depends on the switch firmware being vulnerable.

           - Double Tagging

               - This attack works if the attacker knows what the "native VLAN" that is used on your organization. Typically VLAN 1 is used. All VLANs will be "tagged" with its corresponding VLAN. The Native VLAN however is intended for local network communication and is not tagged. Thus anything tagged for the native VLAN will be stripped off. The attacker will insert 2 tags into their frames. The first tag will be for the Native VLAN and the second tag will be for whatever VLAN he is trying to access. Upon receipt the switch will then remove the Native VLAN tag and will leave the second VLAN tag in tact. This method also requires that the attacker and victim be separated by a trunk and a vulnerable switch.
```
switch(config)# vlan dot1q tag native
switch(config)# interface fastethernet 1/10
switch(config-if)# switchport mode access
switch(config-if)# switchport nonegotiate
switch(config-if)# switchport access vlan 10
switch(config)# interface gigabit 0/1
switch(config-if)# switchport trunk encapsulation dot1q
switch(config-if)# switchport mode trunk
switch(config-if)# switchport nonegotiate
switch(config-if)# switchport trunk native vlan 999
```

## Explain VTP with its vulnerabilities

![Virtual Trunking Protocol](../../0-src/VTP.png)

VLAN Trunking Protocol (VTP) is a Cisco proprietary protocol used to manage VLAN (Virtual Local Area Network) configurations across a network of switches. VTP simplifies VLAN management by allowing network administrators to make changes to VLAN configurations on one switch, and then automatically propagate these changes to all other switches in the same VTP domain. This ensures consistency and reduces the risk of configuration errors across multiple switches.

   - Key Concepts of VTP

       - 1. VTP Domain

           - Definition: A VTP domain is a group of switches that share the same VTP configuration and VLAN information. All switches in the same VTP domain share VLAN information and synchronize their VLAN databases.

           - Configuration: Each switch must be configured with the same VTP domain name to participate in the same VTP domain.

       - 2. VTP Modes

           - Server Mode:

              - Description: Switches in VTP Server mode can create, modify, and delete VLANs and share these VLAN configurations with other switches in the VTP domain. They also maintain a VLAN database that is synchronized with other switches.

               - Default Mode: Switches are in VTP Server mode by default.

           - Client Mode:

               - Description: Switches in VTP Client mode receive VLAN information from VTP Servers and apply these VLAN configurations, but they cannot create, modify, or delete VLANs. They rely on VTP Servers for their VLAN information.

           - Transparent Mode:

               - Description: Switches in VTP Transparent mode do not participate in VTP VLAN information exchange. They forward VTP advertisements but do not apply them or update their VLAN database based on VTP information. They maintain their own VLAN configurations and do not propagate changes to other switches.

           - Off Mode:

               - Description: In some contexts, "Off" mode may be used to disable VTP entirely on a switch. This mode is not a standard VTP mode but can be used to refer to a state where VTP is not active.

       - 3. VTP Advertisements

          - Types:

               - Summary Advertisements: Contain information about the VTP domain name, revision number, and VLAN information.

               - Subset Advertisements: Carry VLAN configuration changes.

               - Advertisement Requests: Request VTP advertisements from other switches.

           - Purpose: Advertisements are used to propagate VLAN changes and maintain consistency across the VTP domain.

       - 4. VTP Revision Number

           - Description: Each VTP advertisement includes a revision number that is incremented with each change to the VLAN configuration. Higher revision numbers indicate more recent configurations. Switches use the revision number to determine if they should update their VLAN database based on received advertisements.

There are three versions of VTP, version 1, version 2, version 3.

## Versions of Spanning Tree Protocol (STP)

   - Open Standards-Based Versions:

       - STP (802.1D):

           - Open standard defined by the IEEE 802.1D specification.

           - Basic version of the Spanning Tree Protocol, widely supported by networking equipment from various vendors.

           - Defines the original spanning tree algorithm for loop prevention in Ethernet networks.

           - Convergence Time: 30 to 50 seconds.

       - RSTP (802.1w):

           - Open standard defined by the IEEE 802.1w specification.

           - Improves upon the original STP by providing faster convergence and better performance.

           - Offers faster link failover times and better utilization of redundant links compared to STP.

           - Widely supported across networking equipment from multiple vendors.

           - Convergence Time: 6 seconds or less.

       - MSTP (802.1s):

           - Open standard defined by the IEEE 802.1s specification.

           - Extends RSTP to support multiple spanning tree instances, each of which can encompass multiple VLANs.

           - Helps reduce the number of spanning tree instances needed in large networks with multiple VLANs, improving scalability and manageability.

           - Convergence Time: Similar to RSTP (6 seconds or less).

   - Cisco Proprietary Versions:

       - Per-VLAN Spanning Tree (PVST) and PVST+ (Per-VLAN Spanning Tree Plus):

           - Proprietary spanning tree protocol developed by Cisco.

           - PVST and PVST+ extend the functionality of STP by creating a separate spanning tree instance for each VLAN.

           - Allows for finer control over spanning tree behavior on a per-VLAN basis, optimizing network performance and stability.

           - Convergence Time: Typically similar to STP (30 to 50 seconds).

       - Rapid Per-VLAN Spanning Tree (Rapid PVST):

           - Cisco’s proprietary version of RSTP, tailored for use with PVST+.

           - Offers faster convergence and better performance compared to traditional PVST+.

           - Provides rapid failover times for individual VLANs, enhancing network resilience and uptime.

           - Convergence Time: Typically similar to RSTP (6 seconds or less).

       - Cisco Multiple Spanning Tree Protocol (MSTP) Implementation:

           - Cisco offers its implementation of MSTP, which is compatible with the IEEE 802.1s standard.

           - Allows Cisco devices to participate in MSTP environments alongside equipment from other vendors.

           - Offers enhanced features and integration with other Cisco networking technologies.

           - Convergence Time: Typically similar to RSTP (6 seconds or less).

## Subnet Chart

![subnet-chart](../../0-src/subnetchart.png)

## Headers

Packet Header breakdown:

![ipv4-header](../../0-src/IPv4_Header.png)

![ipv4-structure](../../0-src/IPv4_Structure.png)

