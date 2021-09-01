<h1> Linux Network Stack </h1>

As we know, there are lots of protocols in the kernel and also there are lots of physical network card in the world.  
The linux need to abstract the common code and also the special code for every protocol and device.  
So the function pointer is in everywhere of network subsystem, and actually in everywhere of Linux kernel.  
[Reference](https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2018/06/17/linux-net-general-intro)

<h2> Architecture </h2>

<table style=color:#505050;">
	<tr>
		<td style="border-color:#7C7B7B;" bgcolor=#F3F1F1 align="center">TCP/IP protocol Suite</td>
	</tr>
	<tr>
		<td style="border-color:#7C7B7B;" bgcolor=#CBC9C9 align="center">Application Layer</td>
	<tr>
	<tr>
		<td style="border-color:#7C7B7B;" bgcolor=#CBC9C9 align="center">
			<a href=#Layer4> Transport Layer</a>
		</td>
	</tr>
	<tr>
		<td style="border-color:#7C7B7B;" bgcolor=#CBC9C9 align="center">
			<a href=#Layer3>Network Layer</a>
	</td></tr>
	<tr>
		<td style="border-color:#7C7B7B;" bgcolor=#CBC9C9 align="center">
			<a href=#Layer2>Network Access Layer</a>
	</td></tr>
</table>

<h2 id="Layer2">Network Access Layer</h2>

The Network Access Layer is the lowest layer of the TCP/IP protocol hierarchy.  
The protocols in this layer provide the means for the system to deliver data to the other device on a directly attached network.  
The Network Access Layer divided into two sub-layer.
* Logical Link Control sub-layer (LLC)
* Media Access Control sub-layer (MAC)

<h3> Logical Link Control </h3>

The LLC data communication protocol layer is the upper sub-layer of the data link layer.  
The LLC sub-layer acts as an interface bwtween the MAC layer and the network layer.  

The LLC sub-layer provides mulyiplexing mechanisms (SAP) that make it possible for several network protocol to coexist within a multipoint network.  

[more](llc.md)

<h2 id="Layer3">Network Layer</h2>
<h2 id="Layer4">Transport Layer</h2>
