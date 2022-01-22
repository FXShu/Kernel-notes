




# Kernel-notes
Reading experience of Linux Kernel.

## Architecture Of Kernel

<table>
    <tr>
        <td style="border-color:#7C7B7B; color:black;" align="center" colspan="5" bgcolor="yellow" >System Call Interface</td>
    </tr>
    <tr>
        <td style="border-color:#7C7B7B; color:black;" bgcolor=#CFF6CB align="center" colspan="3" bgcolor=#E1DFDF>I/O subsystem</td>
        <td style="border-color:#7C7B7B; color:black;" bgcolor=#B8E7E2 align="center" colspan="1" bgcolor=#E1DFDF>Memory <br>Management  <br>(PM)</td>
        <td style="border-color:#7C7B7B; color:black;" bgcolor=#EEBFD8 align="center" colspan="1" bgcolor=#E1DFDF>Process <br> Management  <br>(MM)</td>
	</tr>
    <tr>
        <td style="border-top-width:4px; border-top-style:dashed;border-top-color:#A6CD97;
					border-left-width:5px; border-left-style:dashed;border-left-color:#A6CD97;
					border-right-width:3px; border-right-style:dashed;border-right-color:#A6CD97;
                    color:black;"
			bgcolor="white" align="center" colspan="3">Virtual File System (VFS)</td>
        <td style="border-right-width:3px; border-right-style:dashed;border-right-color:#9EC8C4;
					border-top-width:4px; border-top-style:dashed;border-top-color:#9EC8C4;
                    color:black;"
			bgcolor=#DEEDEA align="center" rowspan="2">Virtual Memory</td>
        <td style="border-top-width:4px; border-top-style:dashed;border-top-color:#C29CB0;
					border-right-width:3px; border-right-style:dashed;border-right-color:#C29CB0;
                    color:black;"
			bgcolor=#FFE9E9 align="center" rowspan="2">Signal Handling</td>
    </tr>
    <tr>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
					border-left-width:5px; border-left-style:dashed;border-left-color:#A6CD97;
                    color:black;"
			bgcolor=#D0D0D0 align="center">Terminals</td>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
                    color:black;"
			bgcolor=#F1E6BD align="center"><a href="socket.md">Sockets</a></td>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
					border-right-width:3px; border-right-style:dashed;border-right-color:#A6CD97;
                    color:black;"
			bgcolor=#A4E7D7 align="center">File systems</td>
    </tr>
    <tr>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
					border-left-width:5px; border-left-style:dashed;border-left-color:#A6CD97;
                    color:black;"
			bgcolor=#D0D0D0 align="center"  colspan="1" rowspan="4">Line Discipline</td>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
                    color:black;"
			bgcolor=#F1E6BD align="center"  colspan="1">Netfiter/Nftables</td>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
					border-right-width:3px; border-right-style:dashed;border-right-color:#A6CD97;
                    color:black;"
			bgcolor=#A4E7D7 align="center"  colspan="1" rowspan="2">Generic block layer</td>
        <td style="border-right-width:3px; border-right-style:dashed; border-right-color:#9EC8C4;"
            bgcolor="white" align="center"  colspan="1"></td>
        <td style="border-right-width:3px; border-right-style:dashed; border-right-color:#C29CB0;"
            bgcolor="white" align="center" colspan="1"></td>
    </tr>
    <tr>
        <td bgcolor=#F1E6BD align="center"  colspan="1" rowspan="2">
			<a href=network_stack.md>Network Stack</a></td>
        <td style="border-right-width:3px; border-right-style:dashed;border-right-color:#9EC8C4; color:black;"
			bgcolor=#DEEDEA align="center"  colspan="1" rowspan="2">Paging page replacement</td>
        <td style="border-right-width:3px; border-right-style:dashed; border-right-color:#C29CB0; color:black;"
			bgcolor=#FFE9E9 align="center"  colspan="1" rowspan="2">Process/thread creation & termination</td>
    </tr>
    <tr>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
					border-right-width:3px; border-right-style:dashed;border-right-color:#A6CD97;
                    color:black;"
			bgcolor=#A4E7D7 align="center" colspan="1" rowspan="2">I/O Scheduler</td>
    </tr>
    <tr>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4; color:black;"
			bgcolor=#F1E6BD align="center"  colspan="1" rowspan="1">
            <a href=packet_schedule.md>Packet Scheduler</a></td>
        <td style="border-right-width:3px; border-right-style:dashed;border-right-color:#9EC8C4; color:black;"
			bgcolor="white" align="center"  colspan="1" rowspan="2"></td>
        <td style="border-right-width:3px; border-right-style:dashed; border-right-color:#C29CB0; color:black;"
			bgcolor="white" align="center"  colspan="1" rowspan="2"></td>
    </tr>
    <tr>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
					border-bottom-width:4px; border-bottom-style:dashed;border-bottom-color:#A6CD97;
                    color:black;"
			bgcolor=#F1E6BD align="center"  colspan="3">
			<a href=net_namespace.md>Name Sapce</a></td>
    </tr>
    <tr>
        <td style="border-left-width:5px; border-left-style:dashed;border-left-color:#A6CD97;;
					border-bottom-width:4px; border-bottom-style:dashed;border-bottom-color:#A6CD97;
                    color:black;"
			bgcolor=#D0D0D0 align="center"  colspan="1">Character device drivers</td>
        <td style="border-width:2px; border-style:solid;border-color:#F4F4F4;
					border-bottom-width:4px; border-bottom-style:dashed;border-bottom-color:#A6CD97;
                    color:black;"
			bgcolor=#F1E6BD align="center"  colspan="1">
			<a href=https://github.com/FXShu/Kernel-notes/wiki/MTK-Wi-Fi-Driver>Network device drivers</a></td>
        <td style="border-bottom-width:4px; border-bottom-style:dashed;border-bottom-color:#A6CD97;
					border-right-width:3px; border-right-style:dashed;border-right-color:#A6CD97;
                    color:black;"
			bgcolor=#A4E7D7 align="center"  colspan="1">Block device drivers</td>
        <td style="border-right-width:3px; border-right-style:dashed;border-right-color:#91CED4;
					border-bottom-width:4px; border-bottom-style:dashed;border-bottom-color:#9EC8C4;
                    color:black;"
			bgcolor=#DEEDEA align="center"  colspan="1">Page Cache</td>
        <td style="border-right-width:3px; border-right-style:dashed; border-right-color:#C29CB0;
					border-bottom-width:4px; border-bottom-style:dashed; border-bottom-color:#C29CB0;
                    color:black;"
			bgcolor=#FFE9E9 align="center"  colspan="1">Process Scheduler</td>
    </tr>
</table>
