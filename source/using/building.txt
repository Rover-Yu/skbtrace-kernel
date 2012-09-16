
.. _building:

**************
编译
**************

编译skbtrace内核
===========
* 安装git
* 在一个空目录下运行：git clone git://github.com/Rover-Yu/skbtrace-kernel.git skbtrace-kernel.git
* cd skbtrace-kernel.git
* 配置内核，确保启用内核配置CONFIG_SKBTRACE和CONFIG_SKBTRACE_IPV4。
* 编译安装内核，重启系统。

编译skbtrace用户空间工具
============
* 在一个空目录下运行：git clone git://github.com/Rover-Yu/skbtrace-userland.git skbtrace-userland.git
* cd skbtrace-userland.git
* make，它会生成skbtrace [#]_ 和skbparse [#]_ 。

.. rubric:: 注

.. [#] skbtrace, 这个工具将内核记录的协议栈跟踪事件记录在磁盘上。
.. [#] skbparse, 这个工具将skbtrace记录的跟踪数据解析成更易读的文本格式。
