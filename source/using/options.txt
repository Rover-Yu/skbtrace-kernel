
.. _options:

**********
命令行选项
**********

Skbtrace目前提供了两个用户空间工具：

* skbtrace, 功能是把内核记录的协议栈跟踪事件结构记录在磁盘上。

* skbparse, 功能是将skbtrace记录的数据解析成易读的文本格式。

skbtrace
==========

``-r PATH``
   挂载debugfs的目录位置。skbtrace是从debugfs（relayfs）中读取内核协议栈中的跟踪事件的。如果这个目录上没有挂载debugfs，skbtrace会尝试挂载，如果尝试失败，skbtrace会失败退出。默认位置是/sys/kernel/debug。


``-D DIR``
   输出目录，这个目录必须事先存在。默认目录是./skbtrace.results

``-w SECONDS``
   指定skbtrace的运行时间，以秒为单位。如果没有指定这个选项，并且也没有指定运行的子进程，skbtrace会永远运行下去，直到收到SIGINT信号（即当你按下Ctrl-C时的行为）。虽然也可以使用SIGKILL结束skbtrace运行，但建议不要那样做，因为它可能导致skbtrace丢失一部分事件，另外清理内核缓冲区的操作也会被跳过。

``-b BYTES`` ``-n COUNT``
   分别指定Relayfs中subbuffer的大小和个数。如果你发现skbtrace在结束运行时，汇报了事件丢失，可以尝试扩大这两个配置。

``-c PATH``
   指定配置文件skbtrace.conf的搜索路径。这个路径列表中所有配置文件中的配置会叠加到一起。如果配置为空，默认是启用所有跟踪事件。也可以使用-e选项启用事件。

``-C CHANNEL_LIST``
   事件可能分别发生在硬中断、软中断和系统调用中。但我们有时只关心其中某(几)个上下文内的事件，这时可以使用这个选项指定我们关心的”通道“，以过滤掉”噪音“。
   CHANNEL_LIST是以逗号分割的CHANNEL列表。CHANNEL可能是syscall，softirq，hardirq。

``-p PROCESSOR_MASK``
   事件可能发生在不同的处理器上。如果我们只关心特定处理器上的事件，可以使用这个事件指定这些处理器。PROCESSOR_MASK的格式，类似于设置中断亲和性时的场景：1=cpu0, 2=cpu1, 4=cpu2, 8=cpu3，以此类推。

``-e EVENT[,OPTIONS_LIST]``
   指定跟踪事件。这个选项可以使用多次，每个指定不同的跟踪事件。
   * EVENT	 事件名称。
   * OPTIONS_LIST	事件的选项列表，以逗号分割。
   完整的事件列表，请参考 :ref:`events` 。

``-F FILTER``
   指定基于报文的BPF过滤器。语法类似于tcpdump。

``-S FILTER``
   指定基于连接的BPF过滤器。对于TCP，目前只支持使用基于IPv4地址和端口的过滤器。

``-s``
   配合skbparse，可以在标准输出上实时显示跟踪事件信息。例如可以这样：skbtrace -s | skbparse -s -S

``-f``
   默认情况下，如果结果目录下已经有上次写入的结果，skbtrace会错误退出。但如果使用了这个选项，skbtrace会直接覆盖掉它们。

``-l``
   显示所有可用的跟踪事件列表。

``-V``
   Verbose模式，可以在运行时显示更多的skbtrace内部状态。

``-v``
   显示版本信息，然后退出。

skbparse
==========

``-v``
   显示版本信息并退出。

``-s``
   使用skbtrace的控制信息，在标准输出上实时显示解析结果。(目前未实现)

``-S``
   在标准输出上显示解析结果。

``-o PATH``
   指定skbparse结果的输出目录，默认为当前目录。

``-i PATH``
   指定skbtrace的输出结果目录，即输入目录，默认为./skbtrace.results

``-h``
   显示帮助信息。
