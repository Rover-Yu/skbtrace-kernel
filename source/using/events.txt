
.. _events:

*******************
跟踪事件列表
*******************

事件选项
===========

许多事件都有控制其具体行为的选项。例如，tcp_congestion事件可以用mask过滤掉那些不感兴趣的拥塞事件。

还有一些公共选项是所有事件都支持的。

primary
-----------

默认情况下，skbtrace对于所有事件都是独立对待的————也就是说，如果你启用了它，并且成功通过了各种过滤操作，skbtrace工具就把它们会记录到磁盘上。很多时候，这个简单模型可以工作得很好，但在有些情况下，它也记录下了很多没有价值的事件。

有时候我们希望记录的事件更有针对性一些，例如，我们只关心在事件A发生之前的事件B的情况，也就是说，只有在发生了事件A发生的时候，记录之前的事件B才有价值。在这种场景下，在skbtrace里，称事件A为“主事件”，事件B为”从事件“。primary选项的用途，就是建立起主从事件的关联。

例如，使用skbtrace的-e选项时，如果指定了-e tcp_rttm,primary=tcp_congestion，就意味着，只有在发生了tcp_congestion时，才会将它之前发生的tcp_rttm事件从内核的缓冲中记录下来。即tcp_rttm是从事件，tcp_congestion是主事件。

目前实现的限制是：一个主事件可以对应多个从事件，但每个从事件只能从属于一个主事件。最多可记录32个从事件。

通用事件
===========

skb_rps_info
------------

   这是一个基于报文的事件，因此需要使用-F选项过滤。

   显示RPS的散列信息。我们知道RPS可以看作是软件模拟实现的RSS。本质是根据报文内容做散列和映射，将相同连接的报文分发到同一个处理器上。
   这个事件可以显示出RPS用于计算散列计算时的“数据源”。

   一个skbparse解析后的例子 ::

     144574 1347852135.451990372 action=rps_info skb=0xffff880037c7f4c0 rx-queue=0 rx-hash=0x0 cpu=0xffffffff ifindex=1 src=100007f dst=100007f sport=12865 dport=41223 proto=0x6

TCP
============

　 以下所有事件都是基于连接的事件，因此需要使用-S选项过滤。

tcp_congestion
---------------
   TCP拥塞事件。可能的类型有

   * CWR。例如ECN机制在接收到ECE标志后，或者发生本地队列拥塞时。
   * Loss。在没有启用F-RTO机制时，发生了丢包事件，可能是启动重传定时器，或者是根据SACK信息推算出丢包事件。
   * F-RTO。在启用F-RTO时，发生了丢包事件。
   * FastRtx。快速重传事件。

　 这个事件支持mask选项，可以用于过滤不关心的拥塞类型，例如，使用tcp_congestion,mask=cwr:fastrtx，就不会记录CWR和快速重传拥塞事件了。

   一个skbparse解析后的例子::

      1378215231 1347620030.225669489 action=tcp_cong state=FRTO-Loss sk=0xffff88062f8bc700 cwnd=32768 rto=201 sndnxt=1076842762 snduna=1076842762

tcp_connection
---------------
   基本TCP状态迁移事件。包括除LISTEN状态之外的其他所有基本TCP状态间的变迁动作。

   一个skbparse解析后的例子::

      88 1347851487.186018014 action=tcp_conn sk=0xffff880072144780  state=ESTABLISHED local=127.0.0.1:47857 peer=127.0.0.1:55469

icsk_connection
-----------------
   基本TCP状态迁移事件。只包括到LISTEN状态的变迁。

   一个skbparse解析后的例子::
     
      144561 1347851976.556067571 action=icsk_conn sk=0xffff880070ec4e40 state=LISTEN local=127.0.0.1:53549

tcp_sendlimit
---------------
   TCP在执行发送操作，可能因为各种原因停下来，这个事件用来记录停下来的原因。
   
   * cwnd 因为拥塞窗口限制停止发送
   * swnd 因为接收窗口限制停止发送
   * nagle 因为Nagle算法限制停止发送
   * tso  因为TSO原因停止发送
   * frag 因为无法拆分过大的报文停止发送。
   * pushone 因为pushone的标志停止发送。
   * other 其他停止发送原因（几乎等同于内存不足）
   * ok 有数据包发送成功。

   这个事件支持mask选项，可以用于过滤不关心的停止原因，例如，使用tcp_sendlimit,mask=ok，就不会记录发送成功的事件了。

   一个skbparse解析后的例子 ::

      144606 1347852135.453115265 action=tcp_sendlim sk=0xffff880037f96080 reason=ok begin=1347852135.453115265 cnt=1 mtuprobe=1 ssthresh=37 cwnd=10/0 swnd=33920

tcp_ca_state
--------------
   TCP连接的拥塞避免算法状态变迁事件，包括：

   * open
   * disorder
   * cwr
   * recovery
   * loss

   这个事件也支持mask选项，可以用于过滤不关心的状态，例如，tcp_ca_state,mask=disorder, 就不会记录切换到乱序状态的事件了。

   一个skbparse解析后的例子 ::

      1378026600 1347620023.792681609 action=tcp_ca_state sk=0xffff88062f8bc700 state=Disorder cwnd=2 rto=3216 snduna=1076842506 sndnxt=1076842762 snd_ssthresh=7 snd_wnd=32768 rcv_wnd=32768 high_seq=1076842762 packets_out=1 lost_out=0 retrans_out=0 sacked_out=0 fackets_out=0 prior_ssthresh=67 undo_marker=0 undo_retrans=0 total_retrans=4 reordering=28 prior_cwnd=4294967295 mss_cache=16384

tcp_rttm
--------------
   TCP在接收到每个窗口的确认之后执行RTTM时的事件。

   一个skbparse解析后的例子 ::

      144577 1347852135.451990372 action=tcp_rttm sk=0xffff880037f96080 snd_una=256095406 rtt_seq=256095406 rtt=0 rttvar=200 srtt=8 mdev=2 mdev_max=200

sk_timer
-------------
   各种TCP定时器事件。

   可能的操作包括：

    * setup  初始化定时器
    * reset　设置定时器
    * stop　 停止定时器

   可能的定时器包括：

    * rexmit　重传定时器
    * probe　 零窗口探测定时器
    * keepalive　保活定时器
    * delack　　　延迟确认定时器

   这个事件支持mask选项，可以用于过滤操作和定时器，例如，tcp_ca_state,mask=probe，就把零窗口探测定时器的所有操作都忽略掉了。

   一个skbparse解析后的例子 ::

      144604 1347852135.453115265  action=tcp_timer sk=0xffff880072422100 op=reset timers=delay-ack timeout=150ms

tcp_active_conn
-----------------
 　记录当前活动TCP连接的信息，每个活动连接只记录一次。这个事件可以用于将其他事件数据中的sk指针转换成具体的连接信息。

   一个skbparse解析后的例子 ::

      144572 1347852135.451990372 action=tcp_active_conn sk=0xffff880037f96080 state=ESTABLISHED local=127.0.0.1:41223 peer=127.0.0.1:12865
