## 大功能模块调整

1. 原先lexbor的对于网页的解析，之后要用新版的h3操作，调用nghttp3库进行解析。主要是为了实现Alexa500网页的解析和传输行为。（尤其关注https://github.com/ngtcp2/ngtcp2/commit/9ea17af6ef48281d015a73ce46d6689b2255a037#diff-76e715a9e756e801193429538c1cea6cd190fa8e48f4c94fd46594d813eb4966这个commit的大函数变化）
2. 对于自带参数（transport_parameters），旧的自定义加解密操作、传输数据包大小等，新版应该有一个较为容易的接口，在新版中实现定义、设置、传输和获取transport _parameters。
3. late-binding，新版有实现，学会如何调用内置方法。
4. 连接迁移，之前学兵实现在balancer.cc里，学会并查看新版的使用变化。
5. balancer的实现。



## 小模块注意

1. gcc版本提升了。
2. mysql的兼容性，我们的版本有些老，之后还需要master-slave，是否用一下较新的mysql，或者换一个更易于使用的数据库。
3. 新的关于队头阻塞、拥塞控制的解决办法，我们之前实验遇到的错误研究是否解决。
4. 新版的1RTT和0RTT逻辑，有较大的改变。应该是实现了真的0RTT，之前可能没有。
5. 新版client不会自动在传输包结束后断开连接。
6. 内置的并发处理。