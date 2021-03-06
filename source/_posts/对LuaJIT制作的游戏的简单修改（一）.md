---
title: 对LuaJIT制作的游戏的简单修改（一）
date: 2018-06-11 23:40:27
---

# 前言

本次修改的游戏是一个使用了LuaJIT制作的梦幻西游类单机游戏，名字叫做[《梦战：碧海旭梦》](http://dream.supmers.com/forum.php?mod=viewthread&tid=20)。 这个游戏在我的硬盘里放了有很长一段时间了，当时水平有限，就没有再修改，直到这几天才重新开始研究。 网上关于LuaJIT的分析资料并不多，而有关单机游戏修改的是没有了，所以我基本上是从零开始研究。 经过几天不断的研究，终于对LuaJIT有了一点点了解，也找到了一些修改的方法。 不过说实话研究这个东西没什么用处，纯粹是我的兴趣，各位姑且看看就好。 因为我也是新手，所以文章中难免有很多错误，如果发现错误请一定要告诉我。



<!-- more -->

# 什么是Lua？和LuaJIT有什么关系?

Lua是一个脚本语言，通常是用来嵌入应用程序中的，在游戏中的应用范围也很广，尤其是手游。

而LuaJIT则是Lua的一个高效版本。

 [用好Lua+Unity，让性能飞起来—LuaJIT性能坑详解](https://blog.uwa4d.com/archives/usparkle_luajit.html) 这篇文章对LuaJIT的工作原理有了一定的阐述。 若想了解更多，可以去官方网站看看。

 Lua：[The Programming Language Lua](http://www.lua.org/)

 LuaJIT：[The LuaJIT Project](http://luajit.org/)  



# LuaJIT的字节码和虚拟机

LuaJIT可以把.lua脚本编译成字节码，然后放到虚拟机中运行。这里的字节码和我们平常看到的机器码不同，LuaJIT的字节码有自己对应的一套指令， 然后在程序中有一块地方负责解释这些字节码（在windows上就是个dll）， 这块地方就是LuaJIT虚拟机。 关于LuaJIT的指令网上已经有人总结，[Lua LuaJit 指令表(整理)](https://blog.csdn.net/zzz3265/article/details/41146569)。 也可以直接翻阅LuaJIT的源码（官网可以下载），在lj_bc.h中有定义。 官网的wiki中也有文档，[LuaJIT 2.0 Bytecode Instructions](http://wiki.luajit.org/Bytecode-2.0)。 如果有人有改过Lua的游戏就知道非常难改，因为到处都是“共用代码”。 而这里的“共用代码”实际上就是虚拟机，我们直接修改机器码就等于破坏了虚拟机，所以我们要从字节码下手。 



# 开始修改

首先我们先研究一下跟游戏目录下的文件，在游戏目录中有个lua51.dll，我们随便拿一个PE工具看一下。 这里我用ExeinfoPe查看

![](http://wx3.sinaimg.cn/large/006juYZNgy1fse09228naj30hz08udjs.jpg)

dll文件被加壳了，但是问题不大，只是个压缩壳，不脱也没关系。 



点击PE查看导出表信息，发现LuaJIT字样，基本上就确定游戏跟LuaJIT有关系了。 

![](http://wx4.sinaimg.cn/large/006juYZNgy1fse094hagej31960fuqgg.jpg)



第一次进入游戏要过一段剧情，等待游戏正式开始就好。 注意，修改前请先备份存档，游戏有反修改机制，被检测到后直接杀掉存档。（存档文件为save.bhs） 我们尝试修改一下潜力点 

![](http://wx1.sinaimg.cn/large/006juYZNgy1fse097ev1hj30ru0lrb29.jpg)



LuaJIT中的数据都是double类型的，所以我们用double类型来搜索，并找出是什么修改了这个地址。 

![](http://wx2.sinaimg.cn/large/006juYZNgy1fse09a890aj31420q3h86.jpg)

其实如果只是为了自己玩游戏的话这里就直接改数值就好了，只要不改太高游戏的反修改检测都不会杀掉你的存档，但是今天主要是研究一下LuaJIT。 这里出现了两条代码，看第一条就行了。记下代码的地址和潜力点的地址，转到x32dbg或者OD中分析，这里我用x32dbg来分析。 



Ctrl+G输入6B52F6AF来到该代码处，下F2断点，然后发现游戏马上就被断下来了，这很正常，因为这里的代码就是用来解释字节码的虚拟机，在lua51.dll中。 我们切换到断点页面，选中刚才下的断点，按Ctrl+E来编辑设置断点条件 

![](http://wx3.sinaimg.cn/large/006juYZNgy1fse09c9rvcj31730cd403.jpg)

这里的ecx == 0x0DD35300 意思就是在ecx等于这个数值的时候才断下，而这里的0DD35300就是我们刚才搜到的潜力点的地址。 



点击保存后开启断点然后重新运行游戏，发现游戏会变得很卡，这也很正常，因为这里是虚拟机，执行的次数很多，调试器在筛选的时候难免会卡。 随便把某个属性加一点使潜能点改变，游戏就会被断下来，切回到调试器中查看。 这时候的esi值就是指向当前解释的字节码的地址，我们右键点击esi寄存器选择“在内存窗口中转到”，并观察左下角内存窗口。 

![](http://wx2.sinaimg.cn/large/006juYZNgy1fse0a0ssk3j30gj06fjro.jpg)

04B36748就是当前esi的值

这里就是LuaJIT的字节码，每条指令的长度都是4个字节。 注意这里的04B36748的指令是下一条要执行的指令， 实际上改变潜力点的指令在前面04B36744处，对应的字节码就是3A 07 07 06， 顺便再注意下04B36740处的1F 07 05 07 我们查一下指令表（前面有），看看这些是什么东西。 

![](http://wx4.sinaimg.cn/large/006juYZNgy1fse0a3m8bgj30hn01g3ya.jpg)

![](http://wx4.sinaimg.cn/large/006juYZNgy1fse0a60ec7j30h801g742.jpg)

看到之后是不是感觉蒙了，一开始我也是蒙的，后来经过不断的研究发现这里的07 05 07 或者 07 07 06其实是索引， 对应的是LuaJIT栈上的一些东西，这里我就不详细讨论了，主要是我也不太懂。 这两行大概意思就是两个变量相减，然后结果赋值给另一个变量（也就是潜力点）。 这些东西需要自己去写一些LuaJIT的简单程序，然后去调试看内存，再看看LuaJIT对应的源码才能搞清楚一点。 我也读不透LuaJIT的源码，这里我就简单讲一下怎么改就好了。 查看指令表发现这样一条指令，可以直接对变量赋值。 

![](http://wx1.sinaimg.cn/large/006juYZNgy1fse0a7ugvsj30m9028t8j.jpg)

那我们只要修改1F 07 05 07就好了，比如我们要把潜力点变成10000，就改成27 07 10 27 （注意小端序，10 27就是10000的16进制） 看一下效果

![](http://wx3.sinaimg.cn/large/006juYZNgy1fse0ab7lsuj30pr0mk43r.jpg)

![](http://wx2.sinaimg.cn/large/006juYZNgy1fse0aulw77g30zy0ljb29.gif)

修改成功，想要做成修改器也方便，只要搜一下字节码再改就好了，和aobscan是差不多的 



# 后记

这游戏还有一些反修改还没有处理，可能会出二，也可能不会。 有关LuaJIT的知识还有很多，我这里讲的只占了很少，当作是抛砖引玉了，有兴趣的可以深入研究，有问题也可以在群里找我，当然我不一定能解答就是了。  