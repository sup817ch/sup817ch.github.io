---
title: 记一次Unity游戏逆向
date: 2020-06-20 17:40:36
tags:
---

游戏是steam上一款单机音游，难度有点高，在被虐了千百次后，我决定对这个游戏下手。

<!-- more -->

# 探秘

大家都知道，unity游戏的主要逻辑都在Assembly-CSharp.dll，只要用dnspy之类的工具就能够轻易的反编译出源码。于是我兴冲冲的掏出了我的dnspy，将Assembly-CSharp.dll拖了进去，然而一片空白的dnspy告诉我事情没这么简单。

![3](http://tvax3.sinaimg.cn/large/006juYZNly1gfz0xlot64j30d803ljra.jpg)

使用010 editor打开文件，发现并不是标准的PE格式，DOS头的标志MZ被修改为了ML。

![1](http://tvax1.sinaimg.cn/large/006juYZNly1gfywqjo40uj30kr0hqads.jpg)

那就老规矩，开启游戏，对mono.dll的mono_image_open_from_data_with_name下断点观察，结果发现游戏并没有在这部分解密PE文件。抱着不想的预感，使用CE搜索了一下这个游戏的前几个字节，结果不出意料。

![2](http://tva2.sinaimg.cn/large/006juYZNly1gfywy8q3ohj30p70eojt0.jpg)

可以看到游戏并没有直接解密文件，外面长啥样内存里还是啥样。看来游戏应该是对mono的代码进行了修改，用自己的规则来加载文件。那没有办法，只能老老实实的跟着代码走一遍。

# 解密

将mono.dll拖进ida，一般加载dll都会走到mono_image_open_from_data_with_name，所以我们直接定位到这里，然后从github下了一份mono的源码作为对照。顺着流程走下去会走到do_mono_image_load函数，这个函数就是用来解析加载dll文件的。

## PEHeader部分

首先看到pe_image_load_pe_data，这个函数是用来解析PE Header部分的，通过对比可以看出这个函数与源码不一样，是被修改过的，ida F5代码如下

```c
_BOOL8 __fastcall pe_image_load_pe_data(__int64 image)
{
  char *header; // rdi
  __int64 v2_image; // rbx
  signed int section_table_offset; // eax
  _BOOL8 result; // rax
  char data[128]; // [rsp+20h] [rbp-88h]

  header = *(char **)(image + 0x50);
  v2_image = image;
  result = 0;
  if ( *(_DWORD *)(image + 24) >= 0x80u )       // raw_data_len
  {
    memmove(data, *(const void **)(image + 16), 0x80ui64);// raw_data
    if ( data[0] == 'M' && data[1] == 'L' )
    {
      section_table_offset = do_load_header(v2_image, header, *(_DWORD *)&data[0x3C] - 0x4D4C);// NtHeader offset - 0x4D4C
      if ( section_table_offset >= 0 )
      {
        if ( (unsigned int)load_section_tables(v2_image, (__int64)header, section_table_offset) )
          result = 1;
      }
    }
  }
  return result;
```

首先可以看到被修改过的mono在识别DOS头标志的时候用的不是MZ而是ML，与修改过的dll文件一致，然后在读取0x3c位置也就是NtHeader偏移值的时候减去了0x4D4C。do_load_header主要是记录一下IMAGE_NT_HEADERS结构，与源码没什么太大的差异，唯一的区别就是在识别NtHeader标志的时候用的不是PE而是ML，与修改过的dll一致。

```c
signed __int64 __fastcall do_load_header(__int64 image, char *header, int e_lfanew)
{
  __int64 v3; // rdi
  char *v4_header; // rbx
  __int64 v5; // rsi
  unsigned int section_table_offset; // edi
  int v8; // er11
  int v9; // eax
  char Dst; // [rsp+20h] [rbp-D8h]
  int v11; // [rsp+50h] [rbp-A8h]
  int v12; // [rsp+58h] [rbp-A0h]
  int v13; // [rsp+5Ch] [rbp-9Ch]
  __int16 v14; // [rsp+60h] [rbp-98h]
  __int16 v15; // [rsp+62h] [rbp-96h]
  __int16 v16; // [rsp+64h] [rbp-94h]
  __int16 v17; // [rsp+66h] [rbp-92h]
  __int16 v18; // [rsp+68h] [rbp-90h]
  __int16 v19; // [rsp+6Ah] [rbp-8Eh]
  int v20; // [rsp+6Ch] [rbp-8Ch]
  int v21; // [rsp+70h] [rbp-88h]
  int v22; // [rsp+74h] [rbp-84h]
  int v23; // [rsp+78h] [rbp-80h]
  __int16 v24; // [rsp+7Ch] [rbp-7Ch]
  __int16 v25; // [rsp+7Eh] [rbp-7Ah]
  int v26; // [rsp+80h] [rbp-78h]
  int v27; // [rsp+88h] [rbp-70h]
  int v28; // [rsp+90h] [rbp-68h]
  int v29; // [rsp+98h] [rbp-60h]
  int v30; // [rsp+9Ch] [rbp-5Ch]
  char Src; // [rsp+A0h] [rbp-58h]

  v3 = e_lfanew;
  v4_header = header;
  v5 = image;
  if ( e_lfanew + 248i64 > (unsigned __int64)*(unsigned int *)(image + 24) )
    return 0xFFFFFFFFi64;
  memmove(header, (const void *)(e_lfanew + *(_QWORD *)(image + 16)), 0xF8ui64);// raw_data
  if ( *v4_header != 'M' || v4_header[1] != 'L' )// NtHeader signature
    return 0xFFFFFFFFi64;
  if ( *((_WORD *)v4_header + 12) == 0x10B )    // PE32
  {
    section_table_offset = v3 + 248;
    if ( *((_WORD *)v4_header + 10) != 0xE0 )   // SizeOfOptionalHeader
      return 0xFFFFFFFFi64;
  }
  else
  {
    if ( *((_WORD *)v4_header + 12) != 523 || *((_WORD *)v4_header + 10) != 240 )
      return 0xFFFFFFFFi64;
    memmove(&Dst, (const void *)(v3 + *(_QWORD *)(v5 + 16)), 0x108ui64);
    section_table_offset = v3 + 264;
    memmove(&Dst, v4_header, 0xF4ui64);
    v8 = v11;
    *((_DWORD *)v4_header + 24) = v23;
    *((_DWORD *)v4_header + 25) = v26;
    *((_DWORD *)v4_header + 26) = v27;
    *((_DWORD *)v4_header + 27) = v28;
    v9 = v12;
    *((_DWORD *)v4_header + 13) = v8;
    *((_DWORD *)v4_header + 14) = v9;
    *((_DWORD *)v4_header + 15) = v13;
    *((_WORD *)v4_header + 32) = v14;
    *((_WORD *)v4_header + 33) = v15;
    *((_WORD *)v4_header + 34) = v16;
    *((_WORD *)v4_header + 35) = v17;
    *((_WORD *)v4_header + 36) = v18;
    *((_WORD *)v4_header + 37) = v19;
    *((_DWORD *)v4_header + 19) = v20;
    *((_DWORD *)v4_header + 20) = v21;
    *((_DWORD *)v4_header + 21) = v22;
    *((_DWORD *)v4_header + 22) = v23;
    *((_WORD *)v4_header + 46) = v24;
    *((_WORD *)v4_header + 47) = v25;
    *((_DWORD *)v4_header + 28) = v29;
    *((_DWORD *)v4_header + 29) = v30;
    memmove(v4_header + 120, &Src, 0x80ui64);
  }
  return section_table_offset;
}
```

接下来看看load_section_tables

```c
signed __int64 __fastcall load_section_tables(__int64 image, __int64 iinfo, unsigned int offset)
{
  __int64 v3_image; // r13
  unsigned int v4_offset; // er12
  int v5_number_of_sections; // eax
  __int64 v6_iinfo; // r14
  __int64 v7; // r15
  __int64 v8; // rbx
  int v9; // esi
  __int64 v10_index; // rdi
  __int64 v11_current_cli_section_table; // rbp

  v3_image = image;
  v4_offset = offset;
  v5_number_of_sections = *(unsigned __int16 *)(iinfo + 6) + 1;// section+1
  v6_iinfo = iinfo;
  v7 = v5_number_of_sections;
  *(_DWORD *)(iinfo + 248) = v5_number_of_sections;// cli_section_count
  *(_QWORD *)(iinfo + 256) = g_try_calloc(40i64 * v5_number_of_sections);// cli_section_tables
  v8 = 0i64;
  *(_QWORD *)(v6_iinfo + 264) = g_try_calloc(8 * v7);// cli_sections
  if ( v7 <= 0 )
    return 1i64;
  v9 = 0;
  v10_index = 0i64;
  while ( 1 )                                   // 填充cli_section_tables
  {
    v11_current_cli_section_table = v10_index + *(_QWORD *)(v6_iinfo + 256);
    if ( (unsigned __int64)v4_offset + 40 > *(unsigned int *)(v3_image + 24) )
      break;
    memmove(
      (void *)(v10_index + *(_QWORD *)(v6_iinfo + 256)),
      (const void *)(*(_QWORD *)(v3_image + 16) + v4_offset),
      0x28ui64);
    ++v8;
    v4_offset += 40;
    v10_index += 40i64;
    *(_DWORD *)(v11_current_cli_section_table + 20) += -0x4D4Cu - v9;// PointerToRawData - (i+1)*0x4D4C
    v9 += 0x4D4C;
    if ( v8 >= v7 )
      return 1i64;
  }
  return 0i64;
}
```

这个函数主要是用来解析SectionHeader部分的。首先可以看到在读取NumberOfSections时加上了1，然后再接着解析SectionHeader。解析SectionHeader的时候对其中的PointerToRawData也动了手脚，操作是PointerToRawData-(i+1)*0x4D4C，其中i是SectionHeader的索引（从0开始）。

PEHeader部分有改动的解析就结束了，总结一下这个游戏对PEHeader的处理就是：

1、修改了DosHeader和NtHeader的标志，将MZ和PE修改成了ML。

2、修改了指向NtHeader的偏移值。

3、将NumberOfSections减去1。

4、修改了SectionHeader中的PointerToRawData。

按着修改方式逆处理一下就算把PEHeader修复完了，使用010 editor的模板也能正常识别了。于是我高高兴兴的将修复后的文件再次扔进dnspy，发现事情远远没有这么简单。

![4](http://tva3.sinaimg.cn/large/006juYZNly1gfz0z0v66dj30d1067aa3.jpg)

没办法，只能老老实实的接着往下看了。

## CLIHeader部分

这一部分就是.net CLI文件特有的部分了，在开始着手这个游戏之前我对这部分基本没有了解，只能现学现卖了。网上关于这部分的中文资料基本等于没有，只好阅读官方文档[ECMA 335](https://www.ecma-international.org/publications/standards/Ecma-335.htm)了，在这里我简单的介绍一下，CLI文件的概览如下

![5](http://tva2.sinaimg.cn/large/006juYZNly1gfz1a92eswj309d06daa6.jpg)

可以看到除了有传统的PE文件部分之外，还有CLI特有的部分，比如CLIHeader。那这个CLIHeader位于文件中的哪里呢？答案就在PEHeader的OptionalHeader->DataDirectory[14]中，文档的说明如下

![6](http://tva4.sinaimg.cn/large/006juYZNly1gfz1ln5dp4j30ps064aag.jpg)

所以我们可以在这里获取CLIHeader的RVA。再来看看CLIHeader的结构

![7](http://tva3.sinaimg.cn/large/006juYZNly1gfz1nv0gq1j30pd0imacj.jpg)

其中比较重要的就是MetaData元数据了，比如程序中每个方法的IL都可以通过元数据找到，元数据的具体介绍大家可以自己百度或者阅读文档，我这个半吊子就不在这里献丑了。通过CLIHeader中的MetaData我们可以找到MetadataRoot，也就是描述Metadata几个table的地方，下面是MetadataRoot的结构

![8](http://tvax2.sinaimg.cn/large/006juYZNly1gfz22vrmf2j30pn0ih0uz.jpg)

对CLI文件格式的介绍暂时到这里，有兴趣的可以自行翻阅文档，接下来回到代码当中。在执行完pe_image_load_pe_data后，mono会执行pe_image_load_cli_data来解析CLIHeader部分。通过对比发现与源码中不同的部分在load_metadata_ptrs中，mono的源码对MetadataRoot中signature的判断是这样的

![9](http://tvax2.sinaimg.cn/large/006juYZNly1gfz2bkfw2yj30dr05hq30.jpg)

而游戏中的mono是这样的

![10](http://tvax4.sinaimg.cn/large/006juYZNly1gfz2c9sjf2j30i1035dfu.jpg)

看了一下dll中的signature也是WSML（我是Mengluu？），与游戏中的mono对应的上。

将文件中的WSML修改为BSJB后再次丢进dnspy，令人惊喜的发现可以看到东西了

![11](http://tvax1.sinaimg.cn/large/006juYZNly1gfz2wd3cicj30cc0drmxp.jpg)

正当我高兴的开始准备翻阅的时候，现实又给了我当头一棒。

![12](http://tvax3.sinaimg.cn/large/006juYZNly1gfz30tjjq6j31950pdgpy.jpg)

函数反编译失败了。

## opcode部分

将反编译方式切换至IL可以发现应该是opcode被替换了

![13](http://tva2.sinaimg.cn/large/006juYZNly1gfz32qqaw9j30kk0cd756.jpg)

这就麻烦了，在百度+谷歌了一段时间过后得出的结论就是通过阅读mono_method_to_ir，人肉识别出被修改的opcode与原opcode的对应关系。看了一下mono_method_to_ir的源代码，我心态瞬间崩了。

![14](http://tvax4.sinaimg.cn/large/006juYZNly1gfz3694qs3j30z903dmxg.jpg)

尝试着用ida F5了一下该函数，decompile了半天才出来结果，F5出来的伪代码一眼看去接近两万行，随便改个变量名都要卡半天。没办法，只能把F5抠掉看汇编了。分析opcode没什么好讲的，纯粹就是体力活。在分析了大概几十个opcode之后才发现了规律（我太菜了），原来就是把opcode 0xB3-0xC1插到了0x00的前面，用源码中的opcode.def文件来表示的话大概就是这样

```
/* GENERATED FILE, DO NOT EDIT. Edit cil-opcodes.xml instead and run "make opcode.def" to regenerate. */
OPDEF(CEE_NOP, "nop", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0x00, NEXT)
OPDEF(CEE_CONV_OVF_I1, "conv.ovf.i1", Pop1, PushI, InlineNone, 0, 1, 0xFF, 0xB3, NEXT)
OPDEF(CEE_CONV_OVF_U1, "conv.ovf.u1", Pop1, PushI, InlineNone, 0, 1, 0xFF, 0xB4, NEXT)
OPDEF(CEE_CONV_OVF_I2, "conv.ovf.i2", Pop1, PushI, InlineNone, 0, 1, 0xFF, 0xB5, NEXT)
OPDEF(CEE_CONV_OVF_U2, "conv.ovf.u2", Pop1, PushI, InlineNone, 0, 1, 0xFF, 0xB6, NEXT)
OPDEF(CEE_CONV_OVF_I4, "conv.ovf.i4", Pop1, PushI, InlineNone, 0, 1, 0xFF, 0xB7, NEXT)
OPDEF(CEE_CONV_OVF_U4, "conv.ovf.u4", Pop1, PushI, InlineNone, 0, 1, 0xFF, 0xB8, NEXT)
OPDEF(CEE_CONV_OVF_I8, "conv.ovf.i8", Pop1, PushI8, InlineNone, 0, 1, 0xFF, 0xB9, NEXT)
OPDEF(CEE_CONV_OVF_U8, "conv.ovf.u8", Pop1, PushI8, InlineNone, 0, 1, 0xFF, 0xBA, NEXT)
OPDEF(CEE_UNUSED50, "unused50", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0xBB, NEXT)
OPDEF(CEE_UNUSED18, "unused18", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0xBC, NEXT)
OPDEF(CEE_UNUSED19, "unused19", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0xBD, NEXT)
OPDEF(CEE_UNUSED20, "unused20", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0xBE, NEXT)
OPDEF(CEE_UNUSED21, "unused21", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0xBF, NEXT)
OPDEF(CEE_UNUSED22, "unused22", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0xC0, NEXT)
OPDEF(CEE_UNUSED23, "unused23", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0xC1, NEXT)
OPDEF(CEE_BREAK, "break", Pop0, Push0, InlineNone, 0, 1, 0xFF, 0x01, ERROR)
OPDEF(CEE_LDARG_0, "ldarg.0", Pop0, Push1, InlineNone, 0, 1, 0xFF, 0x02, NEXT)
OPDEF(CEE_LDARG_1, "ldarg.1", Pop0, Push1, InlineNone, 1, 1, 0xFF, 0x03, NEXT)
OPDEF(CEE_LDARG_2, "ldarg.2", Pop0, Push1, InlineNone, 2, 1, 0xFF, 0x04, NEXT)
OPDEF(CEE_LDARG_3, "ldarg.3", Pop0, Push1, InlineNone, 3, 1, 0xFF, 0x05, NEXT)
OPDEF(CEE_LDLOC_0, "ldloc.0", Pop0, Push1, InlineNone, 0, 1, 0xFF, 0x06, NEXT)
OPDEF(CEE_LDLOC_1, "ldloc.1", Pop0, Push1, InlineNone, 1, 1, 0xFF, 0x07, NEXT)
OPDEF(CEE_LDLOC_2, "ldloc.2", Pop0, Push1, InlineNone, 2, 1, 0xFF, 0x08, NEXT)
OPDEF(CEE_LDLOC_3, "ldloc.3", Pop0, Push1, InlineNone, 3, 1, 0xFF, 0x09, NEXT)
OPDEF(CEE_STLOC_0, "stloc.0", Pop1, Push0, InlineNone, 0, 1, 0xFF, 0x0A, NEXT)
OPDEF(CEE_STLOC_1, "stloc.1", Pop1, Push0, InlineNone, 1, 1, 0xFF, 0x0B, NEXT)
OPDEF(CEE_STLOC_2, "stloc.2", Pop1, Push0, InlineNone, 2, 1, 0xFF, 0x0C, NEXT)
OPDEF(CEE_STLOC_3, "stloc.3", Pop1, Push0, InlineNone, 3, 1, 0xFF, 0x0D, NEXT)
...以下省略
```

感谢作者没有完全打乱，否则不知道要看到猴年马月。

# opcode修复

没想到这一步卡了我好久，在找了半天合适的轮子未果后（不得不说我的搜索能力实在是不太行），在坛友[@艾莉希雅](https://www.52pojie.cn/home.php?mod=space&uid=294041) 的帮助下，我找到了ilasm和ildasm这两个工具，可以在github的coreclr里找到这两个工具的源码。首先修改源码中的opcode.def为上面提到的样子之后编译ildasm，用修改过的ildasm反编译游戏的dll文件为IL，再用正常的ilasm编译刚才生成的IL，即可得到opcode正确的dll文件。将这个新的dll拖入dnspy后即可正常反编译。

![15](http://tvax3.sinaimg.cn/large/006juYZNly1gfz3wwgteoj31950pdgpl.jpg)

至此，这个游戏的dll文件应该就被正常解密了

# 结语

通过这个unity游戏的逆向学习了一波CLI文件，并且亲自分析了一遍opcode（以前都是云的），感觉收获还蛮大的。然而解密dll后顿时索然无味，为啥不好好玩游戏呢，然后就没有然后了。还有，关于替换opcode这一点我很好奇大家都是怎么做的，希望各位不吝赐教。

