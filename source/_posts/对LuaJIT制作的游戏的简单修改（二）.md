---
title: 对LuaJIT制作的游戏的简单修改（二）
date: 2018-06-25 17:50:04
tags:
---

# 前言

本次修改的游戏还是在（一）中所讲的游戏，这一次的目的是要把游戏的反修改处理掉。但是跟（一）中不同的是这一次用到的技术会更高级一点，直接对LuaJIT进行hook。我们可以直接使用Lua自带的debug库来获得大量的信息，并且能够进行修改。

参考了国外大神的文章：

[Hooking LuaJIT](https://nickcano.com/hooking-luajit/)（原文）

[看我如何通过hook攻击LuaJIT](https://www.anquanke.com/post/id/86958)（译文）



<!-- more -->

# 注入Lua代码

为了注入我们自己的Lua代码，我们需要获得游戏调用luaL_newstate返回的lua_State对象，其实就是Lua代码运行的一个环境。如国外大神的文章所说，直接hook luaL_newstate这个函数是不太妥当的，因为这时候库还没有加载，debug功能无法使用，所以可以选择hook luaL_openlibs这个函数，当然如果hook了luaL_newstate也是可以的，只需要自己手动调用一下luaL_openlibs就行。为了加载我们的代码，我们还需要得到luaL_loadfilex和lua_pcall两个函数的地址。

确定了所需要hook的函数之后，接下来就是确定hook方式。一般来讲是用dll来完成我们的hook，但是注入dll的时机却是个问题。luaL_openlibs一般是在luaL_newstate之后就马上调用，而luaL_newstate一般是在程序一开始时就会调用。一开始我使用SetWindowsHookEx并且第一个参数使用WH_SHELL来注入dll，这样只要游戏创建窗口的时候我们的dll就会被注入进去，但是经过实验之后效果并不理想，因为这个游戏在创建窗口之前就已经调用了luaL_openlibs，所以我们的hook代码并没有被执行。于是我采用了第二种方法，创建进程的时候直接注入dll。为此我参考了网上的一些源码，写了一个注入工具（只支持32位）。

![](http://wx1.sinaimg.cn/large/006juYZNgy1fsnnvv660pj30ga091dfs.jpg)

接下来就是dll的代码

```c++
typedef void* lua_State;
typedef int(*_luaL_loadfilex)(lua_State *L, const char *filename, const char *mode);
typedef int(*_luaL_openlibs)(lua_State *L);
typedef int(*_lua_pcall)(lua_State *L, int nargs, int nresults, int errfunc);

_luaL_openlibs luaL_openlibs_original;
_luaL_loadfilex luaL_loadfilex;
_lua_pcall lua_pcall;
BYTE orig_code[5];
BYTE jmp_code[5] = { 0xe9 };

void MyHook();
void ChooseProc();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		ChooseProc();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

int luaL_openlibs_hook(lua_State *L)
{
	WriteProcessMemory(GetCurrentProcess(), luaL_openlibs_original, &orig_code, 5, NULL);	//恢复原函数
	int ret = luaL_openlibs_original(L);
	WriteProcessMemory(GetCurrentProcess(), luaL_openlibs_original, &jmp_code, 5, NULL);	//修改原函数
	luaL_loadfilex(L, "debug.lua", NULL) || lua_pcall(L, 0, -1, 0);	//加载我们的lua脚本，将脚本放在游戏目录下即可
	MessageBox(NULL, L"Hook success", L"Success", MB_OK);
	return ret;
}

void MyHook()
{
	HMODULE hModule = GetModuleHandle(L"lua51.dll");
	if (!hModule)
	{
		MessageBox(NULL, L"lua51.dll not found!", L"Fail", MB_OK);
		return;
	}
	luaL_openlibs_original = (_luaL_openlibs)GetProcAddress(hModule, "luaL_openlibs");
	luaL_loadfilex = (_luaL_loadfilex)GetProcAddress(hModule, "luaL_loadfilex");
	lua_pcall = (_lua_pcall)GetProcAddress(hModule, "lua_pcall");
	if (!luaL_openlibs_original || !luaL_loadfilex || !lua_pcall)
	{
		MessageBox(NULL, L"function not found", L"Fail", MB_OK);
		return;
	}
	//保存原函数字节
	if (!ReadProcessMemory(GetCurrentProcess(), luaL_openlibs_original, &orig_code, 5, NULL))
	{
		MessageBox(NULL, L"ReadProcessMemory fail", L"Fail", MB_OK);
	}

	//修改原函数
	*(DWORD*)(jmp_code + 1) = (DWORD)luaL_openlibs_hook - (DWORD)luaL_openlibs_original - 5;
	if (!WriteProcessMemory(GetCurrentProcess(), luaL_openlibs_original, &jmp_code, 5, NULL))
	{
		MessageBox(NULL, L"WriteProcessMemory fail", L"Fail", MB_OK);
	}
}

void ChooseProc()
{
	WCHAR szPath[MAX_PATH];
	WCHAR *p = NULL;

	GetModuleFileName(NULL, szPath, MAX_PATH);
	p = wcsrchr(szPath, L'\\');
	
	if (!wcscmp(p + 1, L"梦战.exe"))	//要hook的进程名称
	{
		MyHook();
		MessageBox(NULL, L"DLL inject", L"Success", MB_OK);
	}
}
```

代码比较丑，各种英文语法问题请见谅，看得懂就行。

通过GetProcAddress就可以直接获得我们需要的三个函数的地址，其中luaL_openlibs是我们需要hook的函数，luaL_loadfilex和lua_pcall则是来加载我们写的用来debug的lua脚本。其中ChooseProc是我用SetWindowsHookEx时用来筛选注入进程的，但是因为后来用了注入工具，所以这里会显得比较多余。



# debug.lua

这个就是我们用来获取信息的lua脚本。参考了国外大神的代码并结合实际游戏之后，我的代码如下。

```lua
--lua无法debug即时编译过后的代码，根据实际情况选择是否关闭jit。
jit.off()

function re_print(t,prefix,file)
    for k,v in pairs(t) do
        if type(v) == "function" then
            file:write(string.format("%s => %s","_G." .. k,v) .. "\n")
            --[[
        else
            file:write(prefix .. "." .. k .. "\n")
            --]]
        end
        if type(v) == "table" and k ~= "_G" and k ~= "_G._G" and not v.package then
            re_print(v, "\t" .. prefix .. "." .. k, file)
        end
    end
end

function dumpGlobals()
    local fname = "globals_" .. ".txt"
    local globalsFile = io.open(fname, "w")

    re_print(_G,"_G",globalsFile)

    globalsFile:flush()
    globalsFile:close()
end

function trace(event, line)
    local info = debug.getinfo(2)

    if not info then return end
    if not info.name then return end
    
    dumpGlobals()
    
    --下面注释的代码是获取函数信息的，结合了实际情况之后我并没有使用，详情参考国外大神文章
    --[[
    local fname = "trace_" .. ".txt"
    local traceFile = io.open(fname, "a")
    traceFile:write(info.name .. "()\n")

    local a = 1
    while true do
        local name, value = debug.getlocal(2, a)
        if not name then break end
        if not value then break end
        traceFile:write(tostring(name) .. ": " .. tostring(value) .. "\n")
        a = a + 1
    end
    traceFile:flush()
    traceFile:close()
    --]]
end

debug.sethook(trace, "c")

```

`dumpGlobals`函数中，将名为\_G的表打印出来并保存到游戏目录下。\_G是Lua的全局对象表，这个表储存了很多跟游戏有关的关键信息，有很大的价值。其中`re_print`函数是我从网上参考来的一份可以遍历所有table的代码，因为我只想要获得跟函数有关的信息，所以我在其中加了一句`if type(v) == "function"`来筛选出\_G表中存储的函数。

`debug.sethook(trace, "c")`使Lua在每个函数完成之前调用`trace`这个函数，在`trace`中，我们就可以调用`dumpGlobals`了。但是因为不知道游戏什么时候会把全局变量分配完毕，所以我们只好不设限制的一直调用`dumpGlobals`。当调用脚本后，可能会比较卡，但是开启游戏后就可以马上关掉游戏了，一般来讲游戏开启后在我们没有反应过来时全局变量都已经分配好了。



# 观察_G全局变量表内容

我们使用工具，选择dll的路径和游戏的路径并点击执行，在开启游戏后就可以立马关闭游戏，我们可以看到游戏目录下多了个globals_.txt文件，这就是我们打印出来的全局变量表，我在里面发现了很有意思的东西。

```
...省略一大部分...
_G.渲染函数 => function: 0x057622e0
_G.领取沉船传信 => function: 0x02b313e8
_G.结算保护夕仔 => function: 0x02b315c8
_G.dofile => function: builtin#25
_G.领取押镖任务 => function: 0x02b31430
_G.防修改 => function: 0x0562d190			<------防修改关键函数
_G.是否拥有效果 => function: 0x02b314f0
_G.取效果剩余时间 => function: 0x02b31508
_G.洗点 => function: 0x02b31610
_G.xpcall => function: builtin#21
_G.领取剑指凶狼 => function: 0x02b31418
_G.角色修炼 => function: 0x02b31568
_G.载入视频 => function: 0x04a7ac18
_G.置纹理过滤 => function: 0x02b406f8
_G.停止视频 => function: 0x04a7ac78
...省略一大部分...
```

这个游戏的Lua脚本很多都是用了中文，这个防修改就直接写脸上了，一下就看到了。知道了函数名称后我们就可以干坏事了。



# debug.lua（改）

这里我偷个懒，直接修改一下debug.lua内容，把防修改过掉。

```
function 反防修改()
    return
end

function trace(event, line)
    防修改 = 反防修改
end

debug.sethook(trace, "c")

```

文件记得使用GBK编码格式，不然这个游戏不认文件中的汉字。

我们把防修改直接替换成我们写的反防修改，反防修改是一个空函数，游戏调用防修改这个函数的时候，就相当于是在调用我们的反防修改函数，然后就是啥都没有做。将debug.lua放在游戏目录下并使用注入工具注入我们的dll就可以过掉反修改。

效果图如下，

没有反防修改时：

![](http://wx1.sinaimg.cn/large/006juYZNgy1fsnq8cvf88g30zy0lj1l1.gif)

有反防修改时：

![](http://wx3.sinaimg.cn/large/006juYZNgy1fsnq8n4jyyg30zy0lj7wm.gif)

当然这个方法非常的不优雅，不过因为我对Lua并不是很熟悉，所以我也没有再多研究了。



# 后记

其实这是个相当厉害的技术，不过本人水平有限，没办法给大家展现更多东西，有兴趣的可以自己研究研究。