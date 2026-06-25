// test_dll.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <thread>
#include "EventLoop.hpp"
extern "C" __declspec(dllexport) void __stdcall entry()
{
     []()
    {
        __try
        {
            *(int*)(0) = 1;
        }
        __except (1)
        {
            MessageBoxA(0, "seh ok", "ok", MB_OK);
        }

        }();
    

    EventLoop loop;

    int count = 0;
    EventLoop::TimerId timer = 0;
    loop.Post([] {
        std::cout << "Execute immediately\n";
        });

    loop.PostDelay([] {
        std::cout << "Execute after 1 second\n";
        }, std::chrono::milliseconds(1000));

    loop.PostDelay([&loop] {
        std::cout << "stop\n";
  
        }, std::chrono::milliseconds(2000));
    timer = loop.PostInterval([&] {
        std::cout << "interval tick: " << count << "\n";

        ++count;
        if (count >= 5) {
            loop.Cancel(timer);
        
        }
        }, std::chrono::milliseconds(500));

    while (true) {
        loop.Poll();

        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    return;
}

int __stdcall DllMain(void* hinstance, unsigned int dwreason, void* parm)
{
    if (dwreason == 1)
    {
       
    }
    return 1;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
