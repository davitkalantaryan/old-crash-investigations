/*
 *  Copyright (C) 
 *
 *  Written by Davit Kalantaryan <davit.kalantaryan@desy.de>
 */

 /**
  *   @file       main_investigator.cpp
  *   @copyright  
  *   @brief      Source file to demonstrate crash investigator
  *   @author     Davit Kalantaryan <davit.kalantaryan@desy.de>
  *   @date       2019 Mar 30
  *   @details 
  *       Details :  ...
  */

//
// todo:
// https://oroboro.com/printing-stack-traces-file-line/
// (gdb) info symbol 0x4005BDC
// addr2line -e  investigator 0x189b
// gdb --silent --eval-command "info symbol 0x189b" -ex "quit" ./investigator


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


int main()
{
    char* pMemory;

    printf("Crash analizer test (pid:%d)!\n",getpid());
    //printf("Crash analizer test!\n");

    pMemory = new char[1];
    printf("pMem = %p\n",static_cast<void*>(pMemory));
    delete [] pMemory;

    for(int i=0;i<100;++i){
        printf("iter:%d\n",i);
        void* pMemory = malloc(100);
        free(pMemory);
        sleep(2);
    }

    return 0;
}
