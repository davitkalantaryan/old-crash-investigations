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

#include <stdio.h>
#include <stdlib.h>
#include <crash_investigator.h>
#include <unistd.h>

static BOOL_T_2 HookFunctionStatic(enum HookType,void*, size_t a_size, void*)
//static BOOL_T_2 HookFunctionStatic(enum HookType,void*, size_t , void*)
{
    printf("size = %d\n",static_cast<int>(a_size));
    return 1;
}

int main()
{
    //usleep(10000000);
    InitializeCrashAnalizer();
    SetMemoryInvestigator(&HookFunctionStatic);
    printf("Crash analizer test!\n");
    void* pMemory = malloc(100);
    free(pMemory);
    CleanupCrashAnalizer();
	return 0;
}
