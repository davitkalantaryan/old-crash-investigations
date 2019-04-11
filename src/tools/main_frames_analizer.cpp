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
// (gdb) info address _Z9eq_serveriPPc

#include <crash_investigator.h>
#include <iostream>


int main()
{


    //CleanupCrashAnalizer();
	return 0;
}
