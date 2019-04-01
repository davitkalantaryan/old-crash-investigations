/*
 *  Copyright (C)
 *
 *  Written by Davit Kalantaryan <davit.kalantaryan@desy.de>
 */

 /**
  *   @file       crash_investigator.h
  *   @copyright
  *   @brief      header file for crash investigation APIs
  *   @author     Davit Kalantaryan <davit.kalantaryan@desy.de>
  *   @date       2019 Mar 30
  *   @details
  *       Details :  ...
  */
#ifndef CRASH_INVESTIGATOR_H
#define CRASH_INVESTIGATOR_H

#include <stddef.h>

#ifdef __cplusplus
#define EXTERN_C_2	extern "C"
#define BEGIN_C_DECL_2	extern "C"{
#define END_C_DECL_2	}
#else
#define EXTERN_C_2
#define BEGIN_C_DECL_2
#define END_C_DECL_2
#endif

BEGIN_C_DECL_2

typedef int BOOL_T_2  ;
enum MemoryType {CreatedByMalloc,CreatedByNew, CreatedByNewArray};
enum HookType {HookTypeMallocC, HookTypeCallocC, HookTypeReallocC, HookTypeFreeC,HookTypeNewCpp,HookTypeDeleteCpp,HookTypeNewArrayCpp,HookTypeDeleteArrayCpp};
typedef BOOL_T_2 (*TypeHookFunction)(enum HookType type,void* memoryCreatedOrWillBeFreed, size_t size, void* _memoryForRealloc);

extern int g_nVerbosity;

void InitializeCrashAnalizer(void);
void CleanupCrashAnalizer(void);
TypeHookFunction SetMemoryInvestigator(TypeHookFunction a_newFnc);

END_C_DECL_2


#endif  // #ifndef CRASH_INVESTIGATOR_H
