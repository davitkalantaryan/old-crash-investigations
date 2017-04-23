/*****************************************************************************
 * File:    mex_crasher.cpp
 * created: 2017 Apr 22
 *****************************************************************************
 * Author:	D.Kalantaryan, Tel:+49(0)33762/77552 kalantar
 * Email:	davit.kalantaryan@desy.de
 * Mail:	DESY, Platanenallee 6, 15738 Zeuthen
 *****************************************************************************
 * Description
 *   This is the entry point for the MEX file
 *   For crashing MATLAB
 ****************************************************************************/

#include <mex.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/timeb.h>
#include <execinfo.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

static void* ThreadFunction(void*);

void mexFunction(int /*a_nNumOuts*/, mxArray */*a_Outputs*/[],
    int a_nNumInps, const mxArray*a_Inputs[])
{
    mexPrintf("MATLAB crasher version=2\n");

    if(a_nNumInps && mxIsChar(a_Inputs[0]))
    {
        char* pcInput = (char*)alloca(64);
        mxGetString(a_Inputs[0],pcInput,63);
        if(strncmp(pcInput,"--do-crash",63)==0)
        {
            int* pnValue = (int*)0;
            *pnValue = 10;
            mexPrintf("Crashing! %d\n",*pnValue);
        }
        else if(strncmp(pcInput,"--do-crash-thred",63)==0)
        {
            pthread_t aNewThread;
            mexPrintf("Creating thread for crash!\n");
            pthread_create(&aNewThread,NULL,ThreadFunction,NULL);
        }
    }

}


static void* ThreadFunction(void*)
{
    int* pnValue = (int*)0;
    *pnValue = 10;
    return (void*)pnValue;
}
