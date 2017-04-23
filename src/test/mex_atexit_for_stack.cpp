/*****************************************************************************
 * File:    mex_atexit_for_stack.cpp
 * created: 2017 Apr 22
 *****************************************************************************
 * Author:	D.Kalantaryan, Tel:+49(0)33762/77552 kalantar
 * Email:	davit.kalantaryan@desy.de
 * Mail:	DESY, Platanenallee 6, 15738 Zeuthen
 *****************************************************************************
 * Description
 *   This is the entry point for the MEX file
 *   For registering stack tracing during exit
 ****************************************************************************/

#define FILE_NAME_EXIT  "stack.txt"
#define FILE_NAME_CRASH  "stack_crash.txt"


#include <QMessageBox>
#include <QApplication>
#include <QAbstractButton>
#include <QThread>

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
#include <common_unnamedsemaphorelite.hpp>

//#define SIGNAL_FOR_MAIN_THREAD  (SIGRTMIN + 8)
#define SIGNAL_FOR_MAIN_THREAD SIGUSR2

static common::UnnamedSemaphoreLite s_semaphore;
static int s_nInited = 0;
static int s_nLogInAnyCase=1;
static int s_nMatlabTryingToCrash=0;
static pthread_t s_mainThreadHandle = (pthread_t)0;

static void AtExitFunction(void);
static void MexExitFunction(void);
static void SigSegvHandler(int sigNum, siginfo_t * sigInfo, void * stackInfo);
static void SigRtHandler(int sigNum, siginfo_t * sigInfo, void * stackInfo);

typedef void (*TYPE_SIG_HANDLER)(int sigNum, siginfo_t * sigInfo, void * stackInfo);
static struct sigaction s_sigSegvActionOld;
static struct sigaction s_sigRtActionOld;

void mexFunction(int /*a_nNumOuts*/, mxArray */*a_Outputs*/[],
    int a_nNumInps, const mxArray*a_Inputs[])
{
    mexPrintf("Version=6\n");

    if (!s_nInited)
    {
        struct sigaction* pSigAction;
        struct sigaction sigAction;

        s_nInited = 1;
        s_mainThreadHandle = pthread_self();
        mexLock();
        mexAtExit(MexExitFunction);
        atexit(AtExitFunction);

        sigemptyset(&sigAction.sa_mask);
        sigAction.sa_flags = SA_SIGINFO;
        sigAction.sa_sigaction = (TYPE_SIG_HANDLER)SigSegvHandler;
        //sigAction.sa_flags = 0;
        //sigAction.sa_handler = (TYPE_SIG_HANDLER)SignalHandlerSimple;
        sigaction(SIGSEGV, &sigAction, &s_sigSegvActionOld);

        sigAction.sa_sigaction = (TYPE_SIG_HANDLER)SigRtHandler;
        sigaction(SIGNAL_FOR_MAIN_THREAD, &sigAction, &s_sigRtActionOld);

        pSigAction = &s_sigSegvActionOld;
        mexPrintf("Sv:flag&SA_SIGINFO=%d,sigaction=%p,handler=%p\n",pSigAction->sa_flags&SA_SIGINFO,
                  pSigAction->sa_sigaction,pSigAction->sa_handler);
        pSigAction = &s_sigRtActionOld;
        mexPrintf("Rt:flag&SA_SIGINFO=%d,sigaction=%p,handler=%p\n",pSigAction->sa_flags&SA_SIGINFO,
                  pSigAction->sa_sigaction,pSigAction->sa_handler);

    } // if (!s_nInited)
    else
    {
        if(a_nNumInps && mxIsChar(a_Inputs[0]))
        {
            char* pcInput = (char*)alloca(64);
            mxGetString(a_Inputs[0],pcInput,63);
            if(strncmp(pcInput,"--print-always",63)==0)
            {
                s_nLogInAnyCase = 1;
            }
            else if(strncmp(pcInput,"--print-when-crash",63)==0)
            {
                s_nLogInAnyCase = 0;
            }
        }
        mexPrintf("Stack calculator already registered!\n");
    }

}

static void StackCalculation(const char* a_cpcFileName,const char* a_cpcAdditional);

static void AtExitFunction(void)
{
    if(s_nLogInAnyCase){StackCalculation(FILE_NAME_EXIT,__FUNCTION__);}
}


static void MexExitFunction(void)
{
    if(s_nLogInAnyCase){StackCalculation(FILE_NAME_EXIT,__FUNCTION__);}
}


void SigRtHandler(int a_nSigNum, siginfo_t * a_pSigInfo, void * a_pStackInfo)
{
    if(s_nMatlabTryingToCrash){s_semaphore.wait();s_nMatlabTryingToCrash=0;}
    else {(*(s_sigRtActionOld.sa_sigaction))(a_nSigNum, a_pSigInfo, a_pStackInfo);}
}


static void SigSegvHandler(int a_nSigNum, siginfo_t * a_pSigInfo, void * a_pStackInfo)
{
    static int snMasked3 = 0;
    const char* cpcFileName = a_pSigInfo->si_pid==0 ? FILE_NAME_CRASH : FILE_NAME_EXIT;
    int nMsgBoxReturn= snMasked3 ? QMessageBox::No : QMessageBox::Cancel;
    char vcCmdLine[512];

    //if(snMasked2){(*(s_sigSegvActionOld.sa_sigaction))(a_nSigNum, a_pSigInfo, a_pStackInfo);return;}

    snprintf(vcCmdLine,127,"%s,si_pid=%d",__FUNCTION__,a_pSigInfo->si_pid);
    StackCalculation(cpcFileName,vcCmdLine);

    if(a_pSigInfo->si_pid==0) // Real crash signal comes from kernel
    {
        pthread_t currentThread = pthread_self();
        bool bIsMaintThread = s_mainThreadHandle==currentThread;
        FILE* fpCmdLine;

        if(!bIsMaintThread && !snMasked3){s_nMatlabTryingToCrash=1;pthread_kill(s_mainThreadHandle,SIGNAL_FOR_MAIN_THREAD);}

        if(snMasked3){
            usleep(100000);
        }
        else{
            snprintf(vcCmdLine,511,"/proc/%d/cmdline",(int)getpid());
            fpCmdLine=fopen(vcCmdLine,"r");

            if(fpCmdLine){
                char* argv[2] = {vcCmdLine,NULL};
                int argc=1;
                int nInd(0);
                char vcReport[256];
                char cMinCode = '/' < 'a' ? '/' : 'a';

                for(vcCmdLine[nInd]=fgetc(fpCmdLine);vcCmdLine[nInd]>=cMinCode;vcCmdLine[++nInd]=fgetc(fpCmdLine));
                vcCmdLine[nInd]=0;

                snprintf(vcReport,255,
                        "Pid: %d. Some critical error has been accurred in MATLAB.\n"
                        "Crash was catched. Please select the action to continue.",(int)getpid());


                QApplication app(argc,argv);
                QFlags<QMessageBox::StandardButton> messageBoxFlags =
                        currentThread==s_mainThreadHandle ?
                            QMessageBox::Ok|QMessageBox::Cancel : QMessageBox::Ok|QMessageBox::No|QMessageBox::Cancel;
                QMessageBox aMessageBox(QMessageBox::Critical,QObject::tr("Crash!!!"),
                                        QObject::tr(vcReport),
                                        messageBoxFlags,
                                        NULL);
                aMessageBox.setDetailedText(QObject::tr(
                        "Some critical error accured in MATLAB.\n"
                        "Please try to contact the personal from control group,\n"
                        "or make an logebook entry and send an Email to pitz-control@desy.de"));
                //aMessageBox.setFixedSize(1900,550);
                QList<QAbstractButton *> lstButtons = aMessageBox.buttons();
                lstButtons.at(0)->setText(QObject::tr("StopAndWaitDebuger"));
                lstButtons.at(1)->setText(QObject::tr("Do crash now"));
                if(!bIsMaintThread){lstButtons.at(2)->setText(QObject::tr("Continue MATLAB"));}
                nMsgBoxReturn=aMessageBox.exec();

                fclose(fpCmdLine);
            } // if(fpCmdLine){
        } // else of if(snMasked3){

    } // if(a_pSigInfo->si_pid==0) // Real crash signal comes from kernel

    switch (nMsgBoxReturn) {
      case QMessageBox::Ok:
        // Save was clicked
        while(1){usleep(100000000);}
        break;
      case QMessageBox::No:
        //snMasked2 = 1;
        if(!snMasked3){s_semaphore.post();}
        snMasked3 = 1;
        break;
    case QMessageBox::Cancel: // Crash Matlab
        //exit(3);
        (*(s_sigSegvActionOld.sa_sigaction))(a_nSigNum, a_pSigInfo, a_pStackInfo);
        break;
      default:
        //exit(3);
        (*(s_sigSegvActionOld.sa_sigaction))(a_nSigNum, a_pSigInfo, a_pStackInfo);
        break;
    }


}


static void StackCalculation(const char* a_cpcFileName, const char* a_cpcAdditional)
{
#define BUFFER_SIZE 256
    char** ppSymbols;
    void * pStack[BUFFER_SIZE];
    FILE* fpFile=NULL;
    char* pTmln;
    timeb	aCurrTm;
    int nStackDeepness=backtrace(pStack,BUFFER_SIZE);

    if(nStackDeepness<0)
    {
        fprintf(stderr,
                "!!!!!!!!!!!!!!!!!!!!!Unable to calculate stack!\n"
                "!!!!!!!!!!!!!!!!!!!!!Source file:%s,line:%d\n",__FILE__,__LINE__);
        return;
    }

    fpFile = fopen(a_cpcFileName,"a+");
    if(!fpFile){
        fprintf(stderr,
                "!!!!!!!!!!!!!!!!!!!!!Unable to open file (stackDepness=%d)\n"
                "!!!!!!!!!!!!!!!!!!!!!Source file:%s,line:%d\n",nStackDeepness,__FILE__,__LINE__);
        return;
    }

    ftime( &aCurrTm );
    pTmln = ctime( & ( aCurrTm.time ) );
    fprintf( fpFile, "=============[%.19s.%.3hu %.4s]: pid=%d,stackDeep=%d, %s========\n",
             pTmln,aCurrTm.millitm,&pTmln[20],(int)getpid(),nStackDeepness,a_cpcAdditional);

    ppSymbols = backtrace_symbols(pStack,nStackDeepness);
    if(ppSymbols)
    {
        for(int i(0); i<nStackDeepness; ++i)
        {
            fprintf(fpFile,"%s\n",ppSymbols[i]);
        }
        free(ppSymbols);
    }
    else{
        fprintf(fpFile,"Unable to get trace symbols\n");
    }

    fprintf( fpFile, "=========End [%.19s.%.3hu %.4s]: pid=%d,stackDeep=%d, %s========\n\n\n",
             pTmln,aCurrTm.millitm,&pTmln[20],(int)getpid(),nStackDeepness,a_cpcAdditional);

    fflush( fpFile );

    fclose(fpFile);
}
