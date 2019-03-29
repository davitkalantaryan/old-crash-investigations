# Crash investigations

## Introduction  
  
The goal of this project to document and to implement some helper files in order to investigate crashes.  
Usually best way to investigate crashes is to attach debugger (if crash is reproducible) and see what is ongoing.  
From time to time this not possible for several reasons:  
 - No proper debugger is available, because host is server host with minimal installations  
 - Crash happens in very early stage of application  
 - Crash happens inside third party library (missing the sources)  
 - Crash happens not in the time of faulty code execution. For example memory is cleaned twice by some erroneous code, then crash due to this can happen later  
Not in all cases mentioned above there is guarantied method that will solve everything, but at least here you will find some hints those should work for many cases  
 
## Methods  
  - For UNIX implementing signal handler for SIGSEGV, that do following
  -- thread name  
  -- stack calculation  
  
  
## Useful links  
 - [hacking malloc<void *(*__malloc_hook)(size_t __size, const void *)>](https://ide.geeksforgeeks.org/F10DpiEh8N)  
 - [hacking realloc<void *weak_variable (*__realloc_hook)(void *__ptr, size_t __size, const void *)>](https://ide.geeksforgeeks.org/eMZJdkcAMy)  
 - [hacking free<void (*__free_hook) (void *__ptr,const void *)>](https://ide.geeksforgeeks.org/eMZJdkcAMy)   
