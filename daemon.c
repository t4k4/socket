#include <stdlib.h>
#include <unistd.h>
#include <signal.h> /* for signal */
#include <sys/stat.h> /* for umask */
#include <sys/param.h> /* for NOFILE */

void init_daemon(void)
{
    int pid;
    int i;
    if(pid=fork())
        exit(0); /* exit parent process */
    else if(pid < 0)
        exit(1);
    
    /* child process */
    setsid(); 
    if(pid=fork())
        exit(0); /* exit child process */
    else if(pid < 0)
        exit(1);
    
    /* grandchild process */
    for(i=0; i<NOFILE; ++i)
        close(i); /* close opened file descriptor */
    chdir("/");
    umask(0);

    signal(SIGCHLD, SIG_IGN); /* ignore SIGCHILD */
}