#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define TAB_SIZE 13

static const long	auth_syscall[] =
  {
    3,
    4,
    5,
    6,
    11,
    33,
    45,
    91,
    125,
    192,
    197,
    243,
    252 
  };

static bool	syscall_check(long syscall)
{
  int		i = 0;

  while (i < TAB_SIZE)
    {
      if (auth_syscall[i] == syscall)
	{
	  printf("syscall %ld is ok \n", syscall);
	  return false;
	}
      ++i;
    }
  return true;
}

int main(int argc, char **argv)
{
  int i;
  pid_t child;
  int status;
  long orig_eax;
  int kill_ret = 0;

  child = fork();
  if (child == -1)
    return 1;
  if(child == 0)
    {
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execl(argv[1], argv[1],  NULL);
    }
  else
    {
      i = 0;
      while(1)
	{
	  wait(&status);
	  if (WIFEXITED(status) || WIFSIGNALED(status) )
	    break;
	  orig_eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);
	  if (syscall_check(orig_eax))
	    {
	      printf("program killed %d\n", child);
	      kill_ret = kill(child, SIGKILL);
	      ptrace(PTRACE_KILL, child, NULL, NULL);
	    }
	  printf("%d time, system call %ld\n", i++, orig_eax);
	  ptrace(PTRACE_SYSCALL, child, NULL, NULL);
	}
    }

  return 0;
}
