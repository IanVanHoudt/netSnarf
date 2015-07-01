/* Copyright (c) Ian Van Houdt 2015 */

/*
*	daemon.c
*		The daemon for the wireSnarf project. 
*
*	notable functions:
* 		int main()
*/

#include <stdio.h>
#include <stdlib.h>
#include "../../include/daemon.h"

int DEBUG = 1;

int main(int argc, char *argv[])
{
    if (DEBUG) fprintf(stdout, "daemon: main()\n");
    testPrint();
}

int testPrint()
{
    fprintf(stderr, "testing inclusion\n");
}
