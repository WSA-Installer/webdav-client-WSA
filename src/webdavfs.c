/* Development scaffold: explicitly refuses mounts until the WebDAV/FUSE engine exists. */
#include <stdio.h>
#include <string.h>
#ifndef VERSION
#define VERSION "0.1.0-dev"
#endif
int main(int argc, char **argv) {
 if (argc == 2 && (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-V"))) { printf("webdavfs %s (development scaffold)\n", VERSION); return 0; }
 if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) { puts("Usage: webdavfs <webdav-url> <mountpoint> [-o options]"); puts("This development build is not a functional filesystem yet."); return 0; }
 fputs("webdavfs: WebDAV/FUSE operation engine is not implemented; refusing to mount.\n", stderr); return 78;
}
