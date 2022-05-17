#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
	int fd = open("./testmnt", O_DIRECTORY);
	fsync(fd);
	close(fd);
	return 0;
}
