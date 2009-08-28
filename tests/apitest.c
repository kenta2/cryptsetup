/*
 * cryptsetup library API check functions
 *
 * Copyright (C) 2009 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <errno.h>
#include <sys/stat.h>

#include "libcryptsetup.h"

#define DMDIR "/dev/mapper/"

#define DEVICE_1 "/dev/loop5"
#define DEVICE_1_UUID "28632274-8c8a-493f-835b-da802e1c576b"
#define DEVICE_2 "/dev/loop6"
#define DEVICE_EMPTY_name "crypt_zero"
#define DEVICE_EMPTY DMDIR DEVICE_EMPTY_name
#define DEVICE_ERROR_name "crypt_error"
#define DEVICE_ERROR DMDIR DEVICE_ERROR_name

#define CDEVICE_1 "ctest1"
#define CDEVICE_2 "ctest2"
#define CDEVICE_WRONG "O_o"

#define IMAGE1 "compatimage.img"
#define IMAGE_EMPTY "empty.img"

#define KEYFILE1 "key1.file"
#define KEY1 "compatkey"

#define KEYFILE2 "key2.file"
#define KEY2 "0123456789abcdef"

static int _debug   = 0;
static int _verbose = 1;

static char global_log[4096];

// Helpers
static int _prepare_keyfile(const char *name, const char *passphrase)
{
	int fd, r;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd != -1) {
		r = write(fd, passphrase, strlen(passphrase));
		close(fd);
	} else
		r = 0;

	return r == strlen(passphrase) ? 0 : 1;
}

static void _remove_keyfiles(void)
{
	remove(KEYFILE1);
	remove(KEYFILE2);
}

static int yesDialog(char *msg)
{
	return 1;
}

static void cmdLineLog(int class, char *msg)
{
	strncat(global_log, msg, sizeof(global_log));
}

static void reset_log()
{
	memset(global_log, 0, sizeof(global_log));
}

static struct interface_callbacks cmd_icb = {
	.yesDialog = yesDialog,
	.log = cmdLineLog,
};

static void _cleanup(void)
{
	struct stat st;

	//system("udevadm settle");

	if (!stat(DMDIR CDEVICE_1, &st))
		system("dmsetup remove " CDEVICE_1);

	if (!stat(DMDIR CDEVICE_2, &st))
		system("dmsetup remove " CDEVICE_2);

	if (!stat(DEVICE_EMPTY, &st))
		system("dmsetup remove " DEVICE_EMPTY_name);

	if (!stat(DEVICE_ERROR, &st))
		system("dmsetup remove " DEVICE_ERROR_name);

	if (!strncmp("/dev/loop", DEVICE_1, 9))
		system("losetup -d " DEVICE_1);

	if (!strncmp("/dev/loop", DEVICE_2, 9))
		system("losetup -d " DEVICE_2);

	system("rm -f " IMAGE_EMPTY);
	_remove_keyfiles();
}

static void _setup(void)
{
	system("dmsetup create " DEVICE_EMPTY_name " --table \"0 10000 zero\"");
	system("dmsetup create " DEVICE_ERROR_name " --table \"0 10000 error\"");
	if (!strncmp("/dev/loop", DEVICE_1, 9))
		system("losetup " DEVICE_1 " " IMAGE1);
	if (!strncmp("/dev/loop", DEVICE_2, 9)) {
		system("dd if=/dev/zero of=" IMAGE_EMPTY " bs=1M count=4");
		system("losetup " DEVICE_2 " " IMAGE_EMPTY);
	}

}

void check_ok(int status, int line, const char *func)
{
	char buf[256];

	if (status) {
		crypt_get_error(buf, sizeof(buf));
		printf("FAIL line %d [%s]: code %d, %s\n", line, func, status, buf);
		_cleanup();
		exit(-1);
	}
}

void check_ko(int status, int line, const char *func)
{
	char buf[256];

	memset(buf, 0, sizeof(buf));
	crypt_get_error(buf, sizeof(buf));
	if (status >= 0) {
		printf("FAIL line %d [%s]: code %d, %s\n", line, func, status, buf);
		_cleanup();
		exit(-1);
	} else if (_verbose)
		printf("   => errno %d, errmsg: %s\n", status, buf);
}

void check_equal(int line, const char *func)
{
	printf("FAIL line %d [%s]: expected equal values differs.\n", line, func);
	_cleanup();
	exit(-1);
}

void xlog(const char *msg, const char *tst, const char *func, int line, const char *txt)
{
	if (_verbose) {
		if (txt)
			printf(" [%s,%s:%d] %s [%s]\n", msg, func, line, tst, txt);
		else
			printf(" [%s,%s:%d] %s\n", msg, func, line, tst);
	}
}
#define OK_(x)		do { xlog("(success)", #x, __FUNCTION__, __LINE__, NULL); \
			     check_ok((x), __LINE__, __FUNCTION__); \
			} while(0)
#define FAIL_(x, y)	do { xlog("(fail)   ", #x, __FUNCTION__, __LINE__, y); \
			     check_ko((x), __LINE__, __FUNCTION__); \
			} while(0)
#define EQ_(x, y)	do { xlog("(equal)  ", #x " == " #y, __FUNCTION__, __LINE__, NULL); \
			     if ((x) != (y)) check_equal(__LINE__, __FUNCTION__); \
			} while(0)

#define RUN_(x, y)		do { printf("%s: %s\n", #x, (y)); x(); } while (0)

// OLD API TESTS
static void LuksUUID(void)
{
	struct crypt_options co = { .icb = &cmd_icb };

	co.device = DEVICE_EMPTY;
	EQ_(crypt_luksUUID(&co), -EINVAL);

	co.device = DEVICE_ERROR;
	EQ_(crypt_luksUUID(&co), -EINVAL);

	reset_log();
	co.device = DEVICE_1;
	OK_(crypt_luksUUID(&co));
	EQ_(strlen(global_log), 37); /* UUID + "\n" */
	EQ_(strncmp(global_log, DEVICE_1_UUID, strlen(DEVICE_1_UUID)), 0);

}

static void IsLuks(void)
{
	struct crypt_options co = {  .icb = &cmd_icb };

	co.device = DEVICE_EMPTY;
	EQ_(crypt_isLuks(&co), -EINVAL);

	co.device = DEVICE_ERROR;
	EQ_(crypt_isLuks(&co), -EINVAL);

	co.device = DEVICE_1;
	OK_(crypt_isLuks(&co));
}

static void LuksOpen(void)
{
	struct crypt_options co = {
		.name = CDEVICE_1,
		//.passphrase = "blabla",
		.icb = &cmd_icb,
	};

	OK_(_prepare_keyfile(KEYFILE1, KEY1));
	co.key_file = KEYFILE1;

	co.device = DEVICE_EMPTY;
	EQ_(crypt_luksOpen(&co), -EINVAL);

	co.device = DEVICE_ERROR;
	EQ_(crypt_luksOpen(&co), -EINVAL);

	co.device = DEVICE_1;
	OK_(crypt_luksOpen(&co));
	FAIL_(crypt_luksOpen(&co), "already open");

	_remove_keyfiles();
}

static void query_device(void)
{
	struct crypt_options co = {. icb = &cmd_icb };

	co.name = CDEVICE_WRONG;
	EQ_(crypt_query_device(&co), 0);

	co.name = CDEVICE_1;
	EQ_(crypt_query_device(&co), 1);

	OK_(strncmp(crypt_get_dir(), DMDIR, 11));
	OK_(strcmp(co.cipher, "aes-cbc-essiv:sha256"));
	EQ_(co.key_size, 16);
	EQ_(co.offset, 1032);
	EQ_(co.flags & CRYPT_FLAG_READONLY, 0);
	EQ_(co.skip, 0);
	crypt_put_options(&co);
}

static void remove_device(void)
{
	int fd;
	struct crypt_options co = {. icb = &cmd_icb };

	co.name = CDEVICE_WRONG;
	EQ_(crypt_remove_device(&co), -ENODEV);

	fd = open(DMDIR CDEVICE_1, O_RDONLY);
	co.name = CDEVICE_1;
	FAIL_(crypt_remove_device(&co), "device busy");
	close(fd);

	OK_(crypt_remove_device(&co));
}

static void LuksFormat(void)
{
	struct crypt_options co = {
		.device = DEVICE_2,
		.key_size = 256 / 8,
		.key_slot = -1,
		.cipher = "aes-cbc-essiv:sha256",
		.hash = "sha1",
		.flags = 0,
		.iteration_time = 10,
		.align_payload = 0,
		.icb = &cmd_icb,
	};

	OK_(_prepare_keyfile(KEYFILE1, KEY1));

	co.new_key_file = KEYFILE1;
	co.device = DEVICE_ERROR;
	FAIL_(crypt_luksFormat(&co), "error device");

	co.device = DEVICE_2;
	OK_(crypt_luksFormat(&co));

	co.new_key_file = NULL;
	co.key_file = KEYFILE1;
	co.name = CDEVICE_2;
	OK_(crypt_luksOpen(&co));
	OK_(crypt_remove_device(&co));
	_remove_keyfiles();
}

static void LuksKeyGame(void)
{
	int i;
	struct crypt_options co = {
		.device = DEVICE_2,
		.key_size = 256 / 8,
		.key_slot = -1,
		.cipher = "aes-cbc-essiv:sha256",
		.hash = "sha1",
		.flags = 0,
		.iteration_time = 10,
		.align_payload = 0,
		.icb = &cmd_icb,
	};

	OK_(_prepare_keyfile(KEYFILE1, KEY1));
	OK_(_prepare_keyfile(KEYFILE2, KEY2));

	co.new_key_file = KEYFILE1;
	co.device = DEVICE_2;
	co.key_slot = 8;
	FAIL_(crypt_luksFormat(&co), "wrong slot #");

	co.key_slot = 7; // last slot
	OK_(crypt_luksFormat(&co));

	co.new_key_file = KEYFILE1;
	co.key_file = KEYFILE1;
	co.key_slot = 8;
	FAIL_(crypt_luksAddKey(&co), "wrong slot #");
	co.key_slot = 7;
	FAIL_(crypt_luksAddKey(&co), "slot already used");

	co.key_slot = 6;
	OK_(crypt_luksAddKey(&co));

	co.key_file = KEYFILE2 "blah";
	co.key_slot = 5;
	FAIL_(crypt_luksAddKey(&co), "keyfile not found");

	co.new_key_file = KEYFILE2; // key to add
	co.key_file = KEYFILE1;
	co.key_slot = -1;
	for (i = 0; i < 6; i++)
		OK_(crypt_luksAddKey(&co)); //FIXME: EQ_(i)?

	FAIL_(crypt_luksAddKey(&co), "all slots full");

	// REMOVE KEY
	co.new_key_file = KEYFILE1; // key to remove
	co.key_file = NULL;
	co.key_slot = 8; // should be ignored
	 // only 2 slots should use KEYFILE1
	OK_(crypt_luksRemoveKey(&co));
	OK_(crypt_luksRemoveKey(&co));
	FAIL_(crypt_luksRemoveKey(&co), "no slot with this passphrase");

	co.new_key_file = KEYFILE2 "blah";
	co.key_file = NULL;
	FAIL_(crypt_luksRemoveKey(&co), "keyfile not found");

	// KILL SLOT
	co.new_key_file = NULL;
	co.key_file = NULL;
	co.key_slot = 8;
	FAIL_(crypt_luksKillSlot(&co), "wrong slot #");
	co.key_slot = 7;
	FAIL_(crypt_luksKillSlot(&co), "slot already wiped");

	co.key_slot = 5;
	OK_(crypt_luksKillSlot(&co));

	_remove_keyfiles();
}

size_t _get_device_size(const char *device)
{
	unsigned long size = 0;
	int fd;

	fd = open(device, O_RDONLY);
	if (fd == -1)
		return 0;
	(void)ioctl(fd, BLKGETSIZE, &size);
	close(fd);

	return size;
}

void DeviceResizeGame(void)
{
	size_t orig_size;
	struct crypt_options co = {
		.name = CDEVICE_2,
		.device = DEVICE_2,
		.key_size = 128 / 8,
		.cipher = "aes-cbc-plain",
		.hash = "sha1",
		.offset = 333,
		.skip = 0,
		.icb = &cmd_icb,
	};

	orig_size = _get_device_size(DEVICE_2);

	OK_(_prepare_keyfile(KEYFILE2, KEY2));

	co.key_file = KEYFILE2;
	co.size = 1000;
	OK_(crypt_create_device(&co));
	EQ_(_get_device_size(DMDIR CDEVICE_2), 1000);

	co.size = 2000;
	OK_(crypt_resize_device(&co));
	EQ_(_get_device_size(DMDIR CDEVICE_2), 2000);

	co.size = 0;
	OK_(crypt_resize_device(&co));
	EQ_(_get_device_size(DMDIR CDEVICE_2), (orig_size - 333));

	co.size = 0;
	co.offset = 444;
	co.skip = 555;
	co.cipher = "aes-cbc-benbi";
	OK_(crypt_update_device(&co));
	EQ_(_get_device_size(DMDIR CDEVICE_2), (orig_size - 444));

	memset(&co, 0, sizeof(co));
	co.icb = &cmd_icb,
	co.name = CDEVICE_2;
	EQ_(crypt_query_device(&co), 1);
	EQ_(strcmp(co.cipher, "aes-cbc-benbi"), 0);
	EQ_(co.key_size, 128 / 8);
	EQ_(co.offset, 444);
	EQ_(co.skip, 555);
	OK_(crypt_remove_device(&co));

	crypt_put_options(&co);

	_remove_keyfiles();
}

int main (int argc, char *argv[])
{
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp("-v", argv[i]) || !strcmp("--verbose", argv[i]))
			_verbose = 1;
		else if (!strcmp("--debug", argv[i]))
			_debug = _verbose = 1;
	}

	_cleanup();
	_setup();

#ifdef CRYPT_DEBUG_ALL
	crypt_set_debug_level(_debug ? CRYPT_DEBUG_ALL : CRYPT_DEBUG_NONE);
#endif

	RUN_(LuksUUID, "luksUUID API call");
	RUN_(IsLuks, "isLuks API call");
	RUN_(LuksOpen, "luksOpen API call");
	RUN_(query_device, "crypt_query_device API call");
	RUN_(remove_device, "crypt_remove_device API call");
	RUN_(LuksFormat, "luksFormat API call");
	RUN_(LuksKeyGame, "luksAddKey, RemoveKey, KillSlot API calls");
	RUN_(DeviceResizeGame, "regular crypto, resize calls");

	_cleanup();
	return 0;
}
