/*
 * Commandline tool to deploy the libfprint library.
 * Unlike fprint-demo, this one does no GUI output.
 * Copyright (C) 2014 Uli Fouquet <uli at gnufix dot de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <libfprint/fprint.h>

/* The official name of this program.  */
#define PROGRAM_NAME "fpscan"
#define VERSION "0.1dev"

char *program_name = NULL;

/* These enum values cannot possibly conflict with the option values
   ordinarily used by commands, including CHAR_MAX + 1, etc.  Avoid
   CHAR_MIN - 1, as it may equal -1, the getopt end-of-options value.  */
enum
{
  GETOPT_HELP_CHAR = (0 - 2),
  GETOPT_VERSION_CHAR = (0 - 3)
};

/* Options this program supports.  */
static struct option const long_options[] = {
  {"verbose", no_argument, NULL, 'v'},
  {"help", no_argument, NULL, GETOPT_HELP_CHAR},
  {"version", no_argument, NULL, GETOPT_VERSION_CHAR},
  {NULL, 0, NULL, 0}
};


void
version(FILE *stream)
{
  fprintf (stream, "%s %s\n", PROGRAM_NAME, VERSION);
  fprintf (stream, "Copyright (C) 2014 Uli Fouquet and WAeUP Germany\n");
  fputs ("\
\n\
License GPLv3+: GNU GPL version 3 or later \
<http://gnu.org/licenses/gpl.html>.\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\
\n\
",
	 stream);
  fprintf (stream, "Written by Uli Fouquet.\n");
}


void
usage(int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, "Try `%s --help' for more information.\n", program_name);
  else
    {
      printf ("\
Usage: %s [OPTION]...\n",
	       program_name);
      fputs ("\n\
Interact with fingerprint scanner devices.\n\
If no option was given, list available devices.\n\
\n\
", stdout);
      fputs("\
Mandatory arguments to long options are mandatory for short options too.\n\
", stdout);
      fputs ("\
  -v, --verbose   be verbose\n\
      --help      display this help and exit\n\
      --version   output version information and exit\n\
", stdout);
      printf("\nReport bugs to uli at waeup dot org.\n");
    }
}


struct fp_dscv_dev *discover_device(struct fp_dscv_dev **discovered_devs)
{
	struct fp_dscv_dev *ddev = discovered_devs[0];
	struct fp_driver *drv;
	if (!ddev)
		return NULL;
	drv = fp_dscv_dev_get_driver(ddev);
	printf("Found device claimed by %s driver\n", fp_driver_get_full_name(drv));
	printf("Driver name: %s\n", fp_driver_get_name(drv));
	printf("Driver ID:   %d\n", fp_driver_get_driver_id(drv));
	printf("Scan type:   %d\n", fp_driver_get_scan_type(drv));

	struct fp_dev *dev = fp_dev_open(ddev);
	printf("Num Enroll Stages:  %d\n", fp_dev_get_nr_enroll_stages(dev));
	printf("Devtype:            %d\n", fp_dev_get_devtype(dev));
	printf("Supports Imaging:   %d\n", fp_dev_supports_imaging(dev));
	printf("Image WidthxHeight: %d x %d\n",
	       fp_dev_get_img_width(dev), fp_dev_get_img_height(dev));
	fp_dev_close(dev);
	return ddev;
}


int
main(int argc, char **argv)
{
  int verbose_flag = 0;
  int c;
  program_name = argv[0];

  while ((c = getopt_long (argc, argv, "hv", long_options, NULL))
	 != -1)
    {
      switch(c)
	{
	case 'v':
	  printf( "Be verbose\n" );
	  verbose_flag = 1;
	  break;
	case GETOPT_HELP_CHAR:
	  usage (EXIT_SUCCESS);
	  break;
	case GETOPT_VERSION_CHAR:
	  version (stdout );
	  exit (EXIT_SUCCESS);
	default:
	  usage (EXIT_FAILURE);
	  break;
	}
    }
  exit(0);


	int r = 1;
        int d = 0;
	int dev_num = 0;
	struct fp_dscv_dev *ddev;
	struct fp_dscv_dev **discovered_devs;
	struct fp_dscv_dev **ddevs;
	struct fp_dev *dev;
	struct fp_print_data *data;

	printf("fpscan 0.1dev\n"
	       "Fingerprint scanning for Linux based on libfprint.\n"
	       "This software is covered by LGPL 2.1.\n"
	       );
	//getchar();

	r = fp_init();
	if (r < 0) {
		fprintf(stderr, "Failed to initialize libfprint\n");
		exit(1);
	}
	fp_set_debug(3);

	discovered_devs = fp_discover_devs();
	if (!discovered_devs) {
		fprintf(stderr, "Could not discover devices\n");
		goto out;
	}

	ddevs = discovered_devs;
	for (ddevs = discovered_devs; *ddevs != NULL; ddevs++) {
	  dev_num++;
	  printf("Hi there! %p %p\n", ddevs, *ddevs);
	  discover_device(ddevs);
	}
	printf("Num: %ld\n", ddevs-discovered_devs);
	printf("Num2: %d\n", dev_num);

	ddev = discover_device(discovered_devs);
	if (!ddev) {
		fprintf(stderr, "No devices detected.\n");
		goto out;
	}
	dev = fp_dev_open(ddev);
	fp_dscv_devs_free(discovered_devs);
	if (!dev) {
		fprintf(stderr, "Could not open device.\n");
		goto out;
	}

out_close:
	fp_dev_close(dev);
out:
	fp_exit();
	return r;
}
