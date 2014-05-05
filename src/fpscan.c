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
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <libfprint/fprint.h>

/* The official name of this program.  */
#define PROGRAM_NAME "fpscan"
#define VERSION "0.1dev"

/*@null@*/
static char *program_name = NULL;

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
  {"device", required_argument, NULL, (int)'d'},
  {"scan", no_argument, NULL, (int)'s'},
  {"verbose", no_argument, NULL, (int)'v'},
  {"help", no_argument, NULL, GETOPT_HELP_CHAR},
  {"version", no_argument, NULL, GETOPT_VERSION_CHAR},
  {NULL, 0, NULL, 0}
};

static long int official_dev_num = 0;

/* The devices found locally. */
static struct fp_dscv_dev **discovered_devs = NULL;

/* The maximum index number for devices found. */
static long max_dscv_dev = -1;

static void
version(FILE *stream)
{
  fprintf (stream, "%s %s\n", PROGRAM_NAME, VERSION);
  fprintf (stream, "Copyright (C) 2014 Uli Fouquet and WAeUP Germany\n");
  fprintf (stream, "\
\n\
License GPLv3+: GNU GPL version 3 or later \
<http://gnu.org/licenses/gpl.html>.\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\
\n\
");
  fprintf (stream, "Written by Uli Fouquet.\n");
}


static void
usage(int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, "Try `%s --help' for more information.\n", program_name);
  else
    {
      printf ("\
Usage: %s [OPTION]...\n",
	       program_name);
      (void) fputs ("\n\
Interact with fingerprint scanner devices.\n\
If no option was given, list available devices.\n\
\n\
", stdout);
      (void) fputs ("\
Mandatory arguments to long options are mandatory for short options too.\n\
", stdout);
      (void) fputs ("\
  -d, --device=NUM   device to use for scan/verify.\n\
  -s, --scan         do a scan. Creates a new fingerprint file.\n\
  -v, --verbose      be verbose\n\
      --help         display this help and exit\n\
      --version      output version information and exit\n\
", stdout);
      printf ("\nReport bugs to uli at waeup dot org.\n");
    }
}

/**
 * Set the maximum index number for devices found.
 */
void
set_max_dscv_dev(void)
{
  for (max_dscv_dev = -1;
       (discovered_devs[max_dscv_dev + 1]);
       max_dscv_dev++);
}

/**
 * Get a unique id for a device.
 *
 * XXX: Create a real id by examining USB data/internal driver data.
 */
static long
get_device_id(struct fp_dscv_dev *dev)
{
  return (long) official_dev_num++;  /* This is nonsense... */
}

/**
 * Get a device by device id.
 *
 * This function is neither smart, nor secure, as long as we do not have
 * any (really) reliable device ids.
 *
 * Return a non-NULL pointer if the requested device exists.
 */
static struct fp_dscv_dev
*get_device_by_id(long int dev_id)
{
  if ((dev_id > max_dscv_dev) || (dev_id < 0))
    {
      return NULL;
    }
  return discovered_devs[dev_id];
}


static void
discover_device(struct fp_dscv_dev *ddev, const int verbose_flag)
{
  struct fp_driver *drv = NULL;
  struct fp_dev *dev = NULL;

  if (!ddev)
    {
      return;
    }
  drv = fp_dscv_dev_get_driver (ddev);
  dev = fp_dev_open (ddev);
  if (!dev)
    {
      fprintf(stderr, "Could not open device.\n");
      exit (EXIT_FAILURE);
    }
  if (verbose_flag != 0)
    {
      printf ("Found %s\n", fp_driver_get_full_name (drv));
      printf ("  Driver name: %s\n", fp_driver_get_name (drv));
      printf ("  Driver ID:   %d\n", (int) fp_driver_get_driver_id (drv));
      printf ("  Scan type:   %d (0=press, 1=swipe)\n",
	      fp_driver_get_scan_type (drv));
      printf ("  Device ID:   %d\n", (int) get_device_id (ddev));
      printf ("  Num Enroll Stages:  %d\n", fp_dev_get_nr_enroll_stages (dev));
      printf ("  Devtype:            %d\n", (int) fp_dev_get_devtype (dev));
      printf ("  Supports Imaging:   %d\n", fp_dev_supports_imaging (dev));
      printf ("  Image WidthxHeight: %d x %d\n",
	     fp_dev_get_img_width (dev), fp_dev_get_img_height (dev));
    }
  else
    {
      printf ("\
%s\n\
  %d %d %d %d %d %d %d\n\
",	      fp_driver_get_full_name (drv),
	      (int) fp_driver_get_driver_id (drv),
	      fp_driver_get_scan_type (drv),
	      fp_dev_get_nr_enroll_stages (dev),
	      (int) fp_dev_get_devtype (dev),
	      fp_dev_supports_imaging (dev),
	      fp_dev_get_img_width (dev),
	      fp_dev_get_img_height (dev)
	      );
    }
  fp_dev_close (dev);
}


static void
detect_devices(int verbose_flag)
{
  int dev_num = 0;
  struct fp_dscv_dev *curr_dev;

  if (!discovered_devs)
    {
      fprintf (stderr, "Could not discover devices\n");
      exit (EXIT_FAILURE);
    }

  if (*discovered_devs == NULL) {
    if (verbose_flag != 0)
      {
	fprintf (stdout, "No fingerprint scanners detected.\n");
      }
    else
      {
	fprintf (stdout, "0\n");
      }
    return;
  }

  official_dev_num = 0;  /* reset dev num counter */
  for (dev_num = 0; (curr_dev = discovered_devs[dev_num]); dev_num++)
    {
      discover_device (curr_dev, verbose_flag);
    }
  official_dev_num = 0;  /* reset dev num counter */
  curr_dev = NULL;
}


/**
 * Save binary fingerprint data to file.
 */
static int
save_print_data(struct fp_print_data *data, char *filename, int verbose_flag)
{
  FILE *fp;
  size_t len;
  unsigned char *buf;

  len = fp_print_data_get_data (data, &buf);
  if (verbose_flag)
    {
      printf ("Saving print data to %s\n", filename);
    }
  fp = fopen (filename, "w+");
  if (fp == NULL)
    {
      fprintf (stderr, "Could not open file `%s'\n");
      return EXIT_FAILURE;
    }
  fwrite (buf, len, 1, fp);
  fclose (fp);
  return EXIT_SUCCESS;
}


static int
do_scan(const long int device_num, int verbose_flag)
{
  struct fp_dscv_dev *dev;
  struct fp_dev *handle;
  struct fp_print_data *data;
  enum fp_enroll_result scan_result;

  dev = get_device_by_id (device_num);
  if (dev == NULL)
    {
      fprintf (stderr, "Invalid device number: %ld.\n", device_num);
      return EXIT_FAILURE;
    }
  handle = fp_dev_open (dev);
  if (handle == NULL)
    {
      fprintf (stderr, "Could not open device.\n");
      return EXIT_FAILURE;
    }

  if (verbose_flag != 0)
    {
      printf("Scanning data, please touch the device\n");
    }
  scan_result = fp_enroll_finger (handle, &data);
  if (verbose_flag != 0)
    {
      printf ("Did scan via device %ld (result: %d, %p).\n",
	      device_num, scan_result, data);
    }
  if (scan_result == FP_ENROLL_COMPLETE)
    {
      if (verbose_flag != 0)
	{
	  printf ("Fingerprint scan complete.\n");
	}
      save_print_data(data, "data.fp", verbose_flag);
    }
  fp_dev_close (handle);

  return EXIT_SUCCESS;
}


int
main(int argc, char **argv)
{
  char *_end_ptr;
  int _option_index = 0;
  int verbose_flag = 0;
  int scan_flag = 0;
  long int device_num = 0;
  int c;
  int resource = 1;
  int cmd_result = EXIT_SUCCESS;

  program_name = argv[0];

  while ((c = getopt_long (argc, argv, "d:shv", long_options, &_option_index))
	 != -1)
    {
      switch(c)
	{
	case 'd':
	  device_num = strtol (optarg, &_end_ptr, 10);
	  if (_end_ptr == optarg)
	    {
	      /* no leading digits in input */
	      fprintf (stderr, "not a valid device number: %s\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  if (errno != 0)
	    {
	      /* out of range or similar */
	      perror ("invalid device number");
	      exit (EXIT_FAILURE);
	    }
	  break;
	case 's':
	  scan_flag = 1;
	  break;
	case 'v':
	  verbose_flag = 1;
	  break;
	case GETOPT_HELP_CHAR:
	  usage (EXIT_SUCCESS);
	  exit (EXIT_SUCCESS);
	case GETOPT_VERSION_CHAR:
	  version (stdout );
	  exit (EXIT_SUCCESS);
	default:
	  usage (EXIT_FAILURE);
	  exit (EXIT_FAILURE);
	}
    }
  resource = fp_init ();
  if (resource < 0) {
    fprintf (stderr, "Failed to initialize libfprint\n");
    exit (EXIT_FAILURE);
  }

  discovered_devs = fp_discover_devs ();

  /* Set the maximum index number for devices found... */
  set_max_dscv_dev();

  if (scan_flag != 0)
    {
      cmd_result = do_scan(device_num, verbose_flag);
    }
  else
    {
      detect_devices (verbose_flag);
    }

  fp_dscv_devs_free (discovered_devs);
  fp_exit ();
  exit (cmd_result);
}
