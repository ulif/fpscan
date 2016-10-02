/*
 * fpscan.c
 *
 * Copyright (C) 2014 Uli Fouquet <uli at gnufix dot de>
 *
 * This file is part of fpscan, a programme for fingerprint scanners.
 *
 * fpscan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * fpscan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <libfprint/fprint.h>

/* The official name of this program.  */
#define PROGRAM_NAME "fpscan"
#define VERSION "0.1.1dev"

volatile sig_atomic_t fatal_error_in_progress = 0;

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
  {"compare", no_argument, NULL, (int)'c'},
  {"device", required_argument, NULL, (int)'d'},
  {"infile", required_argument, NULL, (int)'i'},
  {"outfile", required_argument, NULL, (int)'o'},
  {"image", no_argument, NULL, (int)'m'},
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

/* A filename for output data. 'fpm' stands for 'finger print minutiae' */
static char *filename = "data.fpm";

void
catch_error (int sig)
{
  /* Some error happened, clean up as good as we can */
  fp_exit ();
  fp_init ();
  fp_exit ();
  exit (sig);
}


void
fatal_error_signal (int sig)
{
  if (fatal_error_in_progress)
    raise (sig);
  fatal_error_in_progress = 1;

  fp_exit();
  fp_init();
  fp_exit();

  raise (sig);  /* reraising sets the return status correctly */
}

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
Usage: %s [OPTION]...                   (1st form, discovery mode)\n\
 or:   %s [OPTION]... -s [-o FILE]      (2nd form, scan mode)\n\
 or:   %s [OPTION]... -c [-i FILE]      (3rd form, comparison mode)\n\
\n\
In 1st form list available fingerprint scanners\n\
In 2nd form scan a finger and create a new fingerprint file\n\
In 3rd form scan a finger and compare it with fingerprint file\n\
",
	      program_name, program_name, program_name);
      (void) fputs ("\n\
Interact with fingerprint scanner devices.\n\
If no option was given, list available devices.\n\
\n\
", stdout);
      (void) fputs ("\
Mandatory arguments to long options are mandatory for short options too.\n\
", stdout);
      (void) fputs ("\
  -c, --compare      compare fingerprints and decide whether\n\
                     they match. Needs a fingerprint file\n\
                     for comparison. By default we look for a\n\
                     file named `data.fpm'. Use `-i' for a\n\
                     different filename. This option is mutual\n\
                     exclusive with `s'.\n\
  -d, --device=NUM     device to use for scan/verify. Equal to\n\
                     device ID as output by default output.\n\
  -i, --infile=FILE    path to a file with a previously stored\n\
                     fingerprint.\n\
  -o, --outfile=FILE   path to a file used for storing prints.\n\
                     The used file-format is libfprint-specific.\n\
  -s, --scan         do a scan. Creates a new fingerprint file\n\
                     named `data.fpm'. Use `-o' for a different\n\
                     filename. Mutual exclusive with `-c'.\n\
      --image        make output file an image (.pnm format).\n\
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
      fprintf (stderr, "Could not open device.\n");
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
      fprintf (stderr, "Could not open file `%s'\n", filename);
      return EXIT_FAILURE;
    }
  fwrite (buf, len, 1, fp);
  fclose (fp);
  return EXIT_SUCCESS;
}


static int
do_scan(const long int device_num, int verbose_flag, int image_flag)
{
  struct fp_dscv_dev *dev;
  struct fp_dev *handle;
  struct fp_print_data *data;
  enum fp_enroll_result scan_result;
  struct fp_img *img = NULL;
  int result = EXIT_SUCCESS;

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
      printf ("Scanning data, please touch the device\n");
    }

  while ((scan_result = fp_enroll_finger_img (handle, &data, &img)) > 2)
    {
      switch (scan_result)
	{
	case FP_ENROLL_PASS:
	  if (verbose_flag != 0)
	    {
	      printf ("Scan done. Another scan needed. ");
	      printf ("Please touch the device.\n");
	    }
	  else
	    {
	      printf ("pass\n");
	    }
	  result = EXIT_SUCCESS;
	  break;
	case FP_ENROLL_RETRY:
	case FP_ENROLL_RETRY_TOO_SHORT:
	case FP_ENROLL_RETRY_CENTER_FINGER:
	default:
	  if (verbose_flag != 0)
	    {
	      printf ("Scan failed, retrying. Please touch the device.\n");
	    }
	  else
	    {
	      printf ("retry\n");
	    }

	  result = EXIT_FAILURE;
	}  /* switch */

    }  /* while */

  /* Scan actually succeeded or failed */
  if (scan_result == FP_ENROLL_COMPLETE)
    {
      if (verbose_flag != 0)
	{
	  printf ("Fingerprint scan complete.\n");
	}
      else
	{
	  printf ("ok\n");
	}
      if (img)
	{
	  /* We received image data (not all devices support this) */
	  if (image_flag != 0)
	    {
	      /* The image data were requested */
	      fp_img_save_to_file (img, "data.pgm");
	      if (verbose_flag != 0)
		{
		  printf ("Wrote image to data.pgm\n");
		}
	    }
	  fp_img_free(img);
	}

      result = save_print_data (data, filename, verbose_flag);
    }
  else
    {
      if (verbose_flag != 0)
	{
	  printf ("Fingerprint scan failed.\n");
	}
      else
	{
	  printf ("fail\n");
	}
    }

  fp_dev_close (handle);
  return result;
}


/**
 * Load fingerprint data from file.
 *
 * Returns EXIT_FAILURE in case of any errors.
 *
 * XXX: Care for all possible error conditions.
 */
static int
load_from_file(char *path, struct fp_print_data **data, int verbose_flag)
{
  const unsigned int BUFLEN=4096;
  struct fp_print_data *fdata;
  size_t length = 0, tmp_length = 0;
  unsigned char *contents;
  FILE *fp;

  fp = fopen (path, "r");
  if (fp == NULL)
    {
      if (verbose_flag != 0)
	{
	  if (errno != 0)
	    {
	      fprintf (stderr, "Could not open file `%s': ", filename);
	      fprintf (stderr, "%s\n", strerror (errno));
	    }

	}
      return EXIT_FAILURE;
    }

  contents = malloc (BUFLEN * sizeof (char));

  while ((tmp_length = fread (contents + length, sizeof (char), BUFLEN, fp)
	  ) == BUFLEN)
    {
      length += BUFLEN;
      contents = realloc (contents, (length + BUFLEN) * sizeof (char));
    }
  if (!feof(fp))
    {
      free (contents);
      return EXIT_FAILURE;
    }
  fclose (fp);
  length += tmp_length;

  fdata = fp_print_data_from_data (contents, length);
  free (contents);
  *data = fdata;
  return EXIT_SUCCESS;
}


static int
verify_fp(const long int device_num, int verbose_flag)
{
  int result;
  struct fp_print_data *data_from_file;
  enum fp_verify_result verify_result;
  struct fp_dscv_dev *dev;
  struct fp_dev *handle;

  /* Try to load fingerprint data from file */
  result = load_from_file (filename, &data_from_file, verbose_flag);
  if (result != EXIT_SUCCESS)
    {
      fprintf (stderr, "Could not load data from file: %s.\n", filename);
      return EXIT_FAILURE;
    }

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
      printf ("Scanning finger, please touch the device\n");
    }
  verify_result = fp_verify_finger (handle, data_from_file);

  switch (verify_result)
    {
    case FP_VERIFY_NO_MATCH:
      if (verbose_flag != 0)
	{
	  printf ("No match\n");
	}
      else
	{
	  printf ("no-match\n");
	}
      break;
    case FP_VERIFY_MATCH:
      if (verbose_flag != 0)
	{
	  printf ("Match\n");
	}
      else
	{
	  printf ("ok\n");
	}
      break;
    default:
      if (verbose_flag != 0)
	{
	  printf ("Error while scanning\n");
	}
      else
	{
	  printf ("error: unknown reason\n");
	}
      return EXIT_FAILURE;
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
  int image_flag = 0;        /* indicates we handle images, not data files */
  int scan_flag = 0;
  int cmp_flag = 0;
  long int device_num = 0;
  int c;
  int resource = 1;
  int cmd_result = EXIT_SUCCESS;

  /* Establish handler for signals */
  signal (SIGINT, catch_error);
  signal (SIGHUP, catch_error);
  signal (SIGTERM, catch_error);
  signal (SIGKILL, fatal_error_signal);

  program_name = argv[0];

  while ((c = getopt_long (argc, argv, "cd:i:o:shv", long_options,
			   &_option_index))
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
	case 'i':
	  filename = optarg;
	  break;
	case 'o':
	  filename = optarg;
          break;
	case 'v':
	  verbose_flag = 1;
	  break;
	case 'm':
	  image_flag = 1;
	  break;
	case GETOPT_HELP_CHAR:
	  usage (EXIT_SUCCESS);
	  exit (EXIT_SUCCESS);
	case GETOPT_VERSION_CHAR:
	  version (stdout );
	  exit (EXIT_SUCCESS);
        case 'c':
          cmp_flag = 1;
	  if (scan_flag == 0)
	    {
	      break;
	    }
	case 's':
	  scan_flag = 1;
	  if (cmp_flag == 0)
	    {
	      break;
	    }
	  fprintf (stderr, "Usage of `-s' and `-c' is mutual exclusive.\n");
	default:
	  usage (EXIT_FAILURE);
	  exit (EXIT_FAILURE);
	}
    }
  if ((scan_flag == 1) && (cmp_flag == 1))
    {
      if (verbose_flag == 1)
	{
	  fprintf (stderr, "Usage of `-c' and `-s' is mutual exclusive.\n");
	}
      usage (EXIT_FAILURE);
    }
  resource = fp_init ();
  if (resource < 0) {
    fprintf (stderr, "Failed to initialize libfprint\n");
    exit (EXIT_FAILURE);
  }

  discovered_devs = fp_discover_devs ();

  /* Set the maximum index number for devices found... */
  set_max_dscv_dev ();

  if (scan_flag != 0)
    {
      cmd_result = do_scan (device_num, verbose_flag, image_flag);
    }
  else if (cmp_flag != 0)
    {
      cmd_result = verify_fp (device_num, verbose_flag);
    }
  else
    {
      detect_devices (verbose_flag);
    }

  fp_dscv_devs_free (discovered_devs);
  fp_exit ();
  exit (cmd_result);
}
