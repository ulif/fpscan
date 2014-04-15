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

#include <libfprint/fprint.h>

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


int main(void)
{
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
