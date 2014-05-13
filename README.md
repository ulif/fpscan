fpscan
======

Fingerprint scanner commandline tool for Linux based on libfprint

This project is yet in very early state and not usable.

Building
--------

`fpscan` requires libfprint to be installed.

    $ autoreconf -fvi
    $ ./configure
    $ make

Installing
----------

Systemwide fpscan can be installed like this:

    $ sudo make install

Usage
-----

`fpscan` can operate in three modes:

  - list available devices
  - scan a finger to create a fingerprint file (`-s`)
  - scan a finger and check, whether it matches with data from file (`-c`)

By default devices are listed. `fpscan --help` gives a list of all
available options.

Detect locally available devices like this:

    $ fpscan -v

Gives you a list of locally attached and supported fingerprint scanners.

Using

    $ fpscan -s -v

a finger is scanned and the data stored to a new fingerprint file. By
default this file is called `data.fpm` in the local directory.

Using

    $ fpscan -c -v

a finger is scanned and compared to data in a file. The result is
output on the commandline. By default the finger is compared to data
in local file `data.fpm`.
