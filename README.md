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
