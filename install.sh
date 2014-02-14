#!/bin/sh

apxs2 -i -c *.c && service apache2 restart
