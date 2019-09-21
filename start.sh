#!/bin/bash

# First be sure to run: sudo npm install -g pm2

/usr/local/bin/pm2 start ./simpler.js >/dev/null 2>&1
