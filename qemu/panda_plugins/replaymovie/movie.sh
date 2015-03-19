#!/bin/bash
#
# NOTE: you may need to apt-get install the following:
# ffmpeg
#

ffmpeg -y -threads 0 -r 20 -i replay_movie_%03d.ppm replay.mp4 -qscale 5 -b 9600 || \
avconv -y -threads 0 -r 20 -i replay_movie_%03d.ppm replay.mp4 -qscale 5 -b 9600
