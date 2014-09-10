#!/bin/bash

ls *.ppm | parallel -m gm mogrify -format png -colorspace RGB
rm replay_movie*.ppm
ffmpeg -y -threads 0 -r 20 -i replay_movie_%03d.png replay.mp4 -qscale 5 -b 9600
