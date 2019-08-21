#!/bin/bash
#
# NOTE: you may need to apt-get install the following:
# ffmpeg
# netpbm
#
# feel free to change the background and foreground (colour) values in the
# ppmlabel call, and the fontsize variable
fontsize=16
fnum=0
linenum=0
filename="replay_movie_counters.txt"
while read fline; do
    linenum=$(($linenum+1))
    if [ $linenum -gt 5 ]
    then
        printf -v fnumt "%03d" $fnum
        # cannot quote string properly for ppmlabel to keep leading spaces, so
        # just use leading zeroes always
        printf -v curcountfmted "%0*ld" $maxdigits $fline
        ppmlabel -background white -colour black -size $fontsize -x $xpos \
          -y $ypos -text "$curcountfmted" replay_movie_$fnumt.ppm \
          &>replay_movie_counter$fnumt.ppm
        fnum=$(($fnum+1))
    elif [ $linenum -eq 1 ]
    then
        maxdigits=$fline
    elif [ $linenum -eq 2 ]
    then
        width=$fline
    elif [ $linenum -eq 3 ]
    then
        xfract=$fline
        # x=width is the right side of the screen, so we really only have
        # (width - maxdigits * fontsize) pixels available width-wise
        # xpos=xfract * (width - (maxdigits * fontsize))
        maxextent=$(($maxdigits*$fontsize))
        x1=$(($width-$maxextent))
        # need to get really ugly to do floating point arithmetic
        xpos=`echo "$xfract $x1" | awk '{print $1*$2}'`
    elif [ $linenum -eq 4 ]
    then
        height=$fline
    else
        yfract=$fline
        # y=0 means the baseline is the top of the screen, so really we only
        # have (height - fontsize) pixels available if want to see the numbers
        # ypos = yfract * (height - fontsize) + fontsize
        ypos=`echo "$yfract $height $fontsize" | awk '{print ($1*($2-$3))+$3}'`
    fi
done < $filename
ffmpeg -y -threads 0 -r 20 -i replay_movie_counter%03d.ppm moviecounter.mp4 -qscale 5 -b 9600 || \
avconv -y -threads 0 -r 20 -i replay_movie_counter%03d.ppm moviecounter.mp4 -qscale 5 -b 96000
