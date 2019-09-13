#!/bin/bash
#
# NOTE: you may need to apt-get install the following:
# ffmpeg
# netpbm
#
# pbmtext with the fixed size built in font uses characters that are each 7
# pixels wide; for one line of text, the text and margins are 25 pixels high,
# and the left and right margins are 7 pixels each
fontsize=7
linehgt=25
fnum=0
linenum=0
filename="replay_movie_counters.txt"
while read fline; do
    linenum=$(($linenum+1))
    if [ $linenum -gt 5 ]
    then
        printf -v fnumt "%03d" $fnum
        printf -v curcountfmted "%*ld" $maxdigits $fline
        pbmtext -builtin fixed "$curcountfmted" &>curcountfmted.ppm
        # note that xoff,yoff is the distance in pixels of the top left corner
        # of the the text image from the top left corner of the movie frame
        pnmcomp -xoff $xoffset -yoff $yoffset curcountfmted.ppm \
          replay_movie_$fnumt.ppm replay_movie_counter$fnumt.ppm
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
        # (width - (maxdigits+2) * fontsize) pixels available width-wise
        # xoffset=xfract * (width - ((maxdigits+2) * fontsize))
        maxextent=$((($maxdigits+2)*$fontsize))
        x1=$(($width-$maxextent))
        # need to get really ugly to do floating point arithmetic
        x2=`echo "$xfract $x1" | awk '{print $1*$2}'`
        # and then need to covert it back to integer to make pnmcomp happy
        printf -v xoffset "%.0f" $x2
    elif [ $linenum -eq 4 ]
    then
        height=$fline
    else
        yfract=$fline
        # y=0 means the baseline is the top of the screen, so really we only
        # have (height - linehgt) pixels available if want to see the numbers
        # yoffset = yfract * (height - linehgt)
        y1=`echo "$yfract $height $linehgt" | awk '{print $1*($2-$3)}'`
        printf -v yoffset "%.0f" $y1
    fi
done < $filename
rm curcountfmted.ppm
ffmpeg -y -threads 0 -r 20 -i replay_movie_counter%03d.ppm moviecounter.mp4 -qscale 5 -b 9600 || \
avconv -y -threads 0 -r 20 -i replay_movie_counter%03d.ppm moviecounter.mp4 -qscale 5 -b 96000
