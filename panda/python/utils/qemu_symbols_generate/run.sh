HERE=`pwd`
BUILD=`realpath ../../../../build`
INCLUDE=`realpath ../../core/pandare/include/`

docker run -v $BUILD:/build -v $INCLUDE:/output structsbuilder bash -c "~/.pyenv/versions/3.6.6/bin/python ./run.py" 
