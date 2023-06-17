FROM pandare/panda

RUN apt-get update \
    && apt-get install -y python3-dev build-essential \
    && rm -rf /var/lib/apt/lists/* \
    \
    && python -m pip install --no-cache-dir yara-python \
    \
    && mkdir /data/ \
    && mkdir /data/recordings/ \
    && mkdir /data/rules/ \
    && mkdir /data/binaries/ \
    && mkdir /data/matches/

WORKDIR /data/
CMD python run.py

COPY rules/ /data/rules/
COPY binaries/decrypt /data/binaries/decrypt
COPY run.py /data/run.py
