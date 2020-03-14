import panda
import requests

# Scripts for building qcows. WIP
upstream = 'https://cloud-images.ubuntu.com/releases/'

def get_filenames(url):
    '''
    Given a url with directory listings, grab all the file/directory names
    '''
    r = requests.get(url)
    link_text = r.text.split("Parent Directory")[1].split("<hr>")[0]
    link_lines = link_text.split("\n")
    names = []
    for line in link_lines:
        try:
            names.append(line.split("<a href=\"")[1].split("/\">")[0])
        except:
            continue
    return names


def build_all():
    '''
    Build qcows for our supported architectures for everything on the ubuntu website
    '''
    # For each major release...
    major_releases = get_filenames(upstream)

    # For each minor release (exclude 'current')

    for major in major_releases[::-1]: # Run newest to oldest
        major_url = upstream + major
        minor_versions = get_filenames(major_url)
        minor_releases = [x for x in minor_versions if x.startswith('release') and x != 'release'] # Filter out RC/beta versions as well as latest (duplicate of another)


        for minor in minor_releases:
            downloads = get_filenames(major_url + "/" + minor)

            for arch in ['i386', 'amd64', 'armhf', 'arm64', 'ppc64']:
                build_qcow(major, minor, arch)

def process(major, minor, arch):
    '''
    WIP
    1) Get the necessary files
    2) Boot and change root passwd
    3) Boot, login and take snapshot
    4) Shutdown
    5) Convert to a qcow
    6) (optional) analyze qcow to extract metadata
    6) Upload qcow to file server
    '''
    base = "data"
    os.makedirs(base, exist_ok=True)
    os.makedirs(os.path.join(*[base, minor]), exist_ok=True)
    os.makedirs(os.path.join(*[base, minor, major]), exist_ok=True)
    os.makedirs(os.path.join(*[base, minor, major, arch]), exist_ok=True)

    url = upstream + major + "/" + minor + "/" +
    r = requests.get(url, allow_redirects=True)


process('bionic', 'release-20180517', 'i386')
"""
kernel= 'bionic-server-cloudimg-amd64-vmlinuz-generic'
hda = 'bionic-server-cloudimg-amd64.img'

qemu-system-x86_64 -nographic -kernel ./bionic-server-cloudimg-amd64-vmlinuz-generic \
  -hda ./bionic-server-cloudimg-amd64.img \
  -append "console=ttyS0 root=/dev/sda1 init=/bin/sh -c \"mount -o remount rw / && echo root:mypass | chpasswd & sleep 3; mount -o remount ro /; halt -f\"" &
"""
