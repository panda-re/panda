#!/bin/bash

TARGETS=(i486-linux-musl-cross mips-linux-musl-cross mipsel-linux-musl-cross mips64-linux-musl-cross arm-linux-musleabi-cross aarch64-linux-musl-cross)

bold=$(tput bold)
red=$(tput setaf 1)
cyan=$(tput setaf 6)
normal=$(tput sgr0)

CMD_NAME="./musl_toolchains.sh"

function error {
    >&2 echo "${bold}${red}error${normal}: $@"
}

function suggest {
    >&2 echo "  ${bold}${cyan}help${normal}: $@"
}

function help {
    >&2 echo "${bold}Usage:${normal}"
    >&2 echo "    ${CMD_NAME} [subcommand]"
    >&2 echo ""
    >&2 echo "${bold}Subcommands:${normal}"
    >&2 echo "    install               Install all needed musl toolchains to the current directory"
    >&2 echo "    uninstall             Remove all installed musl toolchains from the current directory"
    >&2 echo "    list                  List the musl toolchains supported or installed by this script"
    >&2 echo "    check-installed       Checks if a target or set of targets are installed"
    >&2 echo "    help                  Print this help text"
}

function install_help {
    >&2 echo "${bold}Usage:${normal}"
    >&2 echo "    ${CMD_NAME} install [args]"
    >&2 echo ""
    >&2 echo "Install all the toolchains supported by this script"
    >&2 echo ""
    >&2 echo "${bold}Arguments:${normal}"
    >&2 echo "    --help                Print this help text"
    >&2 echo "    --to <dir>            Install the toolchains inside of the <dir> directory (default: cwd)"
}

function uninstall_help {
    >&2 echo "${bold}Usage:${normal}"
    >&2 echo "    ${CMD_NAME} uninstall [args]"
    >&2 echo ""
    >&2 echo "Uninstall all the toolchains supported by this script"
    >&2 echo ""
    >&2 echo "${bold}Arguments:${normal}"
    >&2 echo "    --help                Print this help text"
    >&2 echo "    --from <dir>          Uninstall any toolchains inside of the <dir> directory (default: cwd)"
}

function list_targets_help {
    >&2 echo "${bold}Usage:${normal}"
    >&2 echo "    ${CMD_NAME} list [args]"
    >&2 echo ""
    >&2 echo "List the target triples supported or installed by this script"
    >&2 echo ""
    >&2 echo "${bold}Arguments:${normal}"
    >&2 echo "    --help                Print this help text"
    >&2 echo "    --installed           Show only installed targets"
    >&2 echo "    --in <dir>            When checking for installed toolchains, look inside of the <dir> directory (default: cwd)"
}

function check_installed_help {
    >&2 echo "${bold}Usage:${normal}"
    >&2 echo "    ${CMD_NAME} check-installed [args]"
    >&2 echo ""
    >&2 echo "Checks if a set of targets are installed"
    >&2 echo ""
    >&2 echo "${bold}Arguments:${normal}"
    >&2 echo "    --help                Print this help text"
    >&2 echo "    --all                 Check that all available targets are selected"
    >&2 echo "    --in <dir>            When checking for installed toolchains, look inside of the <dir> directory (default: cwd)"
    >&2 echo "    <TARGETS...>          A list of targets to check are installed"
}

function install {
    cwd=`pwd`
    args=("$@")

    while [[  ${#args[@]} -ne 0 ]]
    do
        case ${args[0]} in
            "--help" | "-h")
                install_help
                exit 0
                ;;
            "--to")
                cwd="${args[1]}"
                args=("${args[@]:2}")
                ;;
            *)
                error "Found '${args[0]}'"
                install_help
                exit 1
                ;;
        esac
    done

    if [[ $cwd == "" ]]
    then
        error "empty directory to install to"
        exit 1
    fi

    if ! [[ -d $cwd ]]
    then
        >&2 echo "Directory '$cwd' does not exist, creating for you..."
        mkdir -p $cwd
    fi

    path_prefix=""

    for target in ${TARGETS[@]}
    do
        full_path="$cwd/$target/bin"
        if [ -d $full_path ]
        then
            echo "$target is already installed"
        else
            echo "${bold}Downloading $target...${normal}"
            curl -o "$cwd/$target.tgz" https://musl.cc/$target.tgz && tar -xzf "$cwd/$target.tgz"
            rm "$cwd/$target.tgz"
        fi

        path_prefix="$full_path:$path_prefix"
    done

    QUOTE='"'
    DOLLAR='$'

    >&2 echo ""
    >&2 echo "${bold}Add to PATH using:${normal}"
    echo "    export PATH=${QUOTE}${path_prefix}${DOLLAR}PATH${QUOTE}"
}

function uninstall {
    cwd=`pwd`
    args=("$@")

    while [[  ${#args[@]} -ne 0 ]]
    do
        case ${args[0]} in
            "--help" | "-h")
                uninstall_help
                exit 0
                ;;
            "--from")
                cwd="${args[1]}"
                args=("${args[@]:2}")
                ;;
            *)
                error "Found '${args[0]}'"
                uninstall_help
                exit 1
                ;;
        esac
    done

    if [[ $cwd == "" ]]
    then
        error "empty directory to uninstall from"
        exit 1
    fi

    for target in ${TARGETS[@]}
    do
        full_path="$cwd/$target/bin"
        if [ -d $full_path ]
        then
            rm -rf "$cwd/$target" && echo "Removed $target"
            >/dev/null 2>/dev/null rm $target.tgz || true
        else
            >/dev/null 2>/dev/null rm $target.tgz || true
        fi
    done

    echo ""
    echo "All targets uninstalled"
}

function list_targets {
    check_installed=false
    cwd_set=false

    cwd=`pwd`
    args=("$@")

    while [[  ${#args[@]} -ne 0 ]]
    do
        case ${args[0]} in
            "--help" | "-h")
                list_targets_help
                exit 0
                ;;
            "--installed")
                check_installed=true
                args=("${args[@]:1}")
                ;;
            "--in")
                cwd_set=true
                cwd="${args[1]}"
                args=("${args[@]:2}")
                ;;
            *)
                error "Found '${args[0]}', unexpected for 'list' subcommand"
                list_targets_help
                exit 1
                ;;
        esac
    done

    if [[ $cwd_set = true && $check_installed = false ]]
    then
        error "'--in' was passed, requires '--installed' to be passed as well"
        exit 1
    fi

    at_least_one_installed=false

    for target in ${TARGETS[@]}
    do
        full_path="$cwd/$target/bin"

        if [[ $check_installed = false || -d $full_path ]]
        then
            echo $target
            at_least_one_installed=true
        fi
    done

    if [[ $check_installed = true && $at_least_one_installed = false ]]
    then
        >&2 echo "${bold}No targets installed${normal}"
    fi
}

containsElement () {
    local e match="$1"
    shift

    for e; do [[ "$e" == "$match"  ]] && return 0; done

    return 1
}

function check_installed {
    check_installed=false
    cwd_set=false

    cwd=`pwd`
    args=("$@")

    selected_targets=()

    while [[  ${#args[@]} -ne 0 ]]
    do
        case ${args[0]} in
            "--help" | "-h")
                check_installed_help
                exit 0
                ;;
            "--all")
                check_all=true
                args=("${args[@]:1}")
                ;;
            "--in")
                cwd="${args[1]}"
                args=("${args[@]:2}")
                ;;
            *)
                if containsElement "${args[0]}" "${TARGETS[@]}"; then
                    selected_targets+=("${args[0]}")
                    args=("${args[@]:1}")
                else
                    error "Found '${args[0]}', unexpected for 'check-installed' subcommand, not a valid flag or target name"
                    suggest "use '${CMD_NAME} list' to see a list of valid targets"
                    >&2 echo ""
                    check_installed_help
                    exit 1
                fi
                ;;
        esac
    done

    if [[ $check_all = true ]]; then
        selected_targets=("${TARGETS[@]}")
    fi

    if [[ ${#selected_targets[@]} -eq 0 ]]; then
        error "No targets specified"
        suggest "pass '--all' or a space-separated list of toolchain names"
        exit 1
    fi

    for target in ${selected_targets[@]}
    do
        full_path="$cwd/$target/bin"

        if ! [[ -d $full_path ]]
        then
            error "Toolchain '$target' is not installed in '$cwd'"
            exit 1
        fi
    done

    >&2 echo "All toolchains are installed."
}

if [[ $# -lt 1 ]]
then
    help
    exit 1
fi

case $1 in
    help | "-h" | "--help")
        help
        ;;
    list)
        list_targets ${@:2}
        ;;
    install)
        install ${@:2}
        ;;
    uninstall | remove | delete)
        uninstall ${@:2}
        ;;
    "check-installed")
        check_installed ${@:2}
        ;;
    *)
        >&2 echo "Invalid usage"
        help
esac
