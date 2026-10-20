import os
import subprocess


def ping_host(host):
    # network diagnostics page
    return os.system("ping -c 1 " + host)


def archive_logs(directory, name):
    command = "tar czf /tmp/" + name + ".tgz " + directory
    return subprocess.check_output(command, shell=True)


def ping_host_safe(host):
    if not host.replace(".", "").replace("-", "").isalnum():
        raise ValueError("invalid host name")
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=10)
    return result.stdout


def disk_usage():
    result = subprocess.run(["df", "-h"], capture_output=True, text=True, timeout=10)
    return result.stdout


def convert_image(source, fmt):
    os.popen(f"convert {source} output.{fmt}")
