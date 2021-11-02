import subprocess
from datetime import datetime

def runcommand (cmd):
    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True,
                            universal_newlines=True)
    std_out, std_err = proc.communicate()
    return proc.returncode, std_out, std_err

def datediff(date_start, date_end):
    date_format_str = '%Y-%m-%d %H:%M:%S'    
    start = datetime.strptime(date_start, date_format_str)
    end =   datetime.strptime(date_end, date_format_str)
    # Get the interval between two datetimes as timedelta object
    diff = end - start  
    return diff.total_seconds()
