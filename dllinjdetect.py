"""
Classic DLL Injection technique detector rekall plugin
by Utku Corbaci ~ Malwation

Twitter: @rhotav
GitHub : @polynomen
"""

suspiciousPids = []

def detect(pid):
    threads = session.plugins.threads(pid)
    for threadx in threads:
            if("kernel32!LoadLibraryW" in str(threadx["win32_start_symb"])):
                    suspiciousPids.append((pid, threadx["Process"]))
                    break
try:
    pslist = session.plugins.pslist()
    for task in pslist.filter_processes():
        if(task.name == "lsass.exe"): # for Windows11 OS Version Errors
            continue
        detect(task.UniqueProcessId)
    if(len(suspiciousPids) > 0):
        print(" ")
        print("\nSuspicious PIDs:\n")
        for pid, addressThread in suspiciousPids:
            print("PID: %d Process: %s" % (pid, addressThread))
    else:
        print("No suspicious PIDs found.")
except Exception as e:
    print(e)