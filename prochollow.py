"""
Process Hollowing technique detector rekall plugin
by Utku Corbaci ~ Malwation

Twitter: @rhotav
GitHub : @polynomen

`run -i prochollow.py`
"""

suspiciousTasks = []

def protectTest(vadList):
    for vad in vadList:
        if(vad["protect"] == "EXECUTE_READWRITE"):
            return True
    return False

def isSuspicious(task):
    x = True
    vadList = session.plugins.vad().collect_vadroot(task.RealVadRoot, task)

    if(len(vadList) <= 3):
        return False

    for vad in vadList:
        filename = str(vad["filename"]).strip()
        if(filename == None):
            continue
        if(str(task.name) in filename):
            x = False
            break
    if(x):
        if(protectTest(vadList)):
            x = True
        else:
            x = False

    return x

def collectSuspiciousTasks():
    pslist = session.plugins.pslist()
    for task in pslist.filter_processes():
        if(task.name == "lsass.exe"): # for Windows11 OS Version Errors
            continue
        if(isSuspicious(task)):
            suspiciousTasks.append(task)

collectSuspiciousTasks()
if(len(suspiciousTasks) > 0):
    print(" ")
    print("Collected Suspicious PIDs:")
    for task in suspiciousTasks:
        print("PID: %d Process: %s" % (task.UniqueProcessId, task.name))
else:
    print("No suspicious PIDs found.")