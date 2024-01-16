import logging
import json
from cbapi.response import CbResponseAPI, Process

root = logging.getLogger()
root.addHandler(logging.StreamHandler())
logging.getLogger("cbapi").setLevel(logging.DEBUG)
cb = CbResponseAPI()


dict1 = {} #empty dictionary that holds all the queried proccesse's depth, start time, users, and commands. For json formatting purposes

#find instances of where our attacker used the built-in Windows tool net.exe to mount an internal network share
query = cb.select(Process).where("process_name:net.exe").and_(r"cmdline:\\test\blah").group_by("id")

#Function that outputs a few data points about each process: namely, the local endpoint time when that process started, the user who spawned the process, and the command line for the process.
def query_output(proc, depth):
	Dict = { "Level" :  depth, "start time" : proc.start,  "user" : proc.username, "Process CLI": proc.cmdline}
	dict1 = Dict | dict1


#execute our query by looping over the result set with a Python for loop. For each process that matches the query, first we print details of the process itself , then calls the .walk_parents() helper method to walk up the chain of all parent processes
for proc in query:
	query_output(proc, 0)
	proc.walk_parents(query_output)


#writing python dictionary into json file with dump method
with open("sample.json", "w") as outfile:
    json.dump(dict1, outfile)