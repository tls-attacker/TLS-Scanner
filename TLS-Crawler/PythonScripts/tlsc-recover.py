from pymongo import MongoClient
from datetime import datetime
import sys
import redis
import pprint

### VAR
workspace = # String Value

redisPass = # String Value
redisHost = # String Value
redisPort = # String Value

mongoUser = # String Value
mongoPass = # String Value
mongoAuth = # String Value
mongoHost = # String Value
mongoPort = # String Value
### END VAR

### DECLARATIONS
def query_yes_no(question, default="no"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

wsFullName = "TLSC-" + workspace
### END DECLARATIONS

### READ REDIS
#redis = redis.StrictRedis(host = redisHost, port = redisPort, password = redisPass)
#listLength = redis.llen(wsFullName)


### END READ REDIS

### READ MONGO
client = MongoClient("mongodb://" + mongoUser + ":" + mongoPass + "@" + mongoHost + ":" + mongoPort + "/" + mongoAuth)
db = client[wsFullName]
coll = db.scans

allResults = coll.find({}, {'_id': 1, 'completedTimestamp': 1}) # { "completedTimestamp" : { "$ne" : None } })

lastCompleted = datetime(1970,1,1)
templist = list()
lostScanIDs = list()

inTempList = False

iterations = 0
for result in allResults:
    completed = result['completedTimestamp']

    if completed == None:
        templist.append(result['_id'])
        inTempList = True
        print "completed timestamp None: " + result['_id']

    if inTempList:
        if completed != None:
            lastCompleted = completed
            if (datetime.now() - lastCompleted).total_seconds() > 1800:
                lostScanIDs.extend(templist)
                templist = list()
                inTempList = False
                lastCompleted = datetime(2050,1,1)

pp = pprint.PrettyPrinter(indent=4)
pp.pprint(lostScanIDs)
### END READ MONGO

if not query_yes_no("add these to redis (will be rescanned)?"):
    print "no redis interaction. tls crawler will NOT be prompted to scan the dropped tasks again."
else:
    print "adding keys to redis..."

    redis = redis.StrictRedis(host = redisHost, port = redisPort, password = redisPass)
    for id in lostScanIDs:
        redis.rpush(wsFullName, id)

    print "all keys added to redis. if a slave instance is running, these scan tasks will now be on its agenda."

print "bye."