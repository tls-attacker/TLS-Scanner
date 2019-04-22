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
def query_yes_no(question, default=None):
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

### SAFETY QUESTIONS
performReset = False
performReset = query_yes_no("do you really want to perform a hard redis reset?")
if performReset:
    performReset = query_yes_no("did you stop all tls crawler slave instances?")
if performReset:

    ### READ MONGO
    client = MongoClient("mongodb://" + mongoUser + ":" + mongoPass + "@" + mongoHost + ":" + mongoPort + "/" + mongoAuth)
    db = client[wsFullName]
    coll = db.scans

    allResults = coll.find({"completedTimestamp" : { "$eq" : None }}, {'_id': 1, 'completedTimestamp': 1}) # { "completedTimestamp" : { "$ne" : None } })

    lostScanIDs = list()
    for result in allResults:
        lostScanIDs.append(result['_id'])
    ### END READ MONGO

    performReset = query_yes_no("delete old redis keys and add the new ones? (if not, this procedure will be aborted and no changes will be made)")
    if performReset:
        print "deleting old keys..."
        redis = redis.StrictRedis(host = redisHost, port = redisPort, password = redisPass)
        redis.delete(wsFullName)

        print "adding keys to redis..."
        
        for id in lostScanIDs:
            redis.rpush(wsFullName, id)

        print "all keys added to redis. if a slave instance is running, these scan tasks will now be on its agenda."

print "bye."