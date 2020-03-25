from pymongo import MongoClient
import pprint
import md5

client = MongoClient("mongodb://user:pass@host:port/authDb")
db = client['database']
coll = db.scans

allResults = coll.find().limit(20000)

durations = {}
durations['all'] = { 'cnt': 0, 'min': 1000000, 'max': 0, 'avg': 0 }
durations['serverIsAlive'] = { 'cnt': 0, 'min': 1000000, 'max': 0, 'avg': 0 }
durations['supportsSslTls'] = { 'cnt': 0, 'min': 1000000, 'max': 0, 'avg': 0 }
durations['vulnerable'] = { 'cnt': 0, 'min': 1000000, 'max': 0, 'avg': 0 }
partially_vulnerable = 0

buckets = {}
allCiphersSameVuln = list()

iterations = 0
for result in allResults:
    iterations += 1
    if iterations % 10000 == 0:
        print iterations

    if result['completedTimestamp'] != None and not 'failedWithException' in result['results']['tls_scan']:
        duration = int((result['completedTimestamp'] - result['startedTimestamp']).total_seconds() * 1000)

        durations['all']['avg'] = (durations['all']['avg'] * durations['all']['cnt'] + duration) / (durations['all']['cnt'] + 1)
        durations['all']['cnt'] += 1
        if durations['all']['min'] > duration:
            durations['all']['min'] = duration
        if durations['all']['max'] < duration:
            durations['all']['max'] = duration
        
        #print "all"
        
        if result['results']['tls_scan']['serverIsAlive']:
            durations['serverIsAlive']['avg'] = (durations['serverIsAlive']['avg'] * durations['serverIsAlive']['cnt'] + duration) / (durations['serverIsAlive']['cnt'] + 1)
            durations['serverIsAlive']['cnt'] += 1
            if durations['serverIsAlive']['min'] > duration:
                durations['serverIsAlive']['min'] = duration
            if durations['serverIsAlive']['max'] < duration:
                durations['serverIsAlive']['max'] = duration
            
            #print "serverIsAlive"

        
        if result['results']['tls_scan']['supportsSslTls']:
            durations['supportsSslTls']['avg'] = (durations['supportsSslTls']['avg'] * durations['supportsSslTls']['cnt'] + duration) / (durations['supportsSslTls']['cnt'] + 1)
            durations['supportsSslTls']['cnt'] += 1
            if durations['supportsSslTls']['min'] > duration:
                durations['supportsSslTls']['min'] = duration
            if durations['supportsSslTls']['max'] < duration:
                durations['supportsSslTls']['max'] = duration
            
            #print "supportsSslTls"
        
        if result['results']['tls_scan']['attacks']['paddingOracleVulnerable']:
            durations['vulnerable']['avg'] = (durations['vulnerable']['avg'] * durations['vulnerable']['cnt'] + duration) / (durations['vulnerable']['cnt'] + 1)
            durations['vulnerable']['cnt'] += 1
            if durations['vulnerable']['min'] > duration:
                durations['vulnerable']['min'] = duration
            if durations['vulnerable']['max'] < duration:
                durations['vulnerable']['max'] = duration
            
            padddingOracleResults = result['results']['tls_scan']['paddingOracle']['paddingOracleResults']

            
            if len(padddingOracleResults) > 1:
                allVulEq = True
                reference = padddingOracleResults[0]
                for poresult in padddingOracleResults:
                    if not reference['getEqualityError'] == poresult['getEqualityError']:
                        allVulEq = False
                    if not set(reference['responseMap']) == set(poresult['responseMap']):
                        allVulEq = False
                
                if allVulEq:
                    suite = padddingOracleResults[0]['suite']
                    eqError = padddingOracleResults[0]['getEqualityError']
                    responseMapFp = ""
                    for element in padddingOracleResults[0]['responseMap']:
                        responseMapFp += element
                    responseMapFp = md5.new(responseMapFp).digest()

                    if not (responseMapFp in buckets):
                        buckets[responseMapFp] = list()
                
                    buckets[responseMapFp].append(result['_id'] + ":" + result['targetIp'])
            
                    
bucketCtr = 0
for a in buckets:
    bucketCtr += 1

pp = pprint.PrettyPrinter(indent=4)
print "Stats: "
pp.pprint(durations)
pp.pprint(buckets)

print "##buckets: " + str(bucketCtr)

pp.pprint(allCiphersSameVuln)
    

#completed = coll.find({ "completedTimestamp" : { "$ne" : None }}).count()
#print "Completed Scan Tasks: " + str(completed)

#alive = coll.find({ "results.tls_scan.serverIsAlive": True }).count()
#print "Alive Servers: " + str(alive)

#ssltls = coll.find({ "results.tls_scan.supportsSslTls": True}).count()
#print "Servers Supporting SSL/TLS: " + str(ssltls)


### NOT WORKING ###
#match = { "$match": { "results.tls_scan.serverIsAlive": True } }
#project = { "$project": { "dur": { "$subtract" : [ "$completedTimestamp", "$startedTimestamp"] }}}
#group = { "$group": { "_id": "null", "avgDur": { "$avg":"$dur"}}}
#durAvg = coll.aggregate( [ { "$match": { "results.tls_scan.serverIsAlive": True } }, { "$project": { "dur": { "$subtract" : [ "$completedTimestamp", "$startedTimestamp"] }}}])#, { "$group": { "_id": "null", "avgDur": { "$avg":"$dur"}}}])

#for document in durAvg:
#    print "Average Duration of completed scan tasks: " + str(document.dur)

#match = { "$match": { "results.tls_scan.serverIsAlive": True } }
#project = { "$project": { "dur": { "$subtract" : [ "$completedTimestamp", "$startedTimestamp"] }}}
#group = { "$group": { "_id": "null", "avgDur": { "$avg":"$dur"}}}
#durAvg = coll.aggregate( [ match, project, group])

#cipherSuitesFound = coll.distinct("results.friendly_scan.ciphers.cipherSuites")
###

#print cipherSuitesFound[0]

#for suite in cipherSuitesFound:
#    print suite + " -> " + str(coll.find({ "results.friendly_scan.ciphers.cipherSuites" : { "$all" : [suite] } }).count())
    
#versionsFound = coll.distinct("results.friendly_scan.extensions.supportedExtensions")

#for version in versionsFound:
#    print version + " -> " + str(coll.find({ "results.friendly_scan.extensions.supportedExtensions" : { "$all" : [version] } }).count())
