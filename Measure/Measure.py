import logging
import json
import datetime
import pytz
import sched
import time
import threading
from typing import List
from Config.Config import Conf
import Utils.Query as Query

domainNSS = {}
domainChangeInfo = {} # [测量次数、查询异常次数、未变更次数、变更次数、平滑变更次数、非平滑变更次数]
changeInfoTitle = ["measure times", "exception times", "not change times", "change times", "smooth change times", "not smooth change times"]
schedules: List[sched.scheduler] = []

def init():
    Conf.LoadConf('./settings.yaml')

    for domain in Conf.DomainList:
        domainChangeInfo[domain] = [0, 0, 0, 0, 0, 0]

    for i in range(Conf.ThreadNum):
        schedules.append(sched.scheduler(time.time, time.sleep))

    logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s", level=logging.DEBUG, datefmt="%Y-%m-%d %H:%M:%S", filename=Conf.LogPath, filemode="a")

    logging.info(json.dumps({
        "domain list": Conf.DomainList,
        "max ttl": Conf.MaxTTL,
        "min ttl": Conf.MinTTL,
        "thread num": Conf.ThreadNum,
        "max times": Conf.MaxTimes,
        "start time": curTime()
    }))

def getChangeInfo(domain):
    return {
        i: j for i, j in zip(changeInfoTitle, domainChangeInfo[domain])
    }

def makeMsg(ttype: str, domain: str, info: dict, ttl: int) -> str:
    return json.dumps({
        "type": ttype,
        "time": curTime(),
        "domain": domain,
        "info": info,
        "ttl": ttl,
        "change info": getChangeInfo(domain)
    })

def curTime():
    return datetime.datetime.now(pytz.timezone(Conf.TimeZone)).strftime("%Y-%m-%d %H:%M:%S")

def getTTL(ttl):
    return min(Conf.MaxTTL, max(Conf.MinTTL, ttl))

def checkEqual(a, b):
    if len(a) != len(b):
        return False

    for i in a:
        if i not in b:
            return False

    return True

def checkContain(a, b):
    if len(b) > len(a):
        return False
    
    for i in b:
        if i not in a:
            return False

    return True

def measureADomain(thdno, priority, domain) -> int:
    domainChangeInfo[domain][0] += 1
    nss, ttl, superdetails = Query.GetAuthFromSuper(domain)
    if len(nss) == 0:
        domainChangeInfo[domain][1] += 1
        msg = makeMsg(
            "query error",
            domain,
            {"msg": "could not get Auth"},
            -1
        )

        logging.error(msg)
        return -1
    
    if domain not in domainNSS:
        domainNSS[domain] = nss
        msg = makeMsg(
            "first trust",
            domain, 
            {
                "nameservers": nss,
                "details": superdetails
            },
            ttl
        )

        logging.info(msg)
        return ttl
    
    if checkEqual(domainNSS[domain], nss):
        domainChangeInfo[domain][2] += 1
        msg = makeMsg(
            "not change",
            domain,
            {
                "nameservers": nss,
                "details": superdetails
            },
            ttl
        )
        logging.info(msg)
        return ttl
    else:
        oldReplyNss, _, authdetails = Query.GetAuthFromAuths(domain, domainNSS[domain])
        if not checkContain(oldReplyNss, nss):
            domainChangeInfo[domain][5] += 1
            msg = makeMsg(
                "not smooth change",
                domain,
                {
                    "new nameservers": nss,
                    "old nameservers": domainNSS[domain],
                    "old reply nameservers": oldReplyNss,
                    "super details": superdetails,
                    "auth details": authdetails
                },
                ttl
            )

            logging.warning(msg)
        else:
            domainChangeInfo[domain][4] += 1
            msg = makeMsg(
                "smooth change",
                domain,
                {
                    "new nameservers": nss,
                    "old nameservers": domainNSS[domain],
                    "old reply nameservers": oldReplyNss,
                    "super details": superdetails,
                    "auth details": authdetails
                },
                ttl
            )

            logging.info(msg)

            for i in domainNSS[domain]:
                if i not in nss:
                    timingExe(checkAlive, (thdno, priority, domain, i, curTime()))


        domainNSS[domain] = nss

        return ttl

    

def checkAlive(thdno, priority, domain, nsip, startTime) -> int:
    nss, ttl = Query.GetAuthFromAuth(domain, nsip)

    if len(nss) == 0:
        msg = makeMsg(
            "server down",
            domain,
            {
                "nameserver": nsip,
                "start time": startTime
            },
            ttl
        )
        logging.warning(msg)
        return -1
    
    msg = makeMsg(
        "server alive",
        domain,
        {
            "nameserver": nsip,
            "start time": startTime
        },
        ttl
    )

    logging.info(msg)

    return ttl

def timingExe(func, args): # args[0]是使用的线程编号，args[1]是优先级，func必须返回一个ttl，代表延后时间
    ttl = func(*args)
    if ttl != -1:
        schedules[args[0]].enter(getTTL(ttl), args[1], timingExe, (func, args,))

def StartMeasure():
    init()
    for i, domain in enumerate(Conf.DomainList):
        no = i % Conf.ThreadNum
        schedules[no].enter(0, 0, timingExe, (measureADomain, (no, 0, domain,)))

    def run(schd: sched.scheduler):
        schd.run()
    
    thds: List[threading.Thread] = []
    for i in range(Conf.ThreadNum):
        thds.append(threading.Thread(target=run, args=(schedules[i],)))
    for thd in thds:
        thd.start()
    for thd in thds:
        thd.join()
