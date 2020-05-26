#!/usr/bin/python3
import argparse
import sys
import json
import datetime
import logging
import os
import time
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from pyptsiem4.pyptsiem import PyPtSiem
from pyptsiem4.loader import SIEMConfig

task_states = {
    "new": 1,
    "running": 2,
    "finished": 3
}
error_lvls = {
    "green": 1,
    "yellow": 2,
    "red": 3
}

def task_list(server, sessionPersist):
    ptsiem = PyPtSiem(server, sessionPersist=sessionPersist)
    tasks = ptsiem.getTasksStatus()
    tl = []
    for task in tasks:
        tl.append({"{#JOB}": task['name']})
    return {"data": tl}


def task_state(server, sessionPersist=None):

    ptsiem = PyPtSiem(server, sessionPersist=sessionPersist)

    tasks = ptsiem.getTasksStatus()
    tl = []
    for task in tasks:
        health = None
        if 'lastRunErrorLevel' in task:
            health = error_lvls.get(task['lastRunErrorLevel'])
        else:
            health = error_lvls.get(task['lastRunErrorStatus'])
        if health is None: # In case we not recognize state
            health = 0
        state = task_states.get(task['status'])
        tl.append({"{#JOB}": task['name'], "{#STATE}": state, "{#HEALTH}": health})
    return tl


def restart_task(server, taskName, sessionPersist=None):
    ptsiem = PyPtSiem(server, sessionPersist=sessionPersist)
    ptsiem.restartTask(taskName=taskName)
    return


def create_rotating_log(path):
    logger = logging.getLogger("pyptsiem4")
    if 'DEBUG' in os.environ:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    handler = TimedRotatingFileHandler(path, when='d', interval=1, backupCount=7)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def userreq(req_text):
    import getpass
    userinput = getpass.getpass(prompt=req_text)
    return userinput

def entry():
    parser = argparse.ArgumentParser()

    parser.add_argument('-u', '--username', help='add new server credentials to config')
    parser.add_argument('-p', '--sessionpersist', metavar='PATH_TO_COOKIE_FILE', help='Full path to cookie file, where store cookies after authetification and use it for session persistance')

    parser.add_argument('-ca', '--cafile', metavar='CAFILE', default='/usr/bin/zabbix/externalscripts/cafile.pem', help='CAFILE location, False for disable certificate validation')
    parser.add_argument('-c', '--core', metavar='COREADDR', help='PT SIEM Core address (as appears in browser address line after https://)')
    parser.add_argument('entry_name', metavar='NAME_OF_ENTRY_IN_CONFIGFILE', nargs='?', help='Name of instance in config file')

    pgrp = parser.add_mutually_exclusive_group(required=True)
    pgrp.add_argument('-a', '--add-server', action='store_true', help='add new server credentials to config')
    pgrp.add_argument('-d', '--del-server', action='store_true', help='remove server from config file')
    pgrp.add_argument('-m', '--change-pwd', action='store_true', help='modify/change password, stored in config')
    pgrp.add_argument('-l', '--list-tasks', action='store_true', help='task list')
    pgrp.add_argument('-s', '--task-states', action='store_true',
                        help='State of task, that passed as argument(finished, running, etc...)')
    pgrp.add_argument('-r', '--restart', metavar='TASK', help='Restart task with given name')

    try:
        if getattr(sys, 'frozen', False):
            logger.debug(__file__)
    except:
        logger.warning(exc_info=True)

    args = parser.parse_args()
    logger = create_rotating_log("/var/log/zabbix/ptsiem_monitoring.log")
    logger.info(datetime.datetime.now().strftime("%d:%m:%Y %H:%M:%S"))
    logger.info(" ".join(sys.argv[:]))
    config = os.path.join(sys.path[0], 'config.json')
    cfg = SIEMConfig(config)

    if args.add_server:
        cfg.add_new_server(args.core, args.username, userreq("Please, enter password for user " + args.username + ": "), args.cafile, PyPtSiem, args.entry_name, sessionpersist=args.sessionpersist)
    elif args.change_pwd:
        if args.entry_name:
            name = args.entry_name
        else:
            name = args.core
        cfg.update_server(name, args.username, userreq("Please, enter new password: "), args.cafile)
    elif args.del_server:
        if args.entry_name:
            name = args.entry_name
        else:
            name = args.core
        cfg.remove_server(name)
    elif args.restart:
        task = args.restart
        if args.entry_name:
            name = args.entry_name
        else:
            name = args.core
        if name is None:
            logger.fatal("No core name or address defined! Exiting")
            return
        srv = cfg.load_server_from_cfg(name)
        restart_task(srv, task.strip(), sessionPersist=args.sessionpersist or srv.get('cookiejar'))
    elif args.task_states:
        if args.entry_name:
            name = args.entry_name
        else:
            name = args.core
        if name is None:
            logger.fatal("No core name or address defined! Exiting")
            return
        srv = cfg.load_server_from_cfg(name)
        print(json.dumps(task_state(srv, sessionPersist=args.sessionpersist or srv.get('cookiejar'))))
    elif args.list_tasks:
        if args.entry_name:
            name = args.entry_name
        else:
            name = args.core
        if name is None:
            logger.fatal("No core name or address defined! Exiting")
            return
        srv = cfg.load_server_from_cfg(name)
        print(json.dumps(task_list(srv, sessionPersist=args.sessionpersist or srv.get('cookiejar'))))

if __name__ == '__main__':
    entry()
