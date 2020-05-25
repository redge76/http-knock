#!/usr/bin/env python3
from flask import Flask, render_template, request
import subprocess
import socket
import configparser
import argparse

import pprint
import logging 
from logging import StreamHandler, FileHandler


app = Flask(__name__)

# read configuration file. Default file name is config.ini
def read_config(config_file):
    global cfg
    logger.info("Reading configuration file : %s", config_file)
    cfg = configparser.ConfigParser()
    cfg.read(config_file)
    if cfg.has_section('global') is False:
        logger.error("Configuration file '%s' does not exits", config_file)
        exit()

def iptables_uninstall_rules():
    logger.debug("iptables_uninstall_rules()")
    logger.debug("Removing iptables rules")
    rc = subprocess.run(['iptables', '-F', cfg['iptables']['chain_name'] ])
    rc = subprocess.run(['iptables', '-D', 'INPUT', '-i', cfg['iptables']['interface'], '-p', 'tcp', '-m', 'multiport', '--dport', cfg['iptables']['protected_ports'], '-j', cfg['iptables']['chain_name'] ])
    rc = subprocess.run(['iptables', '-X', cfg['iptables']['chain_name']] )
    exit()

def iptables_install_rules():
    logger.debug("iptables_install_rules()")
    logger.debug("Installing iptables rules")
    authorized_ip_list = cfg['iptables']['authorized_ip'].split(',')
    rc = subprocess.run(['iptables', '-N', cfg['iptables']['chain_name'] ] )
    rc = subprocess.run(['iptables', '-I', cfg['iptables']['chain_name'], '-m', 'state', '--state', 'NEW', '-j', 'LOG', '--log-prefix', 'HTTP-KNOCK - ', '--log-level', 'info'])
    for ip in authorized_ip_list:
        rc = subprocess.run(['iptables', '-I', cfg['iptables']['chain_name'], '-s', ip, '-j', 'ACCEPT'] )
    rc = subprocess.run(['iptables', '-A', cfg['iptables']['chain_name'], '-j', 'DROP'  ])
    rc = subprocess.run(['iptables', '-I', 'INPUT', '-i', cfg['iptables']['interface'], '-p', 'tcp', '-m', 'multiport', '--dport', cfg['iptables']['protected_ports'], '-j', cfg['iptables']['chain_name'] ])

def iptables_check_rules():
    logger.debug("iptables_check_rules()")
    rc = subprocess.run(['iptables', '-L', cfg['iptables']['chain_name'], '-n'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if (rc.returncode != 0):
        logger.info("The firewall chain %s was not found. Creating the rules", cfg['iptables']['chain_name'] )
        iptables_install_rules()
    else:
        logger.debug("Chain %s found", cfg['iptables']['chain_name'] )
    

def iptables_display_status():
    logger.debug("iptables_display_status()")
    print("\nThe current firewall rules are:\n")
    rc = subprocess.run(['iptables', '-L', "INPUT", '-n'] )
    print("------")
    rc = subprocess.run(['iptables', '-L', cfg['iptables']['chain_name'], '-n'] )

def iptables_get_allowed_rules():
    logger.debug("iptables_get_allowed_rules()")
    result = subprocess.run(['iptables', '-L', cfg['iptables']['chain_name'], '--line-numbers', '-n'], capture_output = True, text = True)
    lines = result.stdout.splitlines()
    logger.debug("The current firewall rules are:")
    ret = "\n"
    logger.debug(f'\n{ret.join(lines)}')
    return lines

def iptables_add_ip_allowed_rules(ip):
    logger.debug("iptables_add_ip_allowed_rules(%s)", ip)
    result = subprocess.run(["iptables", "-I", cfg['iptables']['chain_name'], "-s", ip, "-j", "ACCEPT"])
    return result
    
# get the last n lines of the f file
def tail(f, n, offset=0):
    proc = subprocess.run([ 'tail', '-n', n + offset, f ],capture_output = True)
    lines = proc.stdout.readlines()
    return lines[:, -offset]
    
@app.route('/')
def root_page():
    found = False

    rules = iptables_get_allowed_rules()
    for rule in rules:
        if request.access_route[0] in rule:
            found = True

    if (found is False):
        logger.info("Adding IP to allowed list: %s", request.access_route[0])
        iptables_add_ip_allowed_rules(request.access_route[0])
    
    last_conn_hostname = list()
    if (cfg.getboolean('global','activity_enable')):
        last_failed_connction_attempts = subprocess.run("tail -n %s %s | sed -n 's/\\(.* ..:..:..\\) .*SRC=\\(.*\\) DST.*/\\1,\\2/p'" %(cfg['global']['activity_size'], cfg['global']['activity_logfile'] ) , capture_output = True, shell = True, text = True).stdout.splitlines()
    
        for attempt in last_failed_connction_attempts:
             try:
                (time, ip) = tuple(attempt.split(','))
                hostname = socket.gethostbyaddr(ip)[0]
             except OSError as e:
                hostname = "Error: %s" %(e.strerror)
           
             last_conn_hostname.append( (time, ip, hostname) )
  
    return render_template('index.html', IP = request.access_route[0], found = found, debug = args.debug , headers = request.headers, request = vars(request), activity_enable=cfg.getboolean('global','activity_enable') ,last_conn = last_conn_hostname)

def parse_args():

    parser = argparse.ArgumentParser(description='Open TCP ports with http requests')

    parser.add_argument("--fw-clear", action='store_true',help = "Clear the firewall")
    parser.add_argument("--config-file", default="./config.ini", metavar='/some/file', help = "File where configuration is stored")
    parser.add_argument("--fw-status", action='store_true',help = "Display the firewall status")
    parser.add_argument("--debug", action='store_true', help = "Enable debugging messages")
    parser.parse_args() 
    return parser.parse_args()


pp = pprint.PrettyPrinter(indent=2)

logger = logging.getLogger('log')
    

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y%m%d %H:%M:%S')
formatter = logging.Formatter('%(levelname)s %(asctime)s - %(message)s', datefmt='%H:%M:%S')

handler_stderror = StreamHandler()
handler_stderror.setLevel(logging.DEBUG)
handler_stderror.setFormatter(formatter)

handler_file = FileHandler("http-knock.log")
handler_file.setLevel(logging.DEBUG)
handler_file.setFormatter(formatter)

logger.addHandler(handler_stderror)
logger.addHandler(handler_file)
print("")
print("-")

args = parse_args()
if (args.debug == True):
    logger.setLevel(logging.DEBUG)


read_config(args.config_file)
if (args.fw_status == True):
    iptables_display_status()
    exit()
    
if (args.fw_clear == True):
    iptables_uninstall_rules()
    exit()

iptables_check_rules()



if __name__ == '__main__':
   app.run(cfg['global']['http_knock_listen_ip'], cfg['global']['http_knock_port'])
