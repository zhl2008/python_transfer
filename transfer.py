#!/usr/bin/env python2

'''

@name python_transfer
@author haozigege@Lancet
@version v0.1
@time 2018.6


This tool is implemented to transfer the traffic sent to the local port to 
another local port or even remote port, and during that process, you can record 
the traffic from both sides.

'''

import os
import sys
import SimpleHTTPServer
import SocketServer
import requests
import cgi
import re
from time import gmtime, strftime

###### configuration #######

listen_port = 28080	
target_socket = 'http://127.0.0.1:8080'
dir_base = '/Users/haozigege'
http_log_enable = True
evil_log_enable = True
flag_detect_enable = True
waf_enable = False
flag_regex_pattern = "TSCTF\{[0-9a-fA-F]{32}\}"
fake_flag = "TSCTF{b821f0660d8ac03ffd9d4c865f1aac78}"
resp_log_len = 1000
admin_router = '/haozigege666'
timeout = 2
all_log_dir = './logs/all_log/'
evil_log_dir = './logs/evil_log/'
flag_log_dir = './logs/flag_log/'
round_time = 5


############################

'''
data structures of the http requests:
self.client_address[0] client ip
self.command        http method
self.path           http url
self.requestline    http line
self.headers        http headers
self.rfile          http request data
self.wfile   	    http response data

'''

class CustomHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def raw_request_http(self):
		'''
		parse data to raw http
		'''
		self.raw_request = "\n"
		self.raw_request += self.requestline + "\n"
		self.raw_request += str(self.headers).replace('\r','')
		self.raw_request += "\n"
		self.content = ''
		if self.headers.has_key('Content-Length'):
			content_length = self.headers['Content-Length']
			self.content = self.rfile.read(int(content_length))
		if self.headers.has_key('Accept-Encoding'):
			del self.headers['Accept-Encoding']
		self.raw_request += self.content
		self.raw_request += "\n"
		# if http_log_enable:
		# 	self.log_file(self.raw_request)

	def raw_reply_http(self,status_code,headers,content):
		self.raw_response = "\n"
		# to simplify, we set everything to OK
		self.raw_response += "HTTP/1.0 %d OK\n"%status_code
		for header in headers:
			self.raw_response += header + ": " + str(headers[header]) + "\n"
		self.raw_response += "\n"
		self.raw_response += content
		self.raw_response += "\n"


	def log_file(self,content,log_dir):
		# log content to file system per round
		if not os.path.exists(log_dir):
			os.mkdir(log_dir)
		now_time = strftime("_%d_%H_", gmtime()) + str((int(gmtime().tm_min)/round_time))
		file_name = self.client_address[0] + now_time + '.log'
		# to prevent the length of log becomes too large
		if len(content) > resp_log_len:
		    content = content[:resp_log_len] + '......'
		open(log_dir + file_name,'a').write(content)



	def my_http_handle(self):
		'''
		play with the http data 

		'''
		# with that admin url prefix, we can be authorized with admin priv
		if self.path.startswith(admin_router):
			real_path = dir_base + self.path[len(admin_router):]
			if not real_path:
				real_path = dir_base + '/'
			if os.path.isdir(real_path):
				f = self.list_directory(real_path)
				self.copyfile(f, self.wfile)
			elif os.path.exists(real_path):
				# I am sure it's a normal file
				f = open(real_path,'rb')
				self.send_response(200)
				self.send_header('Content-type', 'text/html')
				self.end_headers()
				self.copyfile(f, self.wfile)
			return ""

		# transfer our data to remote server
		else:
			if self.command == 'GET':
				r = requests.get(target_socket + self.path,headers=self.headers,data=self.content,timeout=2)
			else:
				# I assume that the http method is get || post
				r = requests.post(target_socket + self.path,headers=self.headers,data=self.content,timeout=2)
			return r

	def my_http_response(self,status_code,headers,content):
		# return the remote server's response to client
		self.send_response(status_code)
		headers['Content-Length'] = len(content)
		for h_key in headers:
			# avoid the duplcated headers
			if h_key in ['Date','Transfer-Encoding']:
				continue
			self.send_header(h_key,headers[h_key])
		self.end_headers()
		self.wfile.write(content)


	def is_evil(self):
		self.sql_rule = 'select|insert|update|delete|union|load_file|outfile|dumpfile|sub|hex'
		self.php_rule = 'file_put_contents|fwrite|curl|system|eval|assert'
		self.cmd_rule_1 = 'passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore'
		self.cmd_rule_2 = '`|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exe'

		r = re.search(self.sql_rule,self.raw_request)
		if r:
			self.log_message("%s","sql injection detected => " + str(r.group()))
			return True
		r = re.search(self.php_rule,self.raw_request)
		if r:
			self.log_message("%s","php injection detected => " + str(r.group()))
			return True
		r = re.search(self.cmd_rule_1,self.raw_request)
		if r:
			self.log_message("%s","cmd_1 injection detected => " + str(r.group()))
			return True
		r = re.search(self.cmd_rule_2,self.raw_request)
		if r:
			self.log_message("%s","cmd_2 injection detected => " + str(r.group()))
			return True

	def is_flag(self):
		r = re.search(flag_regex_pattern,self.raw_response)
		if r:
			self.log_message("%s","flag leakage detected => " + str(r.group()))
			self.real_flag = str(r.group())
			return True



	def do_GET(self):
		self.my_main_handle()

	def do_POST(self):
		self.my_main_handle()

	def do_TEST(self):
		self.raw_request_http()



	def my_main_handle(self):
		'''
		play with everything

		'''
		self.evil = 0

		# get the http request data
		self.raw_request_http()

		# check the request data
		if self.is_evil():
			self.evil = 1
			if evil_log_enable:
				self.log_file(self.raw_request,evil_log_dir)
			if waf_enable:
				# if waf enable, drop the evil data
				self.send_error(404)
				return 

		# send http data and get response
		r = self.my_http_handle()
		# if r is null, it could be boiled down to errors or the acess of admin url
		if not r:
			return

		# get the http response data
		self.raw_reply_http(r.status_code,r.headers,r.content)

		# check and record the http data
		if http_log_enable:
			self.log_file(self.raw_request,all_log_dir)
			self.log_file(self.raw_response,all_log_dir)

		if self.evil:
			self.log_file(self.raw_response,evil_log_dir)

		if self.is_flag():
			self.log_file(self.raw_request,flag_log_dir)
			self.log_file(self.raw_response,flag_log_dir)
			content = r.content.replace(self.real_flag,fake_flag)
		else:
			content = r.content


		# http response
		status_code = r.status_code
		headers = r.headers
		self.my_http_response(status_code,headers,content)


httpd = SocketServer.TCPServer(("", listen_port), CustomHTTPRequestHandler)
print "serving at port", listen_port
httpd.serve_forever()
