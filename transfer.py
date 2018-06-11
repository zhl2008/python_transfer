#!/usr/bin/env python2

'''
python_transfer

@author haozigege@Lancet
@version v0.1


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
from time import gmtime, strftime

###### configuration #######

listen_port = 8002
target_socket = 'http://127.0.0.1:8889'
dir_base = '/Users/haozigege'
http_log_enable = True
json_log_enable = True
resp_log_len = 200
flag_regrex_pattern = "flag\{[0-9a-fA-F]{32}\}"
admin_router = '/haozigege666'
timeout = 2
all_log_dir = './logs/all_log/'
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
self.wfile   		http response data

'''

class CustomHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def raw_request_http(self):
		'''
		parse data to raw http
		'''
		self.raw_data = "\n"
		self.raw_data += self.requestline + "\n"
		self.raw_data += str(self.headers).replace('\r','')
		self.raw_data += "\n"
		self.content = ''
		if self.headers.has_key('Content-Length'):
			content_length = self.headers['Content-Length']
			self.content = self.rfile.read(int(content_length))
		if self.headers.has_key('Accept-Encoding'):
			del self.headers['Accept-Encoding']
		self.raw_data += self.content
		self.raw_data += "\n"
		if http_log_enable:
			self.log_file(self.raw_data)

	def raw_reply_http(self,status_code,headers,content):
		self.raw_response = "\n"
		# to simplify, we set everything to OK
		self.raw_response += "HTTP/1.0 %d OK\n"%status_code
		for header in headers:
			self.raw_response += header + ": " + str(headers[header]) + "\n"
		self.raw_response += "\n"
		if len(content)>resp_log_len:
			self.raw_response += content[:resp_log_len] + '......'
		self.raw_response += "\n"
		if http_log_enable:
			self.log_file(self.raw_response)

	def log_file(self,content):
		# log content to file system per round
		if not os.path.exists(all_log_dir):
			os.mkdir(all_log_dir)
		now_time = strftime("_%d_%H_", gmtime()) + str((int(gmtime().tm_min)/round_time))
		file_name = self.client_address[0] + now_time + '.log'
		open(all_log_dir + file_name,'a').write(content)


	def do_GET(self):
		# get the http request data
		self.raw_request_http()
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

		# transfer our data to remote server
		else:
			r = requests.get(target_socket + self.path,headers=self.headers,data=self.content,timeout=2)
			# return the remote server's response
			self.send_response(r.status_code)
			r.headers['Content-Length'] = len(r.content)
			for h_key in r.headers:
				# avoid the duplcated headers
				if h_key in ['Date','Transfer-Encoding']:
					continue
				self.send_header(h_key,r.headers[h_key])
			self.end_headers()
			self.wfile.write(r.content)
			self.raw_reply_http(r.status_code,r.headers,r.content)

			


	def do_POST(self):
		# get the http request data
		self.raw_request_http()
		# with that admin url prefix, we can be authorized with admin priv
		if self.path.startswith(admin_router):
			real_path = dir_base + self.path[len(admin_router):]
			if not real_path:
				real_path = dir_base + '/'
			f = self.list_directory(real_path)
			self.copyfile(f, self.wfile)
		# transfer our data to remote server
		else:
			r = requests.post(target_socket + self.path,headers=self.headers,data=self.content,timeout=2)
			# return the remote server's response
			self.send_response(r.status_code)
			r.headers['Content-Length'] = len(r.content)
			for h_key in r.headers:
				# avoid the duplcated headers
				if h_key in ['Date','Transfer-Encoding']:
					continue
				self.send_header(h_key,r.headers[h_key])
			self.end_headers()
			self.wfile.write(r.content)
			self.raw_reply_http(r.status_code,r.headers,r.content)


	def do_TEST(self):
		self.raw_request_http()



httpd = SocketServer.TCPServer(("", listen_port), CustomHTTPRequestHandler)
print "serving at port", listen_port
httpd.serve_forever()
sys.exit()
