"""
project: ollama_proxy_server
file: main.py
author: ParisNeo
description: This is a proxy server that adds a security layer to one or multiple ollama servers and routes the requests to the right server in order to minimize the charge of the server.
"""

import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from queue import Queue
import requests
import argparse
from ascii_colors import ASCIIColors
from pathlib import Path
import csv
import datetime
import logging
import io

def initLogger(name:str, file:str, clevel:int=logging.DEBUG, flevel:int=logging.DEBUG)->logging.Logger:
    # 创建一个日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(clevel)  # 设置日志记录器的级别

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(clevel)  # 控制台处理器级别
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    # 创建文件处理器
    file_handler = logging.FileHandler(file)
    file_handler.setLevel(flevel)  # 文件处理器级别
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    # 将处理器添加到记录器
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # 记录日志
    # logger.debug('This is a debug message')
    # logger.info('This is an info message')
    # logger.warning('This is a warning message')
    # logger.error('This is an error message')
    # logger.critical('This is a critical message')
    return logger


def get_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return [(name, {'url': config[name]['url'], 'queue': Queue()}) for name in config.sections()]

# Read the authorized users and their keys from a file
def get_authorized_users(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    authorized_users = {}
    for line in lines:
        if line=="":
            continue
        try:
            user, key = line.strip().split(':')
            authorized_users[user] = key
        except:
            ASCIIColors.red(f"User entry broken:{line.strip()}")
    return authorized_users



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default="config.ini", help='Path to the authorized users list')
    parser.add_argument('--log_path', default="access_log.txt", help='Path to the access log file')
    parser.add_argument('--users_list', default="authorized_users.txt", help='Path to the config file')
    parser.add_argument('--port', type=int, default=8000, help='Port number for the server')
    parser.add_argument('-d', '--deactivate_security', action='store_true', help='Deactivates security')
    parser.add_argument('--ext_log', default="ext.log", help='Path to the proxy extra log file')
    args = parser.parse_args()
    servers = get_config(args.config)  
    authorized_users = get_authorized_users(args.users_list)
    deactivate_security = args.deactivate_security
    ext_log = initLogger("main", args.ext_log, logging.DEBUG, logging.DEBUG)
    ASCIIColors.red("Ollama Proxy server")
    ASCIIColors.red("Author: ParisNeo")

    class RequestHandler(BaseHTTPRequestHandler):
        def add_access_log_entry(self, event, user, ip_address, access, server, nb_queued_requests_on_server, error=""):
            log_file_path = Path(args.log_path)
        
            if not log_file_path.exists():
                with open(log_file_path, mode='w', newline='') as csvfile:
                    fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
        
            with open(log_file_path, mode='a', newline='') as csvfile:
                fieldnames = ['time_stamp', 'event', 'user_name', 'ip_address', 'access', 'server', 'nb_queued_requests_on_server', 'error']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                row = {'time_stamp': str(datetime.datetime.now()), 'event':event, 'user_name': user, 'ip_address': ip_address, 'access': access, 'server': server, 'nb_queued_requests_on_server': nb_queued_requests_on_server, 'error': error}
                writer.writerow(row)

        def _send_response(self, response, logContent:dict):
            self.send_response(response.status_code)
            logContent['response'] = {"status":response.status_code}
            logContent['response']['headers'] = []
            for key, value in response.headers.items():
                if key.lower() not in ['content-length', 'transfer-encoding', 'content-encoding']:
                    self.send_header(key, value)
                    logContent['response']['headers'].append({key:value})
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            try:
                file_like_object = io.BytesIO()
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        self.wfile.write(b"%X\r\n%s\r\n" % (len(chunk), chunk))
                        # file_like_object.write(b"%X\r\n%s\r\n" % (len(chunk), chunk))
                        file_like_object.write(b"%s" % (chunk))
                        self.wfile.flush()
                        file_like_object.flush()
                self.wfile.write(b"0\r\n\r\n")
                # file_like_object.write(b"0\r\n\r\n")
            except BrokenPipeError:
                pass
            file_like_object.seek(0)
            logContent['response']['content'] = file_like_object.getvalue().decode('utf-8')

        def do_GET(self):
            self.log_request()
            self.proxy()

        def do_POST(self):
            self.log_request()
            self.proxy()

        def _validate_user_and_key(self):
            try:
                # Extract the bearer token from the headers
                auth_header = self.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return False
                token       = auth_header.split(' ')[1]
                user, key   = token.split(':')
                
                # Check if the user and key are in the list of authorized users
                if authorized_users.get(user) == key:
                    self.user = user
                    return True
                else:
                    self.user = "unknown"
                return False
            except:
                return False
                
        def proxy(self):
            self.user = "unknown"
            logContent = {}
            if not deactivate_security and not self._validate_user_and_key():
                ASCIIColors.red(f'User is not authorized')
                client_ip, client_port = self.client_address
                # Extract the bearer token from the headers
                auth_header = self.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    self.add_access_log_entry(event='rejected', user="unknown", ip_address=client_ip, access="Denied", server="None", nb_queued_requests_on_server=-1, error="Authentication failed")
                else:
                    token = auth_header.split(' ')[1]                
                    self.add_access_log_entry(event='rejected', user=token, ip_address=client_ip, access="Denied", server="None", nb_queued_requests_on_server=-1, error="Authentication failed")
                self.send_response(403)
                self.end_headers()
                return            
            url = urlparse(self.path)
            path = url.path
            # logContent['path'] = path
            get_params = parse_qs(url.query) or {}
            logContent['get_params'] = get_params
            logContent['command'] = self.command


            if self.command == "POST":
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                post_params = post_data# parse_qs(post_data.decode('utf-8'))
                post_str = post_data.decode('utf-8')
            else:
                post_params = {}
                post_str = ""
            logContent['post_params'] = post_str

            # Find the server with the lowest number of queue entries.
            min_queued_server = servers[0]
            for server in servers:
                cs = server[1]
                if cs['queue'].qsize() < min_queued_server[1]['queue'].qsize():
                    min_queued_server = server

            # Apply the queuing mechanism only for a specific endpoint.
            if path == '/api/generate' or path == '/api/chat':
                que = min_queued_server[1]['queue']
                client_ip, client_port = self.client_address
                self.add_access_log_entry(event="gen_request", user=self.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize())
                que.put_nowait(1)
                try:
                    post_data_dict = {}

                    if isinstance(post_data, bytes):
                        post_data_str = post_data.decode('utf-8')
                        post_data_dict = json.loads(post_data_str)
                    logContent['url'] = min_queued_server[1]['url'] + path
                    # ext_log.info(json.dumps(logContent, ensure_ascii=False))
                    response = requests.request(self.command, min_queued_server[1]['url'] + path, params=get_params, data=post_params, stream=post_data_dict.get("stream", False))
                    self._send_response(response, logContent)
                except Exception as ex:
                    self.add_access_log_entry(event="gen_error",user=self.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize(),error=ex)                    
                finally:
                    que.get_nowait()
                    self.add_access_log_entry(event="gen_done",user=self.user, ip_address=client_ip, access="Authorized", server=min_queued_server[0], nb_queued_requests_on_server=que.qsize())
                    ext_log.info(json.dumps(logContent, ensure_ascii=False))
                    # ext_log.info(str(logContent))
            else:
                # For other endpoints, just mirror the request.
                response = requests.request(self.command, min_queued_server[1]['url'] + path, params=get_params, data=post_params)
                self._send_response(response, logContent)
                ext_log.info(json.dumps(logContent, ensure_ascii=False))
                # ext_log.info(str(logContent))

    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        pass


    print('Starting server')
    server = ThreadedHTTPServer(('', args.port), RequestHandler)  # Set the entry port here.
    print(f'Running server on port {args.port}')
    server.serve_forever()

if __name__ == "__main__":
    main()
