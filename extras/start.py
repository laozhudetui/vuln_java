# coding: utf-8

import yaml
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage

# https://blog.talosintelligence.com/2017/09/vulnerability-spotlight-yaml-remote.html
with open('/etc/vuln.yml', 'rb') as fp:
    yaml.load(fp)

# email hard code
mail_host = 'smtp.example.com'
mail_user = 'admin'
mail_pass = '1qaz@WSX@seecode'
sender = 'hr@example.com'
receivers = ['json0@example.com']
